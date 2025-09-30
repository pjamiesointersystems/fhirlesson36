"""
Kong HTTP Log → Simple Receiver (Step 1)
=======================================

A minimal FastAPI app for Lesson 36, Challenge Part 1:
- Accepts POSTs from Kong's **http-log** plugin at /kong-log
- Validates an optional bearer token
- Extracts a few useful fields from each log entry
- Prints a compact JSON summary to stdout (no database I/O)

Run (with uv):
  uv add fastapi "uvicorn[standard]" python-dotenv
  uv run uvicorn konglogtest:app --host 0.0.0.0 --port 8080

Environment (defaults suitable for your lab):
  LOG_BEARER_TOKEN=fhirdemotoken
  KONG_NODE_NAME=kong-1                # optional tag for the node
  PRINT_FULL_ENTRY=false               # set true to also print whole entries

Kong plugin example:
  curl -s -X POST http://<KONG-ADMIN>/plugins \
    --data name=http-log \
    --data config.http_endpoint=http://<RECEIVER-HOST>:8080/kong-log \
    --data config.method=POST \
    --data config.content_type=application/json \
    --data config.max_batch_size=20 \
    --data config.flush_timeout=2 \
    --data config.headers[Authorization]="Bearer fhirdemotoken"
"""

from __future__ import annotations

import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlencode

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# ---------------------
# Config / Env
# ---------------------
LOG_BEARER_TOKEN = os.getenv("LOG_BEARER_TOKEN", "fhirdemotoken")
KONG_NODE_NAME = os.getenv("KONG_NODE_NAME", "kong-1")
PRINT_FULL_ENTRY = os.getenv("PRINT_FULL_ENTRY", "false").lower() in {"1", "true", "yes"}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("konglogtest")

app = FastAPI(title="Kong HTTP Log Receiver (Step 1)")

# ---------------------
# Helpers
# ---------------------

def _epoch_ms_to_iso(ms: Optional[int]) -> str:
    if ms is None:
        return datetime.now(timezone.utc).isoformat()
    try:
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _qs_to_string(qs_obj: Any) -> Optional[str]:
    if qs_obj is None:
        return None
    try:
        if isinstance(qs_obj, dict):
            return urlencode(qs_obj, doseq=True)
        if isinstance(qs_obj, str):
            return qs_obj
        return json.dumps(qs_obj, separators=(",", ":"))
    except Exception:
        return None


def _get_first(d: Dict[str, Any], key: str) -> Optional[str]:
    v = d.get(key)
    if isinstance(v, list) and v:
        return str(v[0])
    if v is None:
        return None
    return str(v)


def summarize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Pick a few friendly fields for console printing."""
    req = entry.get("request", {}) or {}
    resp = entry.get("response", {}) or {}
    route = entry.get("route", {}) or {}
    service = entry.get("service", {}) or {}
    consumer = entry.get("consumer", {}) or entry.get("authenticated_entity", {}) or {}

    req_headers = req.get("headers", {}) or {}
    resp_headers = resp.get("headers", {}) or {}

    summary: Dict[str, Any] = {
        "event_ts": _epoch_ms_to_iso(entry.get("started_at")),
        "kong_node": KONG_NODE_NAME,
        "client_ip": entry.get("client_ip"),
        "service_name": service.get("name"),
        "route_path": (route.get("paths") or [None])[0],
        "method": req.get("method"),
        "uri": req.get("uri"),
        "query": _qs_to_string(req.get("querystring")),
        "status": resp.get("status"),
        "latency_ms": (entry.get("latencies") or {}).get("request"),
        "request_id": _get_first(req, "id") or _get_first(resp_headers, "x-kong-request-id"),
        "consumer_id": consumer.get("id") or _get_first(req_headers, "x-consumer-id"),
        "consumer_username": consumer.get("username") or _get_first(req_headers, "x-consumer-username"),
        "user_agent": _get_first(req_headers, "user-agent"),
    }

    # Optional: include FHIR hints if present (e.g., via custom_fields_by_lua)
    if isinstance(entry.get("fhir"), dict):
        summary["fhir"] = {
            "resource_type": entry["fhir"].get("resource_type"),
            "resource_id": entry["fhir"].get("resource_id"),
            "operation": entry["fhir"].get("operation"),
        }

    return summary


# ---------------------
# Routes
# ---------------------
@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/kong-log")
async def kong_log(request: Request):
    # Optional bearer token enforcement
    if LOG_BEARER_TOKEN:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != LOG_BEARER_TOKEN:
            raise HTTPException(status_code=401, detail="invalid token")

    body = await request.body()

    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json")

    entries: Iterable[Dict[str, Any]]
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = [payload]
    else:
        raise HTTPException(status_code=400, detail="unexpected payload type")

    accepted = 0
    for entry in entries:
        summary = summarize_entry(entry)
        logger.info("KONG_LOG_SUMMARY %s", json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
        if PRINT_FULL_ENTRY:
            logger.info("KONG_LOG_ENTRY %s", json.dumps(entry, ensure_ascii=False))
        accepted += 1

    return JSONResponse({"accepted": accepted})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("konglogtest:app", host="0.0.0.0", port=8082)
