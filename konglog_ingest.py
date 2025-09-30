"""
Kong HTTP Log → IRIS Ingest (Step 2)
====================================

Refined with clearer try/except/else blocks (fixes Pylance "try must have except/finally")
plus verbose debug switches and safe timestamp/string handling.

Defaults for your lab environment:
  IRIS_CONNECTION_STRING = "127.0.0.1:1972/DEMO"  # host → container via published port
  IRIS_USER             = "_SYSTEM"
  IRIS_PASSWORD         = "ISCDEMO"
  IRIS_LOG_TABLE        = "AUDIT.fhir_logs"
  LOG_BEARER_TOKEN      = "fhirdemotoken"
  KONG_NODE_NAME        = "kong-1"               # optional tag

Debug toggles:
  INGEST_DEBUG   = true   # logs insert errors and offending rows
  TS_AS_TEXT     = true   # sends event_ts as UTC ISO string (avoids tz/driver quirks)

Install & Run (with uv):
  uv add fastapi "uvicorn[standard]" intersystems-irispython python-dotenv
  INGEST_DEBUG=true TS_AS_TEXT=true \
  IRIS_CONNECTION_STRING=127.0.0.1:1972/DEMO IRIS_USER=_SYSTEM IRIS_PASSWORD=ISCDEMO \
  IRIS_LOG_TABLE=AUDIT.fhir_logs LOG_BEARER_TOKEN=fhirdemotoken \
  uv run uvicorn konglog_ingest:app --host 0.0.0.0 --port 8082
"""

from __future__ import annotations

import os
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlencode

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

import iris  # intersystems-irispython

# ---------------------
# Config / Env
# ---------------------
IRIS_CONNECTION_STRING = os.getenv("IRIS_CONNECTION_STRING", "127.0.0.1:1972/DEMO")
IRIS_USER = os.getenv("IRIS_USER", "_SYSTEM")
IRIS_PASSWORD = os.getenv("IRIS_PASSWORD", "ISCDEMO")
IRIS_LOG_TABLE = os.getenv("IRIS_LOG_TABLE", "AUDIT.fhir_logs")
LOG_BEARER_TOKEN = os.getenv("LOG_BEARER_TOKEN", "fhirdemotoken")
KONG_NODE_NAME = os.getenv("KONG_NODE_NAME", "kong-1")
INGEST_DEBUG = os.getenv("INGEST_DEBUG", "true").lower() in {"1","true","yes"}
TS_AS_TEXT = os.getenv("TS_AS_TEXT", "true").lower() in {"1","true","yes"}
# Optional: known FHIR base path prefixes to strip (comma-separated)
FHIR_BASE_PREFIXES = os.getenv("FHIR_BASE_PREFIXES", "/fhir,/r4,/fhir/r4")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("konglog-ingest")

# ---------------------
# IRIS DB connection (global, thread-safe reuse)
# ---------------------
_conn_lock = threading.Lock()
_conn: Optional[iris.IRISConnection] = None


def _connect() -> iris.IRISConnection:
    global _conn
    with _conn_lock:
        if _conn is not None:
            try:
                cur = _conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchall()
                return _conn
            except Exception:
                try:
                    _conn.close()
                except Exception:
                    pass
                _conn = None
        _conn = iris.connect(IRIS_CONNECTION_STRING, IRIS_USER, IRIS_PASSWORD)
        try:
            _conn.autocommit = True  # type: ignore[attr-defined]
        except Exception:
            pass
        return _conn


INSERT_SQL = f"""
INSERT INTO {IRIS_LOG_TABLE} (
  event_ts, client_ip, kong_node, consumer_id, consumer_username,
  credential_type, auth_subject, scopes, method, status_code,
  service_name, route_path, request_path, query_string, resource_type,
  resource_id, operation, request_bytes, response_bytes, latency_ms,
  request_id, error_reason, user_agent
) VALUES (
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?
)
"""

# ---------------------
# Helpers: mapping + parsing
# ---------------------

def _epoch_ms_to_ts(ms: Optional[int]) -> datetime:
    if ms is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _qs_to_string(qs_obj: Any) -> Optional[str]:
    if qs_obj is None:
        return ""
    try:
        if isinstance(qs_obj, dict):
            return urlencode(qs_obj, doseq=True)
        if isinstance(qs_obj, str):
            return qs_obj
        return json.dumps(qs_obj, separators=(",", ":"))
    except Exception:
        return ""


def _infer_credential_type(headers: Dict[str, Any]) -> Optional[str]:
    auth = headers.get("authorization") or headers.get("Authorization")
    if isinstance(auth, list):
        auth = auth[0]
    if isinstance(auth, str):
        low = auth.lower()
        if low.startswith("bearer "):
            return "oauth2"
        if low.startswith("hmac ") or "signature=" in low:
            return "hmac"
        if low.startswith("basic "):
            return "basic"
    if headers.get("x-api-key") or headers.get("apikey"):
        return "apikey"
    return None


def _extract_scopes(headers: Dict[str, Any]) -> Optional[str]:
    return (
        headers.get("x-authenticated-scope")
        or headers.get("x-authenticated-scopes")
        or headers.get("scope")
        or headers.get("scopes")
    )


def _extract_auth_subject(headers: Dict[str, Any]) -> Optional[str]:
    return (
        headers.get("x-authenticated-userid")
        or headers.get("x-credential-identifier")
        or headers.get("x-consumer-custom-id")
        or headers.get("x-consumer-username")
    )


def _parse_fhir_path(path: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not path:
        return None, None, None
    try:
        p = path.split("?")[0].strip()
        if not p.startswith("/"):
            p = "/" + p
        parts = [x for x in p.split("/") if x]
        if not parts:
            return None, None, None
        if parts[0].startswith("$"):
            return None, None, parts[0]
        rtype = parts[0]
        rid = None
        op = None
        if len(parts) > 1:
            if parts[1].startswith("$"):
                op = parts[1]
            elif parts[1] == "_history":
                op = "history"
            else:
                rid = parts[1]
                if len(parts) > 2:
                    if parts[2].startswith("$"):
                        op = parts[2]
                    elif parts[2] == "__history":
                        op = "history"
        if op is None and rid is None and ("?" in path):
            op = "search"
        return rtype, rid, op
    except Exception:
        return None, None, None

def _strip_base_prefix(path: Optional[str], route_path: Optional[str]) -> Optional[str]:
    if not path:
        return path
    try:
        p = path
        if route_path and p.startswith(route_path):
            p = p[len(route_path):] or "/"
        prefixes = [rp.strip() for rp in FHIR_BASE_PREFIXES.split(",") if rp.strip()]
        for pref in prefixes:
            if p.startswith(pref):
                p = p[len(pref):] or "/"
                break
        if not p.startswith("/"):
            p = "/" + p
        return p
    except Exception:
        return path
    try:
        p = path.split("?")[0].strip()
        if not p.startswith("/"):
            p = "/" + p
        parts = [x for x in p.split("/") if x]
        if not parts:
            return None, None, None
        if parts[0].startswith("$"):
            return None, None, parts[0]
        rtype = parts[0]
        rid = None
        op = None
        if len(parts) > 1:
            if parts[1].startswith("$"):
                op = parts[1]
            elif parts[1] == "_history":
                op = "history"
            else:
                rid = parts[1]
                if len(parts) > 2:
                    if parts[2].startswith("$"):
                        op = parts[2]
                    elif parts[2] == "_history":
                        op = "history"
        if op is None and rid is None and ("?" in path):
            op = "search"
        return rtype, rid, op
    except Exception:
        return None, None, None


def _get_first(d: Dict[str, Any], key: str) -> Optional[str]:
    v = d.get(key)
    if isinstance(v, list) and v:
        return str(v[0])
    if v is None:
        return None
    return str(v)


def _truncate(s: Optional[str], limit: int) -> Optional[str]:
    if s is None:
        return None
    if len(s) <= limit:
        return s
    return s[:limit]


def map_entry_to_row(entry: Dict[str, Any]) -> Tuple:
    req = entry.get("request", {}) or {}
    resp = entry.get("response", {}) or {}
    route = entry.get("route", {}) or {}
    service = entry.get("service", {}) or {}
    consumer = entry.get("consumer", {}) or entry.get("authenticated_entity", {}) or {}

    req_headers = req.get("headers", {}) or {}
    resp_headers = resp.get("headers", {}) or {}

    # Prefer fields stamped by Kong Pre-function
    auth_extra = entry.get("auth") or {}
    credential_type = auth_extra.get("scheme")
    auth_subject = auth_extra.get("subject")

    # Back-compat: if someone used dotted keys like 'auth.scheme'
    if not credential_type:
        credential_type = entry.get("auth.scheme")
    if not auth_subject:
        auth_subject = entry.get("auth.subject")

    event_ts_dt = _epoch_ms_to_ts(entry.get("started_at"))
    # DB insert: either as naive UTC datetime or as ISO text based on TS_AS_TEXT
    event_ts = (
        event_ts_dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        if TS_AS_TEXT
        else event_ts_dt.astimezone(timezone.utc).replace(tzinfo=None)
    )

    client_ip = entry.get("client_ip")
    kong_node = KONG_NODE_NAME

    consumer_id = consumer.get("id") or _get_first(req_headers, "x-consumer-id")
    consumer_username = consumer.get("username") or _get_first(req_headers, "x-consumer-username")
    consumer_username = _truncate(consumer_username, 128) if consumer_username else None

    credential_type = _infer_credential_type(req_headers)
    auth_subject = _extract_auth_subject(req_headers)
    scopes = _extract_scopes(req_headers)

    method = req.get("method")
    # Keep existing value if it's an operation like $export or _history we already detected
   

    status_code = resp.get("status")

    service_name = _truncate(service.get("name"), 128) if service.get("name") else None
    route_paths = route.get("paths") or []
    route_path = route_paths[0] if route_paths else None
    route_path = _truncate(route_path, 512) if route_path else None

    request_path = _truncate(req.get("uri"), 1024)
    query_string = _truncate(_qs_to_string(req.get("querystring")) or "", 2048)

    # Compute effective FHIR path by stripping base prefixes and/or Kong route base
    effective_path = _strip_base_prefix(request_path, route_path)

    fhir_obj = entry.get("fhir", {}) or {}
    resource_type = fhir_obj.get("resource_type")
    resource_id = fhir_obj.get("resource_id")
    operation = fhir_obj.get("operation")
    if resource_type is None and resource_id is None and operation is None:
        rt, rid, op = _parse_fhir_path(effective_path)
        resource_type, resource_id, operation = rt, rid, op

    # Fallback: collection GET → search
    if method == "GET" and resource_type and not resource_id and not (operation and operation.startswith("$")):
        operation = operation or "search"

    # Keep existing value if it's an operation like $export or _history we already detected
    if not operation:
        if method == 'GET':
         if resource_type and resource_id:
            operation = 'read'
        elif resource_type and not resource_id:
            operation = 'search'
    elif method == 'POST':
        # create at type endpoint; POST with id is uncommon in FHIR
        operation = 'create'
    elif method == 'PUT':
        operation = 'update'
    elif method == 'PATCH':
        operation = 'patch'
    elif method == 'DELETE':
        operation = 'delete'


    request_bytes = req.get("size")
    response_bytes = resp.get("size")
    latency_ms = (entry.get("latencies") or {}).get("request")

    request_id = _get_first(req, "id") or _get_first(resp_headers, "x-kong-request-id")
    request_id = _truncate(request_id, 128) if request_id else None

    # Derive a human-friendly error_reason for 4xx/5xx
    error_reason = None
    try:
        st = int(status_code) if status_code is not None else None
        if st and st >= 400:
            # Prefer any hints from headers first (rare)
            error_reason = (
                _get_first(resp_headers, "x-kong-upstream-status")
                or _get_first(resp_headers, "x-kong-balancer-retries")
            )
            if not error_reason:
                # Heuristic mapping by status + credential type
                if st == 401:
                    if credential_type == "apikey":
                        error_reason = "invalid_api_key"
                    elif credential_type == "oauth2":
                        error_reason = "invalid_token"
                    elif credential_type == "basic":
                        error_reason = "invalid_basic_credentials"
                    else:
                        error_reason = "invalid_auth_credentials"
                elif st == 403:
                    error_reason = "forbidden"
                elif st == 404:
                    error_reason = "not_found"
                elif st == 405:
                    error_reason = "method_not_allowed"
                elif st == 409:
                    error_reason = "conflict"
                elif st == 413:
                    error_reason = "payload_too_large"
                elif st == 415:
                    error_reason = "unsupported_media_type"
                elif st == 422:
                    error_reason = "unprocessable_entity"
                elif st == 429:
                    error_reason = "rate_limited"
                elif 500 <= st <= 599:
                    error_reason = "upstream_error"
                else:
                    error_reason = f"http_{st}"
    except Exception:
        pass
    error_reason = _truncate(error_reason, 256) if error_reason else None

    user_agent = _get_first(req_headers, "user-agent")
    user_agent = _truncate(user_agent, 256) if user_agent else None

    return (
        event_ts, client_ip, kong_node, consumer_id, consumer_username,
        credential_type, auth_subject, scopes, method, status_code,
        service_name, route_path, request_path, query_string, resource_type,
        resource_id, operation, request_bytes, response_bytes, latency_ms,
        request_id, error_reason, user_agent,
    )


# ---------------------
# FastAPI app
# ---------------------
app = FastAPI(title="Kong HTTP Log → IRIS Ingest (Step 2)")


@app.get("/healthz")
async def healthz():
    # also verify DB connection
    try:
        conn = _connect()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchall()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@app.post("/kong-log")
async def kong_log(request: Request):
    # Bearer token enforcement
    if LOG_BEARER_TOKEN:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != LOG_BEARER_TOKEN:
            raise HTTPException(status_code=401, detail="invalid token")

    raw = await request.body()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json")

    if isinstance(payload, dict):
        entries: Iterable[Dict[str, Any]] = [payload]
    elif isinstance(payload, list):
        entries = payload
    else:
        raise HTTPException(status_code=400, detail="unexpected payload type")

    rows: List[List[Any]] = [list(map_entry_to_row(e)) for e in entries]

    conn = _connect()
    cur = conn.cursor()

    # Clear, Pylance-friendly error handling
    try:
        # executemany expects a sequence of sequences; IRIS driver prefers lists
        cur.executemany(INSERT_SQL, rows)
    except Exception as e:
        if INGEST_DEBUG:
            log.error("Batch insert failed: %s", e)
        ok = 0
        for r in rows:
            try:
                cur.execute(INSERT_SQL, r if isinstance(r, list) else list(r))
                ok += 1
            except Exception as ie:
                if INGEST_DEBUG:
                    log.error("Row insert failed: %s | row=%s", ie, r)
        try:
            conn.commit()
        except Exception:
            pass
        return {"accepted": ok, "failed": len(rows) - ok}
    else:
        try:
            conn.commit()
        except Exception:
            pass
        return {"accepted": len(rows)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("konglog_ingest:app", host="0.0.0.0", port=8082)
