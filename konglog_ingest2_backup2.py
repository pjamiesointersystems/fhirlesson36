"""
konglog_ingest2.py
--------------------------------
FastAPI receiver for Kong HTTP Log with IRIS for Health storage.

• Robust POST parsing (handles transport gzip/deflate; JSON object/array/NDJSON)
• Recovers upstream response body from HTTP Log custom fields:
    - response_body_b64 (preferred)  -> base64 decode
    - response_body      (raw bytes serialized as JSON string) -> latin-1 encode
  then gunzips if needed and extracts Patient IDs
• Merges response-derived entities with request-derived ones (deduped)
• 5 MiB cap (configurable via MAX_BODY_BYTES)
• Inserts into AUDIT.fhir_logs and AUDIT.fhir_entities

Run:
  IRIS_CONNECTION_STRING=127.0.0.1:1972/DEMO \
  IRIS_USER=_SYSTEM IRIS_PASSWORD=ISCDEMO \
  IRIS_LOG_TABLE=AUDIT.fhir_logs IRIS_ENTITY_TABLE=AUDIT.fhir_entities \
  LOG_BEARER_TOKEN=fhirdemotoken \
  ENABLE_ENTITY_INSERT=true ENABLE_RESPONSE_BODY_PARSE=true \
  MAX_BODY_BYTES=5242880 \
  uv run uvicorn konglog_ingest2_refactored:app --host 0.0.0.0 --port 8082
"""

import os
import json
import logging
import re
import gzip
import zlib
import base64
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import iris  # pip/uv: intersystems-irispython

# ------------------------------------------------------------------------------
# Config (ENV)
# ------------------------------------------------------------------------------

IRIS_CONNECTION_STRING = os.getenv("IRIS_CONNECTION_STRING", "127.0.0.1:1972/DEMO")
IRIS_USER              = os.getenv("IRIS_USER", "_SYSTEM")
IRIS_PASSWORD          = os.getenv("IRIS_PASSWORD", "ISCDEMO")

IRIS_LOG_TABLE         = os.getenv("IRIS_LOG_TABLE", "AUDIT.fhir_logs")
IRIS_ENTITY_TABLE      = os.getenv("IRIS_ENTITY_TABLE", "AUDIT.fhir_entities")

LOG_BEARER_TOKEN       = os.getenv("LOG_BEARER_TOKEN", "fhirdemotoken")

ENABLE_ENTITY_INSERT       = os.getenv("ENABLE_ENTITY_INSERT", "true").lower() in {"1","true","yes"}
ENABLE_RESPONSE_BODY_PARSE = os.getenv("ENABLE_RESPONSE_BODY_PARSE", "true").lower() in {"1","true","yes"}

MAX_BODY_BYTES         = int(os.getenv("MAX_BODY_BYTES", str(5 * 1024 * 1024)))  # 5 MiB

INGEST_DEBUG           = os.getenv("INGEST_DEBUG", "true").lower() in {"1","true","yes"}

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO if not INGEST_DEBUG else logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("konglog_ingest2")

# ------------------------------------------------------------------------------
# App
# ------------------------------------------------------------------------------

app = FastAPI(title="Kong FHIR Log Ingest v2 (refactored)")

# ------------------------------------------------------------------------------
# IRIS
# ------------------------------------------------------------------------------

def _connect():
    return iris.connect(IRIS_CONNECTION_STRING, IRIS_USER, IRIS_PASSWORD)

INSERT_LOG_SQL = f"""
INSERT INTO {IRIS_LOG_TABLE} (
    event_ts, client_ip, kong_node, consumer_id, consumer_username,
    credential_type, auth_subject, scopes, method, status_code,
    service_name, route_path, request_path, query_string,
    resource_type, resource_id, operation, request_bytes, response_bytes,
    latency_ms, request_id, error_reason, user_agent
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""

INSERT_ENTITY_SQL = f"""
INSERT INTO {IRIS_ENTITY_TABLE} (
    log_id, event_ts, patient_id, source_resource_type, source_resource_id,
    relation, ref_path, is_direct_target, operation, request_id
) VALUES (?,?,?,?,?,?,?,?,?,?)
"""

# ------------------------------------------------------------------------------
# Helpers: read HTTP-log POST and recover upstream body
# ------------------------------------------------------------------------------

async def _read_json_events(req: Request) -> List[Dict[str, Any]]:
    """Read Kong HTTP Log POST (object, array, or NDJSON). Tolerate transport gzip/deflate."""
    raw = await req.body()
    enc = (req.headers.get("content-encoding") or "").lower()
    try:
        if enc == "gzip" or (len(raw) >= 2 and raw[:2] == b"\x1f\x8b"):
            raw = gzip.decompress(raw)
        elif enc in ("deflate", "zlib"):
            raw = zlib.decompress(raw)
    except Exception:
        pass

    text = raw.decode("utf-8")
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        # NDJSON fallback
        events: List[Dict[str, Any]] = []
        for line in filter(None, (ln.strip() for ln in text.splitlines())):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                if INGEST_DEBUG:
                    log.debug("Skipping non-JSON NDJSON line")
        if events:
            return events
        raise

def _response_bytes_from_entry(entry: Dict[str, Any]) -> Optional[bytes]:
    """
    Recover upstream response bytes from:
      - response_body_b64 (base64; preferred)
      - response_body (JSON string containing raw bytes)
    Then gunzip if Content-Encoding suggests gzip or if magic bytes present.
    """
    data: Optional[bytes] = None

    b64 = entry.get("response_body_b64")
    if isinstance(b64, str) and b64:
        try:
            data = base64.b64decode(b64, validate=True)
        except Exception:
            try:
                data = base64.b64decode(b64)
            except Exception:
                data = None

    if data is None:
        s = entry.get("response_body")
        if isinstance(s, str) and s:
            data = s.encode("latin-1", errors="ignore")

    if not data:
        return None

    # Decompress?
    try:
        ce = ""
        hdrs = (entry.get("response") or {}).get("headers") or {}
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if k.lower() == "content-encoding":
                    ce = (v or "").lower()
                    break
        if data[:2] == b"\x1f\x8b" or ("gzip" in ce):
            data = gzip.decompress(data)
    except Exception as e:
        if INGEST_DEBUG:
            log.debug("Gunzip failed (continuing with raw): %s", e)

    return data

# ------------------------------------------------------------------------------
# FHIR utilities
# ------------------------------------------------------------------------------

def _now_ts_from_entry(entry: Dict[str, Any]) -> str:
    """Use started_at (ms) if available; else now UTC. Return 'YYYY-MM-DD HH:MM:SS'."""
    from datetime import datetime, timezone
    started_at = entry.get("started_at")
    try:
        if isinstance(started_at, (int, float)):
            dt = datetime.fromtimestamp(float(started_at) / 1000.0, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def _parse_operation(method: str, path: str, status: int) -> str:
    method = (method or "GET").upper()
    op = "read"
    if "?" in (path or ""):
        op = "search"
    if method == "POST":
        op = "create"
    elif method in ("PUT", "PATCH"):
        op = "update"
    elif method == "DELETE":
        op = "delete"
    return op

def _split_resource(path_after_base: str) -> Tuple[Optional[str], Optional[str]]:
    seg = (path_after_base or "").split("?", 1)[0].strip("/")
    parts = seg.split("/")
    if not parts or parts[0] == "":
        return None, None
    rtype = parts[0]
    rid = parts[1] if len(parts) > 1 else None
    return rtype, rid

def _guess_credential_type(req_headers: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort infer auth scheme/subject from request headers augmented by Kong."""
    h = { (k or "").lower(): v for k, v in (req_headers or {}).items() }
    scheme = None
    subject = None
    if "apikey" in h:
        scheme = "apikey"
        subject = h.get("x-credential-identifier") or h.get("apikey") or None
    auth = h.get("authorization")
    if not scheme and auth is not None:
        scheme = "basic"
        subject = h.get("x-credential-identifier") or "redacted"
    return scheme, subject

def _querystring_to_text(qs: Dict[str, Any]) -> str:
    try:
        from urllib.parse import urlencode
        return urlencode([(k, v) for k, v in (qs or {}).items()])
    except Exception:
        if not qs:
            return ""
        return "&".join(f"{k}={v}" for k, v in qs.items())

def map_entry_to_log_row(entry: Dict[str, Any]) -> List[Any]:
    """Map Kong http-log entry → AUDIT.fhir_logs row."""
    req: Dict[str, Any] = entry.get("request") or {}
    resp: Dict[str, Any] = entry.get("response") or {}
    service: Dict[str, Any] = entry.get("service") or {}
    route: Dict[str, Any] = entry.get("route") or {}
    consumer: Dict[str, Any] = entry.get("consumer") or {}

    method = (req.get("method") or "GET").upper()
    status = int(resp.get("status") or 0)

    event_ts = _now_ts_from_entry(entry)
    client_ip = entry.get("client_ip")
    kong_node = "kong-1"  # label only
    consumer_id = consumer.get("id")
    consumer_username = consumer.get("username")

    req_headers = req.get("headers") or {}
    credential_type, auth_subject = _guess_credential_type(req_headers)
    scopes = None

    service_name = service.get("name")
    route_paths = route.get("paths") or []
    route_path = route_paths[0] if route_paths else None
    request_path = req.get("uri")
    query_string = _querystring_to_text(req.get("querystring"))

    resource_type = None
    resource_id = None
    if request_path and route_path and request_path.startswith(route_path):
        tail = request_path[len(route_path):].lstrip("/")
        resource_type, resource_id = _split_resource(tail)

    operation = _parse_operation(method, request_path or "", status)

    request_bytes = int(req.get("size") or 0)
    response_bytes = int(resp.get("size") or 0)
    latencies = entry.get("latencies") or {}
    latency_ms = int(latencies.get("proxy") or 0)

    request_id = (req.get("id")
                  or (resp.get("headers") or {}).get("x-kong-request-id")
                  or entry.get("started_at"))

    error_reason = None
    if status >= 400:
        error_reason = (resp.get("headers") or {}).get("x-kong-status") or None

    user_agent = (req_headers or {}).get("user-agent")

    return [
        event_ts, client_ip, kong_node, consumer_id, consumer_username,
        credential_type, auth_subject, scopes, method, status,
        service_name, route_path, request_path, query_string,
        resource_type, resource_id, operation, request_bytes, response_bytes,
        latency_ms, request_id, error_reason, user_agent
    ]

# ------------------------------------------------------------------------------
# Entity extraction (request & response)
# ------------------------------------------------------------------------------

def build_entity_rows(entry: Dict[str, Any], log_id: int, event_ts: str,
                      base_op: str, request_id: Any, route_path: Optional[str]) -> List[List[Any]]:
    """Direct Patient read (/Patient/{id}) from the request path."""
    rows: List[List[Any]] = []
    req: Dict[str, Any] = entry.get("request") or {}
    uri = req.get("uri") or ""
    tail = uri
    if route_path and uri.startswith(route_path):
        tail = uri[len(route_path):]
    tail = tail.lstrip("/")
    resource_type, rid = _split_resource(tail)
    if resource_type == "Patient" and rid:
        rows.append([
            log_id, event_ts, rid, "Patient", rid,
            "direct", "path", 1, base_op, request_id
        ])
    return rows

import json
from typing import Iterable, Iterator, List, Tuple, Dict, Any, Set

def _walk_patient_refs(obj: Any, path: str="") -> Iterator[Tuple[str, str]]:
    """
    Yields (patient_id, ref_path) for any Patient reference found anywhere in obj.
    Handles shapes like:
      {"subject":{"reference":"Patient/123"}}
      {"patient":{"reference":"Patient/123"}}
      {"reference":"Patient/123"}
    """
    # Direct "reference": "Patient/123"
    if isinstance(obj, dict):
        ref = obj.get("reference")
        if isinstance(ref, str) and ref.startswith("Patient/"):
            yield (ref.split("/", 1)[1], f"{path+'.' if path else ''}reference")

        # Common named fields (subject/patient) that contain Reference objects
        for k in ("subject", "patient"):
            if k in obj:
                sub = obj[k]
                if isinstance(sub, dict):
                    r = sub.get("reference")
                    if isinstance(r, str) and r.startswith("Patient/"):
                        yield (r.split("/", 1)[1], f"{path+'.' if path else ''}{k}.reference")

        # Recurse dict
        for k, v in obj.items():
            if k in ("reference",):  # already checked
                continue
            new_path = f"{path+'.' if path else ''}{k}"
            for tup in _walk_patient_refs(v, new_path):
                yield tup

    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_path = f"{path}[{i}]"
            for tup in _walk_patient_refs(v, new_path):
                yield tup


def extract_patient_ids_from_body(body_text: str) -> List[Tuple[str, str, str, str, str]]:
    """
    Returns list of tuples:
      (patient_id, relation, ref_path, source_resource_type, source_resource_id)

    relation is 'search' for Bundle entries, 'reference' for single-resource bodies.
    """
    try:
        body = json.loads(body_text)
    except Exception:
        return []

    if not isinstance(body, dict):
        return []

    rtype = body.get("resourceType")
    rid = body.get("id")

    out: List[Tuple[str, str, str, str, str]] = []
    seen: Set[Tuple[str, str, str, str, str]] = set()

    if rtype == "Bundle":
        # Iterate over entries; stamp src from entry.resource
        entries = body.get("entry") or []
        for idx, ent in enumerate(entries):
            res = (ent or {}).get("resource") or {}
            etype = res.get("resourceType")
            eid = res.get("id")
            if not isinstance(res, dict) or not etype:
                continue
            for pid, ref_path in _walk_patient_refs(res, path=f"entry[{idx}].resource"):
                row = (pid, "search", ref_path, etype, (eid or ""))
                if row not in seen:
                    seen.add(row)
                    out.append(row)
    else:
        # Single resource (Observation, Encounter, etc.)
        # Stamp hits with this container resource type/id
        for pid, ref_path in _walk_patient_refs(body, path=rtype or "resource"):
            row = (pid, "reference", ref_path, (rtype or ""), (rid or ""))
            if row not in seen:
                seen.add(row)
                out.append(row)

    return out

# ------------------------------------------------------------------------------
# Utility: identity normalization (IRIS driver often returns nested sequences)
# ------------------------------------------------------------------------------

def _is_seq_like(x):
    # Treat DataRow/list/tuple/etc as sequence-like, but not strings/bytes
    return hasattr(x, "__len__") and hasattr(x, "__getitem__") and not isinstance(x, (str, bytes, bytearray))

def _as_scalar(v):
    """
    Peel nested sequence-like layers (including IRIS DataRow/list/tuple)
    until we reach a scalar: [[71]] -> [71] -> 71
    """
    # Limit depth to prevent accidental infinite loops
    for _ in range(10):
        if _is_seq_like(v) and len(v) == 1:
            v = v[0]
        else:
            break
    return v

def _normalize_identity_value(val):
    val = _as_scalar(val)
    # Some drivers wrap numbers in Decimal-like objects or strings
    try:
        return int(val)
    except Exception:
        # As a last resort, try str -> int
        return int(str(val))

def _get_inserted_log_id(cur) -> int:
    """
    Fetch last inserted identity robustly:
    - Try LAST_IDENTITY()
    - Fallback to MAX(log_id)
    Unwrap any sequence-like DataRow into a scalar.
    """
    rows = None
    try:
        cur.execute("SELECT LAST_IDENTITY()")
        rows = cur.fetchall()
    except Exception:
        rows = None

    if not rows:
        cur.execute(f"SELECT MAX(log_id) FROM {IRIS_LOG_TABLE}")
        rows = cur.fetchall()

    if not rows:
        raise RuntimeError("Could not fetch identity row (no rows returned)")

    # rows may be [[71]] or [DataRow(71)] etc.
    scalar = _as_scalar(rows)
    return _normalize_identity_value(scalar)


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    """
    Lightweight health check. If IRIS env vars are present, also pings the DB.
    Always returns HTTP 200 with {"ok": true|false, "error": "..."}.
    """
    return {"ok": True}


@app.get("/kong-log")
async def kong_log(request: Request):
    # ---- Bearer token guard
    if LOG_BEARER_TOKEN:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != LOG_BEARER_TOKEN:
            raise HTTPException(status_code=401, detail="invalid token")

    # ---- Read events array from request body
    try:
        events = await _read_json_events(request)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json")

    if INGEST_DEBUG:
        log.info("Kong POST received: entries=%d", len(events) if events else 0)
    if not events:
        return {"accepted_logs": 0, "accepted_entities": 0}

    # Helper: return UTF-8 JSON text for parsing (handles bytes or str, gzip or plain)
    def _get_response_text(e: Any) -> str:
        # 1) Prefer raw bytes collected by helper (may already be base64-decoded)
        rb = None
        try:
            rb = _response_bytes_from_entry(e)  # may be None
        except Exception as exc:
            print(exc)

        # 2) If not present, try 'response_body'
        if rb is None:
            b = e.get("response_body")
            if isinstance(b, (bytes, bytearray)):
                rb = bytes(b)
            elif isinstance(b, str):
                # Kong often delivers gzipped bytes inside a JSON string.
                # Reinterpret the string's code points as raw bytes (latin-1 preserves 0x00-0xFF)…
                raw = b.encode("latin-1", errors="ignore")
                rb = raw

        if not rb:
            return ""

        # 3) Detect gzip (by header or magic) and decompress
        enc = ""
        try:
            enc = (e.get("response", {}).get("headers", {}).get("content-encoding") or "").lower()
        except Exception:
            enc = ""

        is_gzip = (len(rb) >= 2 and rb[0] == 0x1F and rb[1] == 0x8B) or ("gzip" in enc)
        if is_gzip:
            try:
                rb = gzip.decompress(rb)
            except Exception as e:
                print(e)
                # if gunzip fails, keep original bytes
                pass

        return rb.decode("utf-8", errors="ignore")[:MAX_BODY_BYTES]

    conn = _connect(); cur = conn.cursor()
    accepted_logs = 0
    accepted_entities = 0

    for entry in events:
        # 1) Insert into AUDIT.fhir_logs
        log_row = map_entry_to_log_row(entry)
        try:
            cur.execute(INSERT_LOG_SQL, list(log_row))
            log_id = _get_inserted_log_id(cur)
            accepted_logs += 1
        except Exception as e:
            if INGEST_DEBUG:
                log.error("Log insert failed: %s | row=%s", e, log_row)
            continue

        if not ENABLE_ENTITY_INSERT:
            continue

        event_ts   = log_row[0]
        route_path = log_row[11]
        base_op    = log_row[16]
        request_id = log_row[20]

        # URL container fallback (e.g., Observation/1 from path for read ops)
        url_container_type = (log_row[14] or "").strip() or None
        url_container_id   = (log_row[15] or "").strip() or None

        try:
            # 2) Entities from metadata (direct reads etc.)
            ent_rows: List[List[Any]] = build_entity_rows(
                entry, log_id, event_ts, base_op, request_id, route_path
            )

            # 3) Enrich from response body (search bundles, references)
            if ENABLE_RESPONSE_BODY_PARSE:
                text = _get_response_text(entry)
                container_type, container_id = None, None

                if text:
                    # Detect container for single-resource bodies
                    try:
                        body_json = json.loads(text)
                        if isinstance(body_json, dict):
                            rt = body_json.get("resourceType")
                            if isinstance(rt, str) and rt and rt != "Bundle":
                                container_type = rt
                                cid = body_json.get("id")
                                if isinstance(cid, str) and cid:
                                    container_id = cid
                    except Exception:
                        pass

                    # Best fallback (single resource first, else from URL)
                    fallback_type = container_type or url_container_type
                    fallback_id   = container_id   or url_container_id

                    # De-dup keys
                    existing = {(r[2], r[5], r[3] or None, r[4] or None, r[6] or None) for r in ent_rows}
                    extras: List[List[Any]] = []
                    try:
                        # (patient_id, relation, ref_path, src_type, src_id)
                        for pid, relation, ref_path, src_type, src_id in extract_patient_ids_from_body(text):
                            stype = (src_type or "").strip()
                            sid   = (src_id  or "").strip()

                            # If extractor lacked/said 'Bundle' (wrong for single-resource),
                            # override with detected container or URL container.
                            if not stype or stype == "Bundle":
                                if fallback_type:
                                    stype = fallback_type
                                if not sid and fallback_id:
                                    sid = fallback_id

                            key = (pid, relation, stype or None, sid or None, ref_path or None)
                            if key in existing:
                                continue

                            extras.append([
                                _normalize_identity_value(log_id),  # 0 log_id
                                event_ts,                           # 1 event_ts
                                pid,                                # 2 patient_id
                                stype or "",                        # 3 source_resource_type
                                sid or "",                          # 4 source_resource_id
                                relation,                           # 5 relation
                                ref_path,                           # 6 ref_path
                                0,                                  # 7 is_direct_target
                                base_op,                            # 8 request_operation
                                request_id                          # 9 request_id
                            ])
                    except Exception as e:
                        if INGEST_DEBUG:
                            log.error("Response body parse failed: %s", e)

                    if extras:
                        ent_rows.extend(extras)

            # 4) Insert entities
            for r in ent_rows:
                params = list(r)
                params[0] = _normalize_identity_value(params[0])
                if INGEST_DEBUG:
                    if len(params) != 10:
                        log.error("Bad entity row length: %d | row=%r", len(params), params)
                    else:
                        for idx, val in enumerate(params):
                            if isinstance(val, (list, dict, tuple, set)):
                                log.error("Unsupported param type at col %d: %s (%r)", idx, type(val), val)
                cur.execute(INSERT_ENTITY_SQL, params)

            accepted_entities += len(ent_rows)

        except Exception as e:
            if INGEST_DEBUG:
                log.error("Entity insert failed: %s", e)

    try:
        conn.commit()
    except Exception:
        pass
    finally:
        try: cur.close()
        except Exception: pass
        try: conn.close()
        except Exception: pass

    return {"accepted_logs": accepted_logs, "accepted_entities": accepted_entities}

# Ensure both /kong-log and /kong-log/ hit the same handler
@app.post("/kong-log", include_in_schema=False)
async def kong_log_noslash(request: Request):
    return await kong_log(request)

@app.post("/kong-log/", include_in_schema=False)
async def kong_log_slash(request: Request):
    return await kong_log(request)


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8082"))
    uvicorn.run("konglog_ingest2:app", host=host, port=port, reload=False)

