# konglog_ingest2.py
# A clean FastAPI receiver for Kong HTTP Log that writes to InterSystems IRIS
# and (optionally) extracts Patient entities from FHIR responses.
#
# Run example:
# IRIS_CONNECTION_STRING=127.0.0.1:1972/DEMO \
# IRIS_USER=_SYSTEM IRIS_PASSWORD=ISCDEMO \
# IRIS_LOG_TABLE=AUDIT.fhir_logs IRIS_ENTITY_TABLE=AUDIT.fhir_entities \
# LOG_BEARER_TOKEN=fhirdemotoken \
# ENABLE_ENTITY_INSERT=1 ENABLE_RESPONSE_BODY_PARSE=1 MAX_BODY_BYTES=5242880 \
# uv run uvicorn konglog_ingest2:app --host 0.0.0.0 --port 8082

import os
import json
import gzip
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn


# -------------------- Configuration --------------------

IRIS_CONNECTION_STRING = os.getenv("IRIS_CONNECTION_STRING", "127.0.0.1:1972/DEMO")
IRIS_USER              = os.getenv("IRIS_USER", "_SYSTEM")
IRIS_PASSWORD          = os.getenv("IRIS_PASSWORD", "ISCDEMO")
IRIS_LOG_TABLE         = os.getenv("IRIS_LOG_TABLE", "AUDIT.fhir_logs")
IRIS_ENTITY_TABLE      = os.getenv("IRIS_ENTITY_TABLE", "AUDIT.fhir_entities")
LOG_BEARER_TOKEN       = os.getenv("LOG_BEARER_TOKEN", "fhirdemotoken")
KONG_NODE              = os.getenv("KONG_NODE", "kong-1")

# Feature flags
ENABLE_ENTITY_INSERT       = os.getenv("ENABLE_ENTITY_INSERT", "1") not in ("0", "false", "False", "")
ENABLE_RESPONSE_BODY_PARSE = os.getenv("ENABLE_RESPONSE_BODY_PARSE", "1") not in ("0", "false", "False", "")
MAX_BODY_BYTES             = int(os.getenv("MAX_BODY_BYTES", str(5 * 1024 * 1024)))  # default 5 MiB
INGEST_DEBUG               = os.getenv("INGEST_DEBUG", "1") not in ("0", "false", "False", "")

# -------------------- Logging --------------------

log = logging.getLogger("konglog")
logging.basicConfig(level=logging.DEBUG if INGEST_DEBUG else logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# -------------------- App --------------------

app = FastAPI(title="Kong FHIR HTTP Log Receiver", version="2.0")

@app.get("/healthz", include_in_schema=False)
@app.head("/healthz", include_in_schema=False)
async def healthz():
    """
    Lightweight health check. If IRIS env vars are present, also pings the DB.
    Always returns 200 with {"ok": true|false, "error": "..."}.
    """
    try:
        if IRIS_CONNECTION_STRING and IRIS_USER and IRIS_PASSWORD:
            _ = _connect()  # will raise on failure
            _.close()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=200, content={"ok": False, "error": str(e)})

# Accept both /kong-log and /kong-log/ to avoid trailing-slash mismatches
@app.post("/kong-log", include_in_schema=False)
async def kong_log_noslash(request: Request):
    return await _kong_log_impl(request)

@app.post("/kong-log/", include_in_schema=False)
async def kong_log_slash(request: Request):
    return await _kong_log_impl(request)

# -------------------- IRIS DB helpers --------------------

def _connect():
    """
    Returns an IRIS DB-API connection using the 'iris' module from intersystems-irispython.
    """
    try:
        import iris  # provided by intersystems-irispython
    except Exception as e:
        raise RuntimeError("IRIS Python driver 'iris' is not installed. Use: uv add intersystems-irispython") from e

    conn = iris.connect(IRIS_CONNECTION_STRING, IRIS_USER, IRIS_PASSWORD)
    return conn

INSERT_LOG_SQL = f"""
INSERT INTO {IRIS_LOG_TABLE}
(event_ts, client_ip, kong_node, consumer_id, consumer_username, credential_type, auth_subject, scopes,
 method, status_code, service_name, route_path, request_path, query_string, resource_type, resource_id,
 operation, request_bytes, response_bytes, latency_ms, request_id, error_reason, user_agent)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""

INSERT_ENTITY_SQL = f"""
INSERT INTO {IRIS_ENTITY_TABLE}
(log_id, event_ts, patient_id, source_resource_type, source_resource_id, relation, ref_path,
 is_direct_target, operation, request_id)
VALUES (?,?,?,?,?,?,?,?,?,?)
"""

def _get_inserted_log_id(cur) -> int:
    """
    Retrieve the last inserted log_id in a portable way.
    """
    try:
        cur.execute("SELECT LAST_IDENTITY()")
        rid = cur.fetchall()[0][0]
        return int(rid)
    except Exception:
        cur.execute(f"SELECT MAX(log_id) FROM {IRIS_LOG_TABLE}")
        rid = cur.fetchall()[0][0]
        return int(rid)

def _normalize_identity_value(x: Any) -> int:
    if isinstance(x, (list, tuple)):
        if len(x) == 1:
            x = x[0]
        else:
            raise ValueError("Unexpected identity wrapper")
    if isinstance(x, (str, bytes)):
        try:
            return int(x)
        except Exception:
            pass
    if isinstance(x, (int,)):
        return x
    raise ValueError(f"Unsupported identity type: {type(x)}")

# -------------------- Parsing helpers --------------------

def _ts_from_entry(entry: Dict[str, Any]) -> str:
    # Kong started_at is epoch ms
    started = entry.get("started_at")
    if isinstance(started, (int, float)):
        dt = datetime.fromtimestamp(float(started) / 1000.0, tz=timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def _derive_paths(entry: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Returns (route_path, request_path, query_string)
    """
    route_path = ""
    try:
        paths = entry.get("route", {}).get("paths") or []
        if isinstance(paths, list) and paths:
            route_path = str(paths[0])
    except Exception:
        route_path = ""

    request_path = entry.get("request", {}).get("uri") or ""
    # Build query string from dict, if present
    qd = entry.get("request", {}).get("querystring") or {}
    if isinstance(qd, dict) and qd:
        query_string = "&".join(f"{k}={qd[k]}" for k in qd.keys())
    else:
        # try to split from uri
        if "?" in request_path:
            query_string = request_path.split("?", 1)[1]
        else:
            query_string = ""
    return route_path, request_path, query_string

def _parse_resource_from_path(route_path: str, request_path: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract resource_type and resource_id from request_path after stripping the route_path prefix.
    """
    rp = request_path or ""
    base = route_path or ""
    # Ensure normalized slashes
    if base and rp.startswith(base):
        tail = rp[len(base):]
    else:
        tail = rp
    # strip leading '/'
    if tail.startswith("/"):
        tail = tail[1:]
    # now first segment = resource type, second = id
    if not tail:
        return None, None
    segs = tail.split("?", 1)[0].split("/")
    if len(segs) == 0 or not segs[0]:
        return None, None
    rtype = segs[0]
    rid = segs[1] if len(segs) > 1 and segs[1] else None
    return rtype, rid

def _derive_operation(method: str, resource_type: Optional[str], resource_id: Optional[str]) -> str:
    m = (method or "").upper()
    if m == "GET":
        if resource_type and resource_id:
            return "read"
        # metadata or capability statements could be here, but default to search when no id
        return "search"
    if m == "POST":
        return "create"
    if m == "PUT":
        return "update"
    if m == "PATCH":
        return "patch"
    if m == "DELETE":
        return "delete"
    return m.lower() or "unknown"

def _derive_auth(entry: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (credential_type, auth_subject). Prefers pre/post-function injected 'auth' field.
    """
    a = entry.get("auth")
    if isinstance(a, dict):
        scheme = a.get("scheme")
        subject = a.get("subject")
        if scheme:
            return str(scheme), (str(subject) if subject is not None else None)

    # Heuristics: DO NOT record secrets
    hdrs = entry.get("request", {}).get("headers") or {}
    if "apikey" in hdrs or "x-api-key" in hdrs:
        return "apikey", hdrs.get("x-credential-identifier") or None
    if "authorization" in hdrs:
        # Kong redacts the value; we only know scheme type (likely basic)
        return "basic", hdrs.get("x-credential-identifier") or entry.get("consumer", {}).get("username")
    return None, None

def _derive_error_reason(status: int, credential_type: Optional[str]) -> Optional[str]:
    if status >= 500:
        return "upstream_error"
    if status == 401:
        return "invalid_api_key" if credential_type == "apikey" else "invalid_auth_credentials"
    if status == 403:
        return "forbidden"
    if status == 404:
        return "not_found"
    return None

def _get_request_id(entry: Dict[str, Any]) -> Optional[str]:
    # Kong usually adds X-Kong-Request-Id on response
    try:
        rh = entry.get("response", {}).get("headers") or {}
        rid = rh.get("x-kong-request-id") or rh.get("X-Kong-Request-Id")
        if rid:
            return str(rid)
    except Exception:
        pass
    rid = entry.get("request", {}).get("id")
    return str(rid) if rid else None

import base64
import gzip

def _get_response_text(entry: Dict[str, Any]) -> str:
    """
    Return UTF-8 JSON text for the response body (<= MAX_BODY_BYTES).
    Prefers base64 field 'response_body_b64'. Falls back to 'response_body'
    (raw string) if present. Gunzips when magic bytes are present or when
    Kong headers indicate gzip.
    """
    rb: Optional[bytes] = None

    # Preferred: base64 from pre-function log phase
    b64 = entry.get("response_body_b64")
    if isinstance(b64, str) and b64:
        try:
            rb = base64.b64decode(b64, validate=False)
        except Exception:
            rb = None

    # Fallback: raw string (may be JSON-escaped bytes)
    if rb is None:
        raw = entry.get("response_body")
        if isinstance(raw, (bytes, bytearray)):
            rb = bytes(raw)
        elif isinstance(raw, str):
            # This won't fix JSON-escaped bytes, but keeps backward compatibility
            rb = raw.encode("latin-1", errors="ignore")

    if not rb:
        return ""

    # Trim to cap before decompress
    if len(rb) > MAX_BODY_BYTES:
        rb = rb[:MAX_BODY_BYTES]

    # Honor headers (if present) or magic bytes for gzip
    enc = ""
    try:
        enc = (entry.get("resp_content_encoding") or
               entry.get("response", {}).get("headers", {}).get("content-encoding") or "")
        enc = enc.lower()
    except Exception:
        enc = ""

    is_gzip = (len(rb) >= 2 and rb[0] == 0x1F and rb[1] == 0x8B) or ("gzip" in enc)
    if is_gzip:
        try:
            rb = gzip.decompress(rb)
        except Exception:
            # Keep as-is if decompression fails
            pass

    return rb.decode("utf-8", errors="ignore")[:MAX_BODY_BYTES]


# -------------------- Entity extraction --------------------

def _walk_patient_refs(obj: Any, path: str = "") -> Iterator[Tuple[str, str]]:
    """
    Yields (patient_id, ref_path) for any Patient reference found anywhere in obj.
    Detects shapes like:
      {"subject":{"reference":"Patient/123"}}
      {"patient":{"reference":"Patient/123"}}
      {"reference":"Patient/123"}
    """
    if isinstance(obj, dict):
        # direct 'reference'
        ref = obj.get("reference")
        if isinstance(ref, str) and ref.startswith("Patient/"):
            yield (ref.split("/", 1)[1], f"{path + '.' if path else ''}reference")
        # common named fields
        for k in ("subject", "patient"):
            if k in obj and isinstance(obj[k], dict):
                r = obj[k].get("reference")
                if isinstance(r, str) and r.startswith("Patient/"):
                    yield (r.split("/", 1)[1], f"{path + '.' if path else ''}{k}.reference")
        # recurse
        for k, v in obj.items():
            if k in ("reference",):
                continue
            newp = f"{path + '.' if path else ''}{k}"
            for tup in _walk_patient_refs(v, newp):
                yield tup
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            newp = f"{path}[{i}]"
            for tup in _walk_patient_refs(v, newp):
                yield tup

def extract_patient_ids_from_body(body_text: str) -> List[Tuple[str, str, str, str, str]]:
    """
    Parses FHIR JSON text and returns tuples:
      (patient_id, relation, ref_path, source_resource_type, source_resource_id)
    - For Bundle search results: 'relation' = 'search' (from entry.resource where resourceType=='Patient')
      and we also collect 'reference' occurrences inside non-Patient resources.
    - For single resources: 'relation' = 'reference' for any Patient references found.
    """
    try:
        doc = json.loads(body_text)
    except Exception:
        return []

    if not isinstance(doc, dict):
        return []

    out: List[Tuple[str, str, str, str, str]] = []
    seen: Set[Tuple[str, str, str, str, str]] = set()

    rtype = doc.get("resourceType")
    rid = doc.get("id")

    if rtype == "Bundle":
        entries = doc.get("entry") or []
        for idx, ent in enumerate(entries):
            res = (ent or {}).get("resource") or {}
            if not isinstance(res, dict):
                continue
            etype = res.get("resourceType")
            eid = res.get("id") or ""
            # Case A: patient entry in search results
            if etype == "Patient" and isinstance(res.get("id"), str):
                row = (res["id"], "search", f"entry[{idx}].resource", "Patient", res["id"])
                if row not in seen:
                    seen.add(row)
                    out.append(row)
            # Case B: references within other resources
            for pid, ref_path in _walk_patient_refs(res, path=f"entry[{idx}].resource"):
                row = (pid, "reference", ref_path, etype or "", eid)
                if row not in seen:
                    seen.add(row)
                    out.append(row)
    else:
        # Single container resource (e.g., Observation)
        for pid, ref_path in _walk_patient_refs(doc, path=rtype or "resource"):
            row = (pid, "reference", ref_path, rtype or "", rid or "")
            if row not in seen:
                seen.add(row)
                out.append(row)

    return out

# -------------------- Mapping logs --------------------

def map_entry_to_log_row(entry: Dict[str, Any]) -> List[Any]:
    event_ts = _ts_from_entry(entry)
    client_ip = entry.get("client_ip")
    kong_node = KONG_NODE

    consumer = entry.get("consumer") or {}
    consumer_id = consumer.get("id")
    consumer_username = consumer.get("username")

    credential_type, auth_subject = _derive_auth(entry)
    scopes = None  # not used in this lab unless you inject it via plugin

    req = entry.get("request") or {}
    method = (req.get("method") or "GET").upper()

    resp = entry.get("response") or {}
    status_code = int(resp.get("status") or 0)

    service_name = entry.get("service", {}).get("name")
    route_path, request_path, query_string = _derive_paths(entry)
    resource_type, resource_id = _parse_resource_from_path(route_path, request_path)

    operation = _derive_operation(method, resource_type, resource_id)

    request_bytes = int(req.get("size") or 0)
    response_bytes = int(resp.get("size") or 0)

    lat = entry.get("latencies") or {}
    latency_ms = int(lat.get("proxy") or lat.get("request") or 0)

    request_id = _get_request_id(entry)

    error_reason = _derive_error_reason(status_code, credential_type)

    user_agent = None
    try:
        user_agent = req.get("headers", {}).get("user-agent")
    except Exception:
        pass

    return [
        event_ts, client_ip, kong_node, consumer_id, consumer_username,
        credential_type, auth_subject, scopes, method, status_code,
        service_name, route_path, request_path, query_string,
        resource_type, resource_id, operation, request_bytes,
        response_bytes, latency_ms, request_id, error_reason, user_agent
    ]

# -------------------- Build entity rows from metadata (no body) --------------------

def build_entity_rows(entry: Dict[str, Any], log_id: int, event_ts: str,
                      base_op: str, request_id: Optional[str], route_path: str) -> List[List[Any]]:
    """
    Build 'direct' rows for Patient reads from the request path alone.
    Body-based search/reference rows are added later.
    """
    rows: List[List[Any]] = []
    req = entry.get("request") or {}
    method = (req.get("method") or "GET").upper()
    _, request_path, _ = _derive_paths(entry)
    resource_type, resource_id = _parse_resource_from_path(route_path, request_path)

    # Direct Patient read -> mark as direct target
    if method == "GET" and resource_type == "Patient" and resource_id:
        rows.append([
            log_id, event_ts, resource_id, "Patient", resource_id,
            "direct", "resource", 1, base_op, request_id
        ])
    return rows

# -------------------- JSON events reader --------------------

async def _read_json_events(request: Request) -> List[Dict[str, Any]]:
    raw = await request.body()
    if not raw:
        return []
    # text decode (request is JSON array or object)
    text = raw.decode("utf-8", errors="ignore").strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as e:
        # Re-raise for caller to turn into 400
        raise e

    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict)]
    return []

# -------------------- Main handler --------------------

async def _kong_log_impl(request: Request):
    # ---- Bearer token check
    if LOG_BEARER_TOKEN:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != LOG_BEARER_TOKEN:
            raise HTTPException(status_code=401, detail="invalid token")

    # ---- Read events
    try:
        events = await _read_json_events(request)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid json")

    if INGEST_DEBUG:
        log.info("Kong POST received: entries=%d", len(events))

    if not events:
        return {"accepted_logs": 0, "accepted_entities": 0}

    conn = _connect(); cur = conn.cursor()
    accepted_logs = 0
    accepted_entities = 0

    for entry in events:
        # 1) Insert fhir_logs row
        log_row = map_entry_to_log_row(entry)
        try:
            cur.execute(INSERT_LOG_SQL, list(log_row))
            log_id = _get_inserted_log_id(cur)
            accepted_logs += 1
        except Exception as e:
            if INGEST_DEBUG:
                log.error("Log insert failed: %s | row=%s", e, log_row)
            continue  # skip entities if log insert failed

        if not ENABLE_ENTITY_INSERT:
            continue

        event_ts   = log_row[0]
        route_path = log_row[11]
        base_op    = log_row[16]
        request_id = log_row[20]

        # 2) Direct rows from metadata
        ent_rows: List[List[Any]] = build_entity_rows(entry, log_id, event_ts, base_op, request_id, route_path) or []
        if not isinstance(ent_rows, list):
            ent_rows = []

        # 3) Enrich from response body
        if ENABLE_RESPONSE_BODY_PARSE:
            text = _get_response_text(entry)
            container_type: Optional[str] = None
            container_id: Optional[str] = None

            if text:
                # Detect single-resource container
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

                # URL fallback (e.g., Observation/1 from the request path)
                url_container_type, url_container_id = _parse_resource_from_path(route_path, log_row[12] or "")
                fallback_type = container_type or url_container_type
                fallback_id   = container_id   or url_container_id

                existing: Set[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = set()
                if ent_rows:
                    existing = {(r[2], r[5], r[3] or None, r[4] or None, r[6] or None) for r in ent_rows}

                try:
                    extras: List[List[Any]] = []
                    for pid, relation, ref_path, src_type, src_id in extract_patient_ids_from_body(text):
                        stype = (src_type or "").strip()
                        sid   = (src_id  or "").strip()
                        # Fix empty/'Bundle' for single-resource or URL container
                        if not stype or stype == "Bundle":
                            if fallback_type:
                                stype = fallback_type
                            if not sid and fallback_id:
                                sid = fallback_id
                        key = (pid, relation, stype or None, sid or None, ref_path or None)
                        if key in existing:
                            continue
                        extras.append([
                            _normalize_identity_value(log_id),
                            event_ts,
                            pid,
                            stype or "",
                            sid or "",
                            relation,
                            ref_path,
                            0,
                            base_op,
                            request_id
                        ])
                    if extras:
                        ent_rows.extend(extras)
                except Exception as e:
                    if INGEST_DEBUG:
                        log.error("Response body parse failed: %s", e)

        # 4) Insert entity rows
        if ent_rows:
            for r in ent_rows:
                params = list(r)
                params[0] = _normalize_identity_value(params[0])
                cur.execute(INSERT_ENTITY_SQL, params)
            accepted_entities += len(ent_rows)

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

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8082"))
    uvicorn.run("konglog_ingest2:app", host=host, port=port, reload=False)

