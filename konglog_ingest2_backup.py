"""
Kong HTTP Log → IRIS Ingest (Challenge 2)
=========================================

Purpose
-------
A clean receiver that ingests Kong http-log payloads into:
  • AUDIT.fhir_logs (same as Challenge 1)
  • AUDIT.fhir_entities (new) — mapping each event to *all* Patient IDs

How patients are captured
-------------------------
1) Direct target: /Patient/{id} → patient_id={id}, relation="direct", is_direct_target=1
2) Query hints: look at query params (subject=Patient/{id}, patient={id}) → relation="query_subject"/"query_patient"
3) (Optional/Best) From response body via Kong Post/Pre-function:
   - Add this Post-function *log phase* snippet to your route with Basic/Key auth:

     local cjson = require 'cjson.safe'
     local body  = kong.ctx.shared.resp_body  -- set by body_filter chunk collector below
     local ent = { patients = {}, refs = {} }
     if body then
       local t = cjson.decode(body)
       if t and t.resourceType == 'Bundle' and t.entry then
         for _,e in ipairs(t.entry) do
           local r = e.resource
           if r and r.resourceType == 'Patient' and r.id then
             table.insert(ent.patients, r.id)
             table.insert(ent.refs, {resource_type='Patient', resource_id=r.id, patient_id=r.id, relation='search', path='entry[*].resource.id'})
           elseif r and r.resourceType == 'Observation' and r.subject and r.subject.reference then
             local pid = r.subject.reference:match('^Patient/(.+)$')
             if pid then table.insert(ent.patients, pid); table.insert(ent.refs, {resource_type='Observation', resource_id=r.id, patient_id=pid, relation='subject', path='entry[*].resource.subject.reference'}) end
           end
         end
       end
     end
     kong.log.set_serialize_value('fhir_entities', ent)

   - To collect the full body during streaming add the same plugin with a *body_filter* function:

     local chunk, eof = ngx.arg[1], ngx.arg[2]
     local buf = kong.ctx.shared.resp_body or ''
     if chunk then buf = buf .. chunk end
     if eof then kong.ctx.shared.resp_body = buf end

   This stamps an `fhir_entities` object into the log payload which this receiver reads.
   (For privacy, keep this enabled only in lab environments.)

Environment
-----------
IRIS_CONNECTION_STRING : default "127.0.0.1:1972/DEMO"
IRIS_USER              : default "_SYSTEM"
IRIS_PASSWORD          : default "ISCDEMO"
IRIS_LOG_TABLE         : default "AUDIT.fhir_logs"
IRIS_ENTITY_TABLE      : default "AUDIT.fhir_entities"
LOG_BEARER_TOKEN       : default "fhirdemotoken"
KONG_NODE_NAME         : default "kong-1"
FHIR_BASE_PREFIXES     : default "/fhir,/r4,/fhir/r4" (stripped before parsing)
ENABLE_ENTITY_INSERT   : default "true"
ENTITY_MAX_PER_EVENT   : default 10000
INGEST_DEBUG           : default "true"
TS_AS_TEXT             : default "true" (send UTC string timestamps)

Run
---
uv add fastapi "uvicorn[standard]" intersystems-irispython python-dotenv
IRIS_CONNECTION_STRING=127.0.0.1:1972/DEMO \
IRIS_USER=_SYSTEM IRIS_PASSWORD=ISCDEMO \
IRIS_LOG_TABLE=AUDIT.fhir_logs IRIS_ENTITY_TABLE=AUDIT.fhir_entities \
LOG_BEARER_TOKEN=fhirdemotoken \
uv run uvicorn konglog_ingest2:app --host 0.0.0.0 --port 8082
"""

from __future__ import annotations

import os
import re
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set
from urllib.parse import urlencode, parse_qs

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

import iris  # intersystems-irispython

# ---------------------
# Env / Config
# ---------------------
IRIS_CONNECTION_STRING = os.getenv("IRIS_CONNECTION_STRING", "127.0.0.1:1972/DEMO")
IRIS_USER = os.getenv("IRIS_USER", "_SYSTEM")
IRIS_PASSWORD = os.getenv("IRIS_PASSWORD", "ISCDEMO")
IRIS_LOG_TABLE = os.getenv("IRIS_LOG_TABLE", "AUDIT.fhir_logs")
IRIS_ENTITY_TABLE = os.getenv("IRIS_ENTITY_TABLE", "AUDIT.fhir_entities")
LOG_BEARER_TOKEN = os.getenv("LOG_BEARER_TOKEN", "fhirdemotoken")
KONG_NODE_NAME = os.getenv("KONG_NODE_NAME", "kong-1")
FHIR_BASE_PREFIXES = os.getenv("FHIR_BASE_PREFIXES", "/fhir,/r4,/fhir/r4")
ENABLE_ENTITY_INSERT = os.getenv("ENABLE_ENTITY_INSERT", "true").lower() in {"1","true","yes"}
ENTITY_MAX_PER_EVENT = int(os.getenv("ENTITY_MAX_PER_EVENT", "10000"))
INGEST_DEBUG = os.getenv("INGEST_DEBUG", "true").lower() in {"1","true","yes"}
TS_AS_TEXT = os.getenv("TS_AS_TEXT", "true").lower() in {"1","true","yes"}
ENABLE_RESPONSE_BODY_PARSE = os.getenv("ENABLE_RESPONSE_BODY_PARSE", "true").lower() in {"1","true","yes"}
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "5242880"))  # 256 KiB default (match plugin cap)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("konglog-ingest2")

# ---------------------
# IRIS connection (global)
# ---------------------
_conn_lock = threading.Lock()
_conn: Optional[iris.IRISConnection] = None

def _connect() -> iris.IRISConnection:
    global _conn
    with _conn_lock:
        if _conn is not None:
            try:
                c = _conn.cursor(); c.execute("SELECT 1"); c.fetchall()
                return _conn
            except Exception:
                try: _conn.close()
                except Exception: pass
                _conn = None
        _conn = iris.connect(IRIS_CONNECTION_STRING, IRIS_USER, IRIS_PASSWORD)
        try:
            _conn.autocommit = True  # type: ignore[attr-defined]
        except Exception:
            pass
        return _conn

# ---------------------
# SQL
# ---------------------
INSERT_LOG_SQL = f"""
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

INSERT_ENTITY_SQL = f"""
INSERT INTO {IRIS_ENTITY_TABLE} (
  log_id, event_ts, patient_id, source_resource_type, source_resource_id,
  relation, ref_path, is_direct_target, operation, request_id
) VALUES (
  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
"""

# ---------------------
# Helpers
# ---------------------

def extract_patient_ids_from_body(body: str) -> List[Tuple[str, str, str, Optional[str], Optional[str]]]:
    """
    Parse a (trimmed) FHIR JSON response body and return tuples:
      (patient_id, relation, ref_path, source_type, source_id)

    - relation: 'search' if Patient in Bundle entries; 'reference' for Patient/ID refs
    - ref_path: minimal context for audit
    """
    out: List[Tuple[str, str, str, Optional[str], Optional[str]]] = []
    if not body:
        return out
    s = body[:MAX_BODY_BYTES].replace("\\/", "/")

    seen: set = set()

    # 1) Bundle entries where resourceType: Patient and id: <pid> (order-insensitive within a single object)
    # Simple approach: find Patient resource objects, then their id fields within that block
    for block in re.finditer(r'"resource"\s*:\s*{(.*?)}', s, flags=re.DOTALL):
        obj = block.group(1)
        if re.search(r'"resourceType"\s*:\s*"Patient"', obj):
            m_id = re.search(r'"id"\s*:\s*"([^"]+)"', obj)
            if m_id:
                pid = m_id.group(1)
                key = ("search", pid, "entry.resource")
                if key not in seen:
                    seen.add(key)
                    out.append((pid, "search", "entry.resource", "Patient", pid))

        # References inside other resources (e.g., Observation.subject.reference)
        for m in re.finditer(r'"reference"\s*:\s*"Patient/([^"]+)"', obj):
            pid = m.group(1)
            key = ("reference", pid, "reference")
            if key not in seen:
                seen.add(key)
                out.append((pid, "reference", "reference", None, None))

    # 2) Bundle fullUrl fallback (…/Patient/{id})
    for m in re.finditer(r'"fullUrl"\s*:\s*"[^"]*/Patient/([^"]+)"', s):
        pid = m.group(1)
        key = ("search", pid, "entry.fullUrl")
        if key not in seen:
            seen.add(key)
            out.append((pid, "search", "entry.fullUrl", "Patient", pid))

    # 3) Generic references anywhere else
    for m in re.finditer(r'"reference"\s*:\s*"Patient/([^"]+)"', s):
        pid = m.group(1)
        key = ("reference", pid, "reference")
        if key not in seen:
            seen.add(key)
            out.append((pid, "reference", "reference", None, None))

    return out



def _epoch_ms_to_ts(ms: Optional[int]) -> datetime:
    if ms is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _ts_for_db(dt: datetime) -> Any:
    if TS_AS_TEXT:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _qs_to_string(qs_obj: Any) -> str:
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


def _truncate(s: Optional[str], limit: int) -> Optional[str]:
    if s is None: return None
    return s if len(s) <= limit else s[:limit]


def _get_first(d: Dict[str, Any], key: str) -> Optional[str]:
    v = d.get(key)
    if isinstance(v, list) and v: return str(v[0])
    if v is None: return None
    return str(v)


def _strip_base_prefix(path: Optional[str], route_path: Optional[str]) -> Optional[str]:
    if not path: return path
    p = path
    try:
        if route_path and p.startswith(route_path):
            p = p[len(route_path):] or "/"
        for pref in [x.strip() for x in FHIR_BASE_PREFIXES.split(',') if x.strip()]:
            if p.startswith(pref):
                p = p[len(pref):] or "/"
                break
        if not p.startswith('/'): p = '/' + p
        return p
    except Exception:
        return path


def _parse_fhir_path(path: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not path: return None, None, None
    try:
        p = path.split('?')[0].strip()
        if not p.startswith('/'): p = '/' + p
        parts = [x for x in p.split('/') if x]
        if not parts: return None, None, None
        if parts[0].startswith('$'): return None, None, parts[0]
        rtype = parts[0]; rid = None; op = None
        if len(parts) > 1:
            if parts[1].startswith('$'): op = parts[1]
            elif parts[1] == '_history': op = 'history'
            else:
                rid = parts[1]
                if len(parts) > 2:
                    if parts[2].startswith('$'): op = parts[2]
                    elif parts[2] == '_history': op = 'history'
        if op is None and rid is None and ('?' in path): op = 'search'
        return rtype, rid, op
    except Exception:
        return None, None, None


def _parse_query_for_patient_ids(qs_str: str) -> List[Tuple[str,str,str]]:
    """Return list of (patient_id, relation, ref_path) from query params.
       Supports subject=Patient/{id}, patient={id}, and repeats.
    """
    out: List[Tuple[str,str,str]] = []
    if not qs_str: return out
    q = parse_qs(qs_str, keep_blank_values=False)
    # subject references
    for subj in q.get('subject', []):
        if subj.startswith('Patient/'): out.append((subj.split('/',1)[1], 'query_subject', 'subject'))
    # patient param (id only)
    for pid in q.get('patient', []):
        if pid: out.append((pid, 'query_patient', 'patient'))
    return out

# ---------------------
# Mapping functions
# ---------------------

def map_entry_to_log_row(entry: Dict[str, Any]) -> List[Any]:
    req = entry.get('request', {}) or {}
    resp = entry.get('response', {}) or {}
    route = entry.get('route', {}) or {}
    service = entry.get('service', {}) or {}
    consumer = entry.get('consumer', {}) or entry.get('authenticated_entity', {}) or {}

    req_headers = req.get('headers', {}) or {}
    resp_headers = resp.get('headers', {}) or {}

    event_ts_dt = _epoch_ms_to_ts(entry.get('started_at'))
    event_ts = _ts_for_db(event_ts_dt)

    client_ip = entry.get('client_ip')
    kong_node = KONG_NODE_NAME

    consumer_id = consumer.get('id') or _get_first(req_headers, 'x-consumer-id')
    consumer_username = consumer.get('username') or _get_first(req_headers, 'x-consumer-username')
    consumer_username = _truncate(consumer_username, 128) if consumer_username else None

    # Prefer stamped auth values if present
    auth_extra = entry.get('auth') or {}
    credential_type = auth_extra.get('scheme')
    auth_subject = auth_extra.get('subject')
    if not credential_type:
        # header-based inference fallback
        auth = req_headers.get('authorization') or req_headers.get('Authorization')
        if isinstance(auth, list): auth = auth[0]
        if isinstance(auth, str):
            low = auth.lower()
            if low.startswith('bearer '): credential_type = 'oauth2'
            elif low.startswith('basic '): credential_type = 'basic'
        if req_headers.get('x-api-key') or req_headers.get('apikey'):
            credential_type = credential_type or 'apikey'
    if not auth_subject:
        auth_subject = (
            req_headers.get('x-authenticated-userid')
            or req_headers.get('x-credential-identifier')
            or req_headers.get('x-consumer-custom-id')
            or req_headers.get('x-consumer-username')
        )

    scopes = (
        req_headers.get('x-authenticated-scope')
        or req_headers.get('x-authenticated-scopes')
        or req_headers.get('scope')
        or req_headers.get('scopes')
    )

    method = req.get('method')
    status_code = resp.get('status')

    service_name = _truncate(service.get('name'), 128) if service.get('name') else None
    route_paths = route.get('paths') or []
    route_path = route_paths[0] if route_paths else None
    route_path = _truncate(route_path, 512) if route_path else None

    request_path = _truncate(req.get('uri'), 1024)
    query_string = _truncate(_qs_to_string(req.get('querystring')) or '', 2048)

    fhir_obj = entry.get('fhir', {}) or {}
    resource_type = fhir_obj.get('resource_type')
    resource_id = fhir_obj.get('resource_id')
    operation = fhir_obj.get('operation')

    if resource_type is None and resource_id is None and operation is None:
        effective_path = _strip_base_prefix(request_path, route_path)
        rt, rid, op = _parse_fhir_path(effective_path)
        resource_type, resource_id, operation = rt, rid, op
        if method == 'GET' and resource_type and not rid and not (op and op.startswith('$')):
            operation = operation or 'search'

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
        
    request_bytes = req.get('size')
    response_bytes = resp.get('size')
    latency_ms = (entry.get('latencies') or {}).get('request')

    request_id = _get_first(req, 'id') or _get_first(resp_headers, 'x-kong-request-id')
    request_id = _truncate(request_id, 128) if request_id else None

    error_reason = None
    try:
        st = int(status_code) if status_code is not None else None
        if st and st >= 400:
            error_reason = (
                _get_first(resp_headers, 'x-kong-upstream-status')
                or _get_first(resp_headers, 'x-kong-balancer-retries')
            )
            if not error_reason:
                if st == 401:
                    if credential_type == 'apikey': error_reason = 'invalid_api_key'
                    elif credential_type == 'oauth2': error_reason = 'invalid_token'
                    elif credential_type == 'basic': error_reason = 'invalid_basic_credentials'
                    else: error_reason = 'invalid_auth_credentials'
                elif st == 403: error_reason = 'forbidden'
                elif st == 404: error_reason = 'not_found'
                elif st == 405: error_reason = 'method_not_allowed'
                elif st == 409: error_reason = 'conflict'
                elif st == 413: error_reason = 'payload_too_large'
                elif st == 415: error_reason = 'unsupported_media_type'
                elif st == 422: error_reason = 'unprocessable_entity'
                elif st == 429: error_reason = 'rate_limited'
                elif 500 <= st <= 599: error_reason = 'upstream_error'
                else: error_reason = f'http_{st}'
    except Exception:
        pass

    user_agent = _get_first(req_headers, 'user-agent')
    user_agent = _truncate(user_agent, 256) if user_agent else None

    return [
        _ts_for_db(event_ts_dt), client_ip, kong_node, consumer_id, consumer_username,
        credential_type, auth_subject, scopes, method, status_code,
        service_name, route_path, request_path, query_string, resource_type,
        resource_id, operation, request_bytes, response_bytes, latency_ms,
        request_id, error_reason, user_agent,
    ]


def build_entity_rows(entry: Dict[str, Any], log_id: int, event_ts: Any, base_op: Optional[str], request_id: Optional[str], route_path: Optional[str]) -> List[List[Any]]:
    rows: List[List[Any]] = []
    added: Set[Tuple[str,str,str,str]] = set()  # (patient_id, relation, src_type, src_id)

    # Base request context
    req = entry.get('request', {}) or {}
    method = req.get('method')
    request_path = req.get('uri')
    effective_path = _strip_base_prefix(request_path, route_path)
    rt, rid, op = _parse_fhir_path(effective_path)

    # 1) Direct Patient read
    if rt == 'Patient' and rid:
        key = (rid, 'direct', 'Patient', rid)
        if key not in added:
            rows.append([log_id, event_ts, rid, 'Patient', rid, 'direct', 'path', 1, op or base_op, request_id])
            added.add(key)

    # 2) Query hints (?subject=Patient/{id}, ?patient=123)
    qstr = _qs_to_string(req.get('querystring'))
    for pid, rel, refp in _parse_query_for_patient_ids(qstr):
        key = (pid, rel, rt or '', rid or '')
        if key not in added:
            rows.append([log_id, event_ts, pid, rt or 'Bundle', rid, rel, refp, 0, op or base_op, request_id])
            added.add(key)

    # 3) Entities stamped by Kong (preferred)
    ents = entry.get('fhir_entities') or entry.get('entities') or {}
    patients = ents.get('patients') if isinstance(ents, dict) else None
    refs = ents.get('refs') if isinstance(ents, dict) else None

    if isinstance(patients, list):
        for pid in patients[:ENTITY_MAX_PER_EVENT]:
            pid_s = str(pid)
            key = (pid_s, 'search' if (method == 'GET' and rt == 'Patient' and not rid) else 'derived', rt or 'Bundle', rid or '')
            if key not in added:
                rows.append([log_id, event_ts, pid_s, rt or 'Bundle', rid, key[1], 'response', 0, op or base_op, request_id])
                added.add(key)

    if isinstance(refs, list):
        for r in refs[:ENTITY_MAX_PER_EVENT]:
            pid = str(r.get('patient_id')) if r.get('patient_id') is not None else None
            if not pid: continue
            rtype = r.get('resource_type') or rt or 'Bundle'
            rid2 = r.get('resource_id')
            rel = r.get('relation') or 'reference'
            refp = r.get('path') or 'response'
            key = (pid, rel, rtype, str(rid2) if rid2 else '')
            if key not in added:
                rows.append([log_id, event_ts, pid, rtype, rid2, rel, refp, 0, op or base_op, request_id])
                added.add(key)

    return rows

# ---------------------
# FastAPI
# ---------------------
app = FastAPI(title="Kong HTTP Log → IRIS Ingest (Challenge 2)")

@app.get('/healthz')
async def healthz():
    try:
        conn = _connect(); cur = conn.cursor(); cur.execute("SELECT 1"); cur.fetchall()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

@app.post('/kong-log')
async def kong_log(request: Request):
    # Token
    if LOG_BEARER_TOKEN:
        auth = request.headers.get('authorization') or request.headers.get('Authorization')
        if not auth or not auth.startswith('Bearer ') or auth.split(' ',1)[1] != LOG_BEARER_TOKEN:
            raise HTTPException(status_code=401, detail='invalid token')

    raw = await request.body()
    try:
        payload = json.loads(raw.decode('utf-8'))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail='invalid json')

    entries: Iterable[Dict[str, Any]]
    if isinstance(payload, dict):
        entries = [payload]
    elif isinstance(payload, list):
        entries = payload
    else:
        raise HTTPException(status_code=400, detail='unexpected payload type')

    conn = _connect(); cur = conn.cursor()

    accepted_logs = 0
    accepted_entities = 0

    for entry in entries:
        # 1) Insert log row
        log_row = map_entry_to_log_row(entry)
        try:
            cur.execute(INSERT_LOG_SQL, list(log_row))
            # Retrieve generated log_id (IRIS supports LAST_IDENTITY() on table)
            cur.execute(f"SELECT MAX(log_id) FROM {IRIS_LOG_TABLE}")
            log_id = cur.fetchall()[0][0]
            accepted_logs += 1
        except Exception as e:
            if INGEST_DEBUG:
                log.error("Log insert failed: %s | row=%s", e, log_row)
            continue  # skip entities for this entry

        # 2) Insert entity rows
        if ENABLE_ENTITY_INSERT:
            event_ts = log_row[0]
            request_id = log_row[20]
            route_path = log_row[11]
            base_op = log_row[16]
            try:
                ent_rows = build_entity_rows(entry, log_id, event_ts, base_op, request_id, route_path)
                if ent_rows:
                    cur.executemany(INSERT_ENTITY_SQL, ent_rows)
                    accepted_entities += len(ent_rows)
            except Exception as e:
                if INGEST_DEBUG:
                    log.error("Entity insert failed: %s | rows=%s", e, ent_rows)
                # continue; do not fail the whole batch

    try:
        conn.commit()
    except Exception:
        pass

    return {"accepted_logs": accepted_logs, "accepted_entities": accepted_entities}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('konglog_ingest2:app', host='0.0.0.0', port=8082)
