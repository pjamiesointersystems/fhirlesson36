FOR the KONG Plugin the endpoint should be

http://127.0.0.1:8082/kong-log

http://127.0.0.1:8080/kong-log


 FHIR Lesson 36 — Logging & Auditing with Kong + InterSystems IRIS for Health

**Goal:** stand up a practical FHIR logging and auditing pipeline that captures request/response metadata at the **API gateway** (Kong), persists to **IRIS for Health**, and derives **patient‑centric “entity” records** from FHIR responses to support HIPAA/GDPR accountability and operational analysis.

> This lab builds on Lesson 35 (Kong API Management). You’ll drive traffic through Kong, verify end‑to‑end logging, and enrich logs with **which Patient IDs were touched** during reads/searches.

---

## Repository at a glance

- `konglog_ingest2.py` — FastAPI receiver for Kong’s HTTP Log plugin. Writes to:
  - `AUDIT.fhir_logs` (request/response metadata)
  - `AUDIT.fhir_entities` (patient IDs touched, derived from responses)
- `challenge1.ipynb` — Smoke testing FHIR logging with Kong (reads/searches).
- `challenge2.ipynb` — Entity extraction & analytics (patient‑centric auditing).
- `fhirrequest.http` — Ready‑to‑run requests for VS Code REST Client / HTTPie.
- `slides/` *(optional)* — Lesson deck (logging requirements, SLOs, lab flow).

---

## Why FHIR logging & auditing?

- Demonstrates **accountability**: who did what, when, from where.
- Enables **security monitoring**, incident investigation, breach timelines.
- Supports patient/regulatory questions (e.g., “Who accessed my data?”).
- Aligns with HIPAA/GDPR expectations for appropriate audit controls and minimal PHI in logs.

---

## Architecture

1. **Kong (Gateway):**
   - Routes FHIR traffic (e.g., `/fhir` → IRIS FHIR service).
   - **HTTP Log** plugin POSTs request/response metadata to the receiver.
   - **Pre‑Function** plugin buffers the FHIR JSON body and attaches it to the log event (base64), enabling patient‑ID extraction without storing PHI long‑term.

2. **Receiver (FastAPI in `konglog_ingest2.py`):**
   - Authenticates incoming logs with a Bearer token.
   - Inserts rows into `AUDIT.fhir_logs`.
   - Optionally parses response bodies to extract **Patient IDs** and writes to `AUDIT.fhir_entities`.

3. **IRIS for Health (DB):**
   - Stores logs and entity rows for SQL & Pandas analytics.
   - Students query via notebooks and build charts (latency, status, entity counts).

---

## Prerequisites

- **InterSystems IRIS for Health** running (container name: `iris-fhir`, namespace `DEMO`), with superserver port `1972` exposed.
- **Kong 3.x** (with Admin API enabled) routing `/fhir` to IRIS.
- Python 3.10+ and either:
  - `uv` (recommended): https://github.com/astral-sh/uv
  - or `pip` / a virtual environment.

---

## Install (Python)

Using **uv**:

```bash
uv venv
source .venv/bin/activate    # or .venv\Scripts\activate on Windows
uv add fastapi uvicorn intersystems-irispython pandas numpy python-dotenv
```

(*If you prefer pip: `pip install fastapi uvicorn intersystems-irispython pandas numpy python-dotenv`.*)

---

## IRIS schema (DDL)

Run these in IRIS (SQL Shell / Portal / notebook):

```sql
-- Logs table
CREATE TABLE AUDIT.fhir_logs (
  log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_ts TIMESTAMP NOT NULL,
  client_ip VARCHAR(64),
  kong_node VARCHAR(64),
  consumer_id VARCHAR(128),
  consumer_username VARCHAR(128),
  credential_type VARCHAR(32),
  auth_subject VARCHAR(256),
  scopes VARCHAR(512),
  method VARCHAR(10) NOT NULL,
  status_code INTEGER NOT NULL,
  service_name VARCHAR(128),
  route_path VARCHAR(512),
  request_path VARCHAR(1024),
  query_string VARCHAR(2048),
  resource_type VARCHAR(64),
  resource_id VARCHAR(128),
  operation VARCHAR(32),
  request_bytes INTEGER,
  response_bytes INTEGER,
  latency_ms INTEGER,
  request_id VARCHAR(128),
  error_reason VARCHAR(256),
  user_agent VARCHAR(256)
);

-- Entity table (patient-centric)
CREATE TABLE AUDIT.fhir_entities (
  entity_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  log_id BIGINT NOT NULL,
  event_ts TIMESTAMP NOT NULL,
  patient_id VARCHAR(128) NOT NULL,
  source_resource_type VARCHAR(64),
  source_resource_id VARCHAR(128),
  relation VARCHAR(32),          -- 'direct' | 'search' | 'reference'
  ref_path VARCHAR(256),         -- JSON path of the reference (if applicable)
  is_direct_target INTEGER,      -- 1 if URL was /Patient/{id}, else 0
  operation VARCHAR(32),         -- read/search/update/etc (copied from log row)
  request_id VARCHAR(128)
);

-- Helpful indexes
CREATE INDEX idx_entities_patient_ts ON AUDIT.fhir_entities(patient_id, event_ts);
CREATE INDEX idx_entities_reqid      ON AUDIT.fhir_entities(request_id);
CREATE INDEX idx_logs_reqid          ON AUDIT.fhir_logs(request_id);
CREATE INDEX idx_logs_ts             ON AUDIT.fhir_logs(event_ts);
```

> **Note:** The app expects `operation` (not `request_operation`) in `AUDIT.fhir_entities`.

---

## Configure Kong

### 1) HTTP Log plugin (route = `main-fhir`)

- **Plugin:** `http-log`
- **Config → http_endpoint:** `http://host.docker.internal:8082/kong-log`
- **Headers:** add `Authorization: Bearer <LOG_BEARER_TOKEN>` (see env below)

### 2) Pre‑Function plugin (same route)

**Body Filter** (already buffers JSON/FHIR; keep your existing version if you have it):

```lua
-- Buffer JSON/FHIR bodies safely for later forwarding (5 MiB cap)
local chunk, eof = ngx.arg[1], ngx.arg[2]
local st = (kong.response.get_status and kong.response.get_status()) or 0
if st < 200 or st >= 300 then return end
local ct = (kong.response.get_header and kong.response.get_header("content-type")) or ""
ct = ct:lower()
if not (ct:find("application/fhir+json", 1, true) or ct:find("application/json", 1, true)) then return end

local buf = kong.ctx.shared.resp_body or ""
local MAX = 5 * 1024 * 1024
if type(chunk) == "string" and #chunk > 0 and #buf < MAX then
  local need = MAX - #buf
  buf = buf .. ((#chunk > need) and string.sub(chunk, 1, need) or chunk)
  kong.ctx.shared.resp_body = buf
end
```

**Log** (serialize in base64 so the receiver decodes reliably):

```lua
local buf = kong.ctx.shared and kong.ctx.shared.resp_body
if buf and #buf > 0 then
  local b64 = ngx.encode_base64(buf)
  local ce  = (kong.response.get_header and kong.response.get_header("content-encoding")) or ""
  local ct  = (kong.response.get_header and kong.response.get_header("content-type")) or ""
  kong.log.set_serialize_value("response_body_b64", b64)
  kong.log.set_serialize_value("resp_content_encoding", ce)
  kong.log.set_serialize_value("resp_content_type", ct)
  kong.log.set_serialize_value("debug_body_len", #buf)
end
```

> Keep your **auth plugin(s)** (e.g., `basic-auth` *or* `key-auth`) attached to the same route. Avoid enabling both on the same route unless you intend to require both.

---

## Run the receiver

### Environment variables

```bash
export IRIS_CONNECTION_STRING="127.0.0.1:1972/DEMO"
export IRIS_USER="_SYSTEM"
export IRIS_PASSWORD="ISCDEMO"
export IRIS_LOG_TABLE="AUDIT.fhir_logs"
export IRIS_ENTITY_TABLE="AUDIT.fhir_entities"
export LOG_BEARER_TOKEN="fhirdemotoken"
export ENABLE_ENTITY_INSERT=1
export ENABLE_RESPONSE_BODY_PARSE=1
export MAX_BODY_BYTES=5242880     # 5 MiB
export KONG_NODE="kong-1"
export INGEST_DEBUG=1
```

### Start

```bash
uv run uvicorn konglog_ingest2:app --host 0.0.0.0 --port 8082
```

Health check:

```bash
curl -s http://localhost:8082/healthz
```

Expected: `{"ok": true}`

---

## Quick test flow

1) **Patient read**  
   `GET http://127.0.0.1:8000/fhir/Patient/4`  
   → 1 row in `AUDIT.fhir_logs` (operation=`read`)  
   → 1 row in `AUDIT.fhir_entities` (`relation='direct'`, `patient_id='4'`)

2) **Observation read** (with `subject.reference=Patient/{id}`)  
   `GET http://127.0.0.1:8000/fhir/Observation/1`  
   → logs row (operation=`read`)  
   → entity row (`relation='reference'`, `source_resource_type='Observation'`)

3) **Patient search**  
   `GET http://127.0.0.1:8000/fhir/Patient?_count=5`  
   → logs row (operation=`search`)  
   → ~5 entity rows (`relation='search'`, one per `entry.resource` Patient)

> If entities don’t appear: confirm the pre‑function **Log** code is present and your log event contains `response_body_b64`.

---

## Notebook snippets

**Pandas connection (example):**
```python
import iris, pandas as pd
conn = iris.connect("127.0.0.1:1972/DEMO", "_SYSTEM", "ISCDEMO")
```

**Recent requests by status:**
```python
df = pd.read_sql("""
  SELECT TOP 200 event_ts, method, status_code, operation, route_path, request_path, latency_ms
  FROM AUDIT.fhir_logs ORDER BY event_ts DESC
""", conn)
df.head()
```

**Which Patients were touched last hour:**
```python
ents = pd.read_sql("""
  SELECT event_ts, patient_id, relation, source_resource_type, source_resource_id, operation
  FROM AUDIT.fhir_entities
  WHERE event_ts >= DATEADD('mi', -60, CURRENT_TIMESTAMP)
  ORDER BY event_ts DESC
""", conn)
ents.head()
```

**Pie chart: Bundles vs. Patient container (from exercise):**
```python
import matplotlib.pyplot as plt
from collections import Counter

rows = pd.read_sql("""
    SELECT patient_id, relation, source_resource_type
    FROM AUDIT.fhir_entities
""", conn)

src_counts = Counter(
    ('Bundle' if r == 'search' else s) for (_, r, s) in rows[["patient_id","relation","source_resource_type"]].itertuples(index=False, name=None)
)

plt.figure()
plt.pie(src_counts.values(), labels=src_counts.keys(), autopct='%1.1f%%')
plt.title('Entity Container Types')
plt.show()
```

---

## Operational tips & guardrails

- **Minimum necessary:** avoid logging PHI content. Use response‑body parsing only to **derive IDs**, and cap body size (5 MiB default).
- **Do not** log secrets/tokens/API keys. Record **credential type** + **subject** identifiers only.
- **Retention & access:** set retention consistent with policy; restrict access and monitor admin actions. Fold logs into your SIEM.
- **Troubleshooting**
  - `SQLCODE -29 Field not found` → schema mismatch; ensure `operation` column exists in `AUDIT.fhir_entities`.
  - `401 Unauthorized` at receiver → wrong/missing `LOG_BEARER_TOKEN` on Kong HTTP Log.
  - Entities missing → ensure pre‑function **Log** code sets `response_body_b64`; receiver has `ENABLE_RESPONSE_BODY_PARSE=1`.
  - `404 Not Found` on `/kong-log` → receiver exposes both `/kong-log` **and** `/kong-log/`.

---

## Optional: Export / import Kong config

If you use **decK**:

```bash
# export
deck dump --all-workspaces --output-file kong.yaml

# import
deck sync --state kong.yaml
```

*(Adjust flags for your decK version; ensure Admin API & RBAC are configured.)*

---

## License & attribution

Course materials © their respective authors. The lab patterns focus on HIPAA/GDPR‑aligned logging, operational SLOs, and audit controls. Use and adapt for instructional purposes within your environment.


