# asgi.py
try:
    from konglog_ingest2 import app as _app
    app = _app
except Exception as e:
    # Failsafe so uvicorn still starts and shows the error at /healthz
    from fastapi import FastAPI
    app = FastAPI(title="Fallback ASGI")
    @app.get("/healthz")
    def healthz():
        return {"ok": False, "error": str(e)}
