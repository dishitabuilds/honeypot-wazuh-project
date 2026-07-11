"""
main.py — FastAPI application: REST analytics API, live WebSocket feed, the
dashboard, and the background collectors that tail the honeypots.

Run:  uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations
import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from . import db, report
from .collector import Pipeline
from . import simulate

DB_PATH = os.getenv("DB_PATH", "/data/honeypot.db")
DASH_DIR = Path(__file__).resolve().parent.parent / "dashboard"
REPORT_EVERY = int(os.getenv("REPORT_EVERY_SECONDS", "86400"))


class Hub:
    """Tracks connected dashboards and fans out new events to them."""
    def __init__(self):
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket):
        self._clients.discard(ws)

    async def broadcast(self, event: dict):
        dead = []
        payload = {k: v for k, v in event.items() if k != "raw"}
        for ws in list(self._clients):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


hub = Hub()
pipeline: Pipeline | None = None


async def _periodic_reports():
    while True:
        await asyncio.sleep(REPORT_EVERY)
        try:
            report.write_report()
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline
    db.init(DB_PATH)
    pipeline = Pipeline(hub.broadcast)
    tasks = [
        asyncio.create_task(pipeline.run_cowrie()),
        asyncio.create_task(pipeline.run_dionaea()),
        asyncio.create_task(_periodic_reports()),
    ]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="Honeypot Threat Analytics", lifespan=lifespan)


# ---------- API ----------
@app.get("/api/summary")
async def api_summary():
    return db.summary()


@app.get("/api/events")
async def api_events(limit: int = 120, min_level: int = 0):
    return db.recent_events(limit=limit, min_level=min_level)


@app.get("/api/alerts")
async def api_alerts():
    return db.alerts_by_rule()


@app.get("/api/credentials")
async def api_credentials():
    return db.top_credentials()


@app.get("/api/commands")
async def api_commands():
    return db.top_commands()


@app.get("/api/mitre")
async def api_mitre():
    return db.mitre_breakdown()


@app.get("/api/timeseries")
async def api_timeseries():
    return db.timeseries()


@app.get("/api/ips")
async def api_ips():
    return db.top_ips()


@app.get("/api/geo")
async def api_geo():
    return db.geo_points()


@app.post("/api/simulate")
async def api_simulate(sessions: int = 8):
    if pipeline is None:
        return JSONResponse({"error": "pipeline not ready"}, status_code=503)
    n = await simulate.run(pipeline, sessions=min(max(sessions, 1), 40))
    return {"generated_events": n, "sessions": sessions}


@app.get("/api/report")
async def api_report():
    path = report.write_report()
    return FileResponse(path, media_type="text/html", filename=os.path.basename(path))


@app.get("/api/health")
async def api_health():
    return {"status": "ok"}


# ---------- WebSocket live feed ----------
@app.websocket("/ws")
async def ws(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive; clients don't need to send
    except WebSocketDisconnect:
        hub.disconnect(ws)
    except Exception:
        hub.disconnect(ws)


# ---------- dashboard ----------
@app.get("/", response_class=HTMLResponse)
async def index():
    idx = DASH_DIR / "index.html"
    if idx.exists():
        return HTMLResponse(idx.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard not built</h1>", status_code=404)


if DASH_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASH_DIR)), name="static")
