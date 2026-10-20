"""Phase 0-2 API: load a scenario and return an Incident. Decide/policy/verify endpoints come in later phases."""
import os
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from context import group_alerts, uncertainties
from detect import SCENARIOS, detect, load_scenario
from models import Asset, Incident

app = FastAPI(title="SentinelLoop")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

DB = os.environ.get("SENTINEL_DB", str(Path(__file__).parent / "sentinel.db"))


def _db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
    return c


def save(inc: Incident):
    with _db() as c:  # ponytail: connection per call, pool if throughput matters
        c.execute("INSERT OR REPLACE INTO incidents VALUES (?, ?)", (inc.id, inc.model_dump_json()))


@app.get("/scenarios")
def scenarios():
    return sorted(p.stem for p in SCENARIOS.glob("*.json"))


@app.post("/incidents/load", response_model=Incident)
def load(scenario: str = "ransomware"):
    if scenario not in scenarios():
        raise HTTPException(404, "unknown scenario")
    sc = load_scenario(scenario)
    inc = Incident(
        id=f"INC-{scenario}", scenario=scenario, assets=sc.assets,
        timeline=sc.events, alerts=(alerts := detect(sc.events)),
        groups=group_alerts(alerts), uncertainties=uncertainties(sc.assets, sc.events, alerts),
    )
    save(inc)
    return inc


@app.get("/incidents/{iid}", response_model=Incident)
def get(iid: str):
    with _db() as c:
        row = c.execute("SELECT body FROM incidents WHERE id=?", (iid,)).fetchone()
    if not row:
        raise HTTPException(404, "not loaded")
    return Incident.model_validate_json(row[0])


@app.patch("/incidents/{iid}/assets/{host}", response_model=Incident)
def set_criticality(iid: str, host: str, asset: Asset):
    inc = get(iid)
    for a in inc.assets:
        if a.host == host:
            a.criticality = asset.criticality
            save(inc)
            return inc
    raise HTTPException(404, "unknown host")
