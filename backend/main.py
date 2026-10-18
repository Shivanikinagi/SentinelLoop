"""Phase 0/1 API: load a scenario and return an Incident. Decide/policy/verify endpoints come in later phases."""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from detect import SCENARIOS, detect, load_scenario
from models import Asset, Incident

app = FastAPI(title="SentinelLoop")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

INCIDENTS: dict[str, Incident] = {}  # ponytail: in-memory; SQLite in Phase 2


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
        timeline=sc.events, alerts=detect(sc.events),
    )
    INCIDENTS[inc.id] = inc
    return inc


@app.get("/incidents/{iid}", response_model=Incident)
def get(iid: str):
    if iid not in INCIDENTS:
        raise HTTPException(404, "not loaded")
    return INCIDENTS[iid]


@app.patch("/incidents/{iid}/assets/{host}", response_model=Incident)
def set_criticality(iid: str, host: str, asset: Asset):
    inc = get(iid)
    for a in inc.assets:
        if a.host == host:
            a.criticality = asset.criticality
            return inc
    raise HTTPException(404, "unknown host")
