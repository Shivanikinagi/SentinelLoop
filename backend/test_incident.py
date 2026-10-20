import os, tempfile
os.environ["SENTINEL_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")

from fastapi.testclient import TestClient
from main import app

c = TestClient(app)


def test_ransomware_context_and_persistence():
    inc = c.post("/incidents/load?scenario=ransomware").json()
    assert {g["host"] for g in inc["groups"]} == {"server-a", "server-b"}
    ga = next(g for g in inc["groups"] if g["host"] == "server-a")
    assert set(ga["rules"]) == {"office_spawns_shell", "c2_beacon", "backup_deletion", "mass_encryption"}
    assert any("payments" in u for u in inc["uncertainties"])
    assert any("Lateral movement" in u for u in inc["uncertainties"])
    assert c.get(f"/incidents/{inc['id']}").json() == inc  # round-trips through SQLite


def test_whatif_persists_and_benign_is_quiet():
    c.post("/incidents/load?scenario=ransomware")
    c.patch("/incidents/INC-ransomware/assets/server-b", json={"host": "server-b", "criticality": "critical"})
    got = c.get("/incidents/INC-ransomware").json()
    assert next(a for a in got["assets"] if a["host"] == "server-b")["criticality"] == "critical"
    b = c.post("/incidents/load?scenario=benign").json()
    assert b["groups"] == [] and b["uncertainties"] == []
