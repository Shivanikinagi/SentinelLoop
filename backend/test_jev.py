import httpx

from detect import detect, load_scenario
from context import uncertainties
from jev import build_payload, decide
from models import Incident

sc = load_scenario("ransomware")
alerts = detect(sc.events)
INC = Incident(id="INC-t", scenario="ransomware", assets=sc.assets, timeline=sc.events, alerts=alerts,
               uncertainties=uncertainties(sc.assets, sc.events, alerts))

# shape taken from the Jev docs, not a live call: replace with a saved real response (Phase 0 fixture)
OK = {"answers": {
    "response": {"type": "choice", "choice": "escalate", "probabilities": {"escalate": 0.7, "isolate_host": 0.2, "collect_evidence": 0.1}, "confidence": 0.7},
    "urgency": {"type": "score", "score": 2.4, "confidence": 0.8},
    "lateral_movement": {"type": "noul", "noul": 0.35}}}


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ok(monkeypatch):
    monkeypatch.setenv("JEVMODEL_API_KEY", "sk-x")
    d = decide(INC, client(lambda r: httpx.Response(200, json=OK)))
    assert (d.status, d.choice, d.urgency_label, d.lateral_movement) == ("ok", "escalate", "High", 0.35)
    assert len(build_payload(INC)["state"]["assets"]) == len(sc.assets)


def test_failures_are_unavailable(monkeypatch):
    monkeypatch.setenv("JEVMODEL_API_KEY", "sk-x")
    calls = []

    def down(r):
        calls.append(1)
        return httpx.Response(502)
    assert decide(INC, client(down)).status == "unavailable" and len(calls) == 2  # retried once
    assert decide(INC, client(lambda r: httpx.Response(200, json={"answers": {}}))).status == "unavailable"  # bad shape
    bad = {"answers": {**OK["answers"], "response": {"choice": "nuke_it", "probabilities": {}}}}
    assert decide(INC, client(lambda r: httpx.Response(200, json=bad))).status == "unavailable"  # off-list choice


def test_no_key(monkeypatch):
    monkeypatch.delenv("JEVMODEL_API_KEY", raising=False)
    assert decide(INC).status == "unavailable"
