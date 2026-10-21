"""Phase 3: one Jev request (Choice + Score + Noul) normalized to a Decision. Any failure -> status="unavailable"."""
import os

import httpx

from models import Decision, Incident

URL = "https://jevmodel.org/v1/systemone"
OPTIONS = {
    "isolate_host": "Recommend isolating the suspected affected host.",
    "collect_evidence": "Gather more evidence before containment.",
    "escalate": "Escalate the case for an incident commander's decision.",
}
LEVELS = ["Low", "Moderate", "High", "Critical"]
QUESTIONS = {
    "response": {
        "type": "choice",
        "instructions": "Select the most appropriate next step given the evidence, uncertainty and operational impact.",
        "criteria": OPTIONS,
    },
    "urgency": {
        "type": "score",
        "instructions": "Rate the incident urgency based on observed activity, scope and business impact.",
        "criteria": LEVELS,
    },
    "lateral_movement": {
        "type": "noul",
        "instructions": "Does the provided evidence support the hypothesis that lateral movement is occurring?",
    },
}


def build_payload(inc: Incident) -> dict:
    rules: dict[str, list[str]] = {}
    for a in inc.alerts:
        rules.setdefault(a.host, []).append(a.summary)
    return {
        "model": "jev-latest",
        "state": {
            "incident": inc.id,
            "assets": [{"host": a.host, "criticality": a.criticality, "evidence": rules.get(a.host, [])} for a in inc.assets],
            "uncertainties": inc.uncertainties,
        },
        "questions": QUESTIONS,
    }


def normalize(body: dict) -> Decision:
    a = body["answers"]
    r, u, n = a["response"], a["urgency"], a["lateral_movement"]
    if r["choice"] not in OPTIONS:
        raise ValueError(f"unknown choice {r['choice']}")
    score = float(u["score"])
    return Decision(
        status="ok", choice=r["choice"], alternatives=r["probabilities"], confidence=r.get("confidence"),
        urgency=score, urgency_label=LEVELS[min(max(round(score), 0), len(LEVELS) - 1)],
        lateral_movement=float(n["noul"]),
    )


def decide(inc: Incident, client: httpx.Client | None = None) -> Decision:
    key = os.environ.get("JEVMODEL_API_KEY")
    if not key:
        return Decision(status="unavailable", reason="JEVMODEL_API_KEY not set")
    client = client or httpx.Client(timeout=15)
    err = ""
    for _ in range(2):  # one retry
        try:
            resp = client.post(URL, json=build_payload(inc), headers={"Authorization": f"Bearer {key}"})
            if resp.status_code in (429, 502):
                err = f"HTTP {resp.status_code}"
                continue
            resp.raise_for_status()
            return normalize(resp.json())
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as e:
            err = f"{type(e).__name__}: {e}"
            if not isinstance(e, httpx.TransportError):
                break  # only transport errors are worth retrying
    return Decision(status="unavailable", reason=err)
