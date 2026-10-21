from typing import Literal
from pydantic import BaseModel

Criticality = Literal["low", "medium", "high", "critical"]


class Event(BaseModel):
    id: str
    ts: str  # ISO-8601 UTC
    host: str
    type: str
    details: dict = {}


class Asset(BaseModel):
    host: str
    criticality: Criticality


class Alert(BaseModel):
    rule: str
    host: str
    severity: Literal["low", "medium", "high"]
    ts: str
    event_ids: list[str]
    summary: str


class Group(BaseModel):
    host: str
    start: str
    end: str
    rules: list[str]
    event_ids: list[str]


class Scenario(BaseModel):
    id: str
    name: str
    assets: list[Asset]
    events: list[Event]
    post_action_events: list[Event] = []  # replayed after containment (Phase 4)
    expected_outcome: dict = {}  # checked by the verifier (Phase 4)


class Incident(BaseModel):
    id: str
    scenario: str
    assets: list[Asset]
    timeline: list[Event]
    alerts: list[Alert]
    groups: list[Group] = []
    uncertainties: list[str] = []


class Decision(BaseModel):
    status: Literal["ok", "unavailable"]
    choice: str | None = None
    alternatives: dict[str, float] = {}  # option -> probability
    confidence: float | None = None
    urgency: float | None = None  # 0-3 on Low..Critical, may be fractional
    urgency_label: str | None = None
    lateral_movement: float | None = None  # Noul P(yes): an uncertain signal, not proof
    reason: str | None = None
