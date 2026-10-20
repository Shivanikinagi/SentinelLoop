"""Phase 2: turn events + alerts into an incident context (grouped timeline + explicit uncertainties)."""
from datetime import datetime

from models import Alert, Asset, Event, Group

GAP_SECONDS = 600  # alerts on one host more than 10 min apart start a new group


def _t(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def group_alerts(alerts: list[Alert]) -> list[Group]:
    groups: list[Group] = []
    for a in sorted(alerts, key=lambda a: (a.host, a.ts)):
        g = groups[-1] if groups else None
        if g and g.host == a.host and (_t(a.ts) - _t(g.end)).total_seconds() <= GAP_SECONDS:
            g.end = a.ts
            g.rules.append(a.rule)
            g.event_ids += a.event_ids
        else:
            groups.append(Group(host=a.host, start=a.ts, end=a.ts, rules=[a.rule], event_ids=list(a.event_ids)))
    return sorted(groups, key=lambda g: g.start)


def uncertainties(assets: list[Asset], events: list[Event], alerts: list[Alert]) -> list[str]:
    seen = {e.host for e in events}
    flagged = {a.host for a in alerts}
    out = []
    for a in assets:
        if a.host not in seen:
            out.append(f"No telemetry for {a.host}: cannot confirm or rule out compromise")
        elif alerts and a.host not in flagged:
            out.append(f"{a.host} ({a.criticality}) has activity but no confirmed malicious indicator")
    for a in alerts:
        if a.rule == "smb_auth_burst":
            out.append(f"Lateral movement unconfirmed: SMB failures on {a.host}, no confirmed compromise of it")
    return out
