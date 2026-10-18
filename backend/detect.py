"""Phase 1: load a scenario, normalize, run plain-function detection rules."""
import json
from datetime import datetime, timezone
from pathlib import Path

from models import Alert, Event, Scenario

SCENARIOS = Path(__file__).parent.parent / "data" / "scenarios"
OFFICE = {"winword.exe", "excel.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "wscript.exe"}


def _utc(ts: str) -> str:
    d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_scenario(name: str) -> Scenario:
    sc = Scenario(**json.loads((SCENARIOS / f"{name}.json").read_text()))
    norm = lambda e: e.model_copy(update={"ts": _utc(e.ts), "host": e.host.lower()})
    sc.events = sorted(map(norm, sc.events), key=lambda e: e.ts)
    sc.post_action_events = sorted(map(norm, sc.post_action_events), key=lambda e: e.ts)
    for a in sc.assets:
        a.host = a.host.lower()
    return sc


def _a(rule, e, sev, summary):
    return Alert(rule=rule, host=e.host, severity=sev, ts=e.ts, event_ids=[e.id], summary=summary)


def r_mass_encryption(e: Event):
    if e.type == "file_rename_burst" and e.details.get("count", 0) >= 100 and e.details.get("new_ext"):
        return _a("mass_encryption", e, "high", f"{e.details['count']} files renamed to .{e.details['new_ext']}")


def r_office_shell(e: Event):
    if e.type == "process_start" and e.details.get("parent", "").lower() in OFFICE \
            and e.details.get("image", "").lower() in SHELLS:
        return _a("office_spawns_shell", e, "medium", f"{e.details['parent']} spawned {e.details['image']}")


def r_smb_burst(e: Event):
    if e.type == "smb_auth" and e.details.get("failures", 0) >= 10:
        return _a("smb_auth_burst", e, "medium", f"{e.details['failures']} SMB auth failures from {e.details.get('src')}")


def r_beacon(e: Event):
    if e.type == "outbound_conn" and e.details.get("beacon"):
        return _a("c2_beacon", e, "high", f"periodic outbound to {e.details.get('dest')}")


def r_backup_delete(e: Event):
    if e.type == "backup_delete":
        return _a("backup_deletion", e, "high", "backup/shadow copies deleted")


RULES = [r_mass_encryption, r_office_shell, r_smb_burst, r_beacon, r_backup_delete]


def detect(events: list[Event]) -> list[Alert]:
    return [a for e in events for r in RULES if (a := r(e))]
