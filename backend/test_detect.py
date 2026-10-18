from detect import detect, load_scenario


def rules(name):
    return {a.rule for a in detect(load_scenario(name).events)}


def test_ransomware_fires_expected_rules():
    assert rules("ransomware") == {
        "office_spawns_shell", "c2_beacon", "backup_deletion", "mass_encryption", "smb_auth_burst",
    }


def test_benign_has_no_alerts():
    assert rules("benign") == set()


def test_payments_not_flagged_in_ransomware():
    assert all(a.host != "payments" for a in detect(load_scenario("ransomware").events))


def test_timestamps_normalized_and_sorted():
    ts = [e.ts for e in load_scenario("ransomware").events]
    assert ts == sorted(ts) and all(t.endswith("Z") for t in ts)
