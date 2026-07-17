from pathlib import Path

from app.services.detection import detect_threats
from app.services.parser import parse_csv_logs


def test_detects_core_threat_categories() -> None:
    content = Path("../../sample-data/auth_network_logs.csv").read_bytes()
    alerts = detect_threats(parse_csv_logs(content))
    categories = {alert.category for alert in alerts}

    assert "failed_login_burst" in categories
    assert "impossible_travel" in categories
    assert "privilege_escalation" in categories
    assert "beaconing" in categories
    assert any(alert.mitre_technique_id.startswith("T") for alert in alerts)

