from app.db import SessionLocal
from app.models import Alert
from app.services import agent_tools


def _seed(db) -> list[Alert]:
    alerts = [
        Alert(
            title=title,
            category=category,
            severity=severity,
            risk_score=risk,
            mitre_technique_id="T1110",
            mitre_technique_name="Brute Force",
            explanation="test explanation",
            entities={"user": "alice"},
            evidence={"failures": 12},
            source_file="test.csv",
        )
        for title, category, severity, risk in [
            ("Low noise", "ml_anomaly", "low", 30.0),
            ("Burst", "failed_login_burst", "high", 78.0),
            ("Travel", "impossible_travel", "critical", 92.0),
        ]
    ]
    db.add_all(alerts)
    db.commit()
    return alerts


def test_list_alerts_filters_by_severity_and_sorts_by_risk() -> None:
    with SessionLocal() as db:
        _seed(db)
        result = agent_tools.list_alerts(db, min_severity="high")
    assert result["count"] == 2
    assert [a["title"] for a in result["alerts"]] == ["Travel", "Burst"]


def test_list_alerts_rejects_bad_severity_and_caps_limit() -> None:
    with SessionLocal() as db:
        _seed(db)
        assert "error" in agent_tools.list_alerts(db, min_severity="urgent")
        assert agent_tools.list_alerts(db, limit=10_000)["count"] == 3


def test_get_alert_returns_evidence_or_clear_error() -> None:
    with SessionLocal() as db:
        alert_id = _seed(db)[1].id
        detail = agent_tools.get_alert(db, alert_id)
        missing = agent_tools.get_alert(db, 99_999)
    assert detail["evidence"] == {"failures": 12}
    assert detail["notes"] == []
    assert "error" in missing


def test_summarize_alerts_counts_and_top_risk() -> None:
    with SessionLocal() as db:
        _seed(db)
        summary = agent_tools.summarize_alerts(db)
    assert summary["total"] == 3
    assert summary["by_severity"]["critical"] == 1
    assert summary["top_risk"][0]["title"] == "Travel"


def test_add_note_is_blocked_unless_writes_enabled() -> None:
    with SessionLocal() as db:
        alert_id = _seed(db)[0].id
        blocked = agent_tools.add_investigation_note(db, alert_id, "check VPN", writes_enabled=False)
        assert "error" in blocked
        assert agent_tools.get_alert(db, alert_id)["notes"] == []

        added = agent_tools.add_investigation_note(db, alert_id, "check VPN", writes_enabled=True)
        assert added["body"] == "[agent] check VPN"
        assert len(agent_tools.get_alert(db, alert_id)["notes"]) == 1
