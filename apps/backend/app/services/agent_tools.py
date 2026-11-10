"""Agent-facing tools for SentinelAI.

These functions hold the logic behind the MCP server (see ``mcp_server.py``).
They take a SQLAlchemy session so they can be unit tested without an MCP client,
and they return plain JSON-serializable dicts that an LLM can read.

Design rules:
- Read tools are always available.
- The one write tool (``add_investigation_note``) is disabled unless
  ``SENTINEL_MCP_ALLOW_WRITES=true`` is set (least privilege by default).
- Every result is capped so an agent can't pull the whole database into context.
"""

from collections import Counter

from sqlalchemy.orm import Session, selectinload

from app.models import Alert, InvestigationNote

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
MAX_LIMIT = 50
MAX_NOTE_LENGTH = 4000


def _alert_summary(alert: Alert) -> dict[str, object]:
    return {
        "id": alert.id,
        "title": alert.title,
        "category": alert.category,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "mitre_technique": f"{alert.mitre_technique_id} {alert.mitre_technique_name}",
        "event_time": alert.event_time.isoformat() if alert.event_time else None,
        "source_file": alert.source_file,
    }


def list_alerts(
    db: Session,
    min_severity: str = "low",
    category: str | None = None,
    limit: int = 20,
) -> dict[str, object]:
    """Return alerts at or above a severity, highest risk first."""
    min_severity = min_severity.lower()
    if min_severity not in SEVERITY_ORDER:
        return {"error": f"min_severity must be one of {SEVERITY_ORDER}"}
    limit = max(1, min(limit, MAX_LIMIT))
    allowed = SEVERITY_ORDER[SEVERITY_ORDER.index(min_severity):]

    query = db.query(Alert).filter(Alert.severity.in_(allowed))
    if category:
        query = query.filter(Alert.category == category)
    alerts = query.order_by(Alert.risk_score.desc()).limit(limit).all()
    return {"count": len(alerts), "alerts": [_alert_summary(a) for a in alerts]}


def get_alert(db: Session, alert_id: int) -> dict[str, object]:
    """Return one alert with its evidence, entities, explanation, and analyst notes."""
    alert = (
        db.query(Alert)
        .options(selectinload(Alert.notes))
        .filter(Alert.id == alert_id)
        .first()
    )
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    return {
        **_alert_summary(alert),
        "explanation": alert.explanation,
        "entities": alert.entities,
        "evidence": alert.evidence,
        "notes": [
            {"id": n.id, "body": n.body, "created_at": n.created_at.isoformat()}
            for n in alert.notes
        ],
    }


def summarize_alerts(db: Session) -> dict[str, object]:
    """Return alert counts by severity and category, plus the top 3 by risk."""
    alerts = db.query(Alert).all()
    top = sorted(alerts, key=lambda a: a.risk_score, reverse=True)[:3]
    return {
        "total": len(alerts),
        "by_severity": dict(Counter(a.severity for a in alerts)),
        "by_category": dict(Counter(a.category for a in alerts)),
        "top_risk": [_alert_summary(a) for a in top],
    }


def add_investigation_note(
    db: Session, alert_id: int, body: str, writes_enabled: bool
) -> dict[str, object]:
    """Attach an analyst note to an alert. Only runs when writes are enabled."""
    if not writes_enabled:
        return {
            "error": "Writes are disabled. Set SENTINEL_MCP_ALLOW_WRITES=true to allow notes."
        }
    body = body.strip()
    if not body:
        return {"error": "Note body is empty"}
    if len(body) > MAX_NOTE_LENGTH:
        return {"error": f"Note is longer than {MAX_NOTE_LENGTH} characters"}
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    note = InvestigationNote(alert_id=alert.id, body=f"[agent] {body}")
    db.add(note)
    db.commit()
    db.refresh(note)
    return {"id": note.id, "alert_id": alert.id, "body": note.body}
