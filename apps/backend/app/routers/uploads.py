from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session, selectinload

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Alert, User
from app.schemas import UploadResult
from app.services.detection import detect_threats
from app.services.parser import parse_csv_logs

router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/upload", response_model=UploadResult)
async def upload_logs(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    file: UploadFile = File(...),
) -> UploadResult:
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV uploads are supported")
    content = await file.read()
    try:
        events = parse_csv_logs(content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    detected = detect_threats(events)
    alerts = [
        Alert(
            title=alert.title,
            category=alert.category,
            severity=alert.severity,
            risk_score=alert.risk_score,
            mitre_technique_id=alert.mitre_technique_id,
            mitre_technique_name=alert.mitre_technique_name,
            explanation=alert.explanation,
            event_time=alert.event_time,
            entities=alert.entities,
            evidence=alert.evidence,
            source_file=file.filename,
        )
        for alert in detected
    ]
    db.add_all(alerts)
    db.commit()
    for alert in alerts:
        db.refresh(alert)

    hydrated = (
        db.query(Alert)
        .options(selectinload(Alert.notes))
        .filter(Alert.id.in_([alert.id for alert in alerts]))
        .all()
        if alerts
        else []
    )
    return UploadResult(parsed_events=len(events), alerts_created=len(alerts), alerts=hydrated)

