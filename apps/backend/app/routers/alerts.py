from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Alert, InvestigationNote, User
from app.schemas import AlertOut, NoteCreate, NoteOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> list[Alert]:
    return (
        db.query(Alert)
        .options(selectinload(Alert.notes))
        .order_by(Alert.created_at.desc())
        .limit(100)
        .all()
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> Alert:
    alert = db.query(Alert).options(selectinload(Alert.notes)).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/notes", response_model=NoteOut, status_code=201)
def add_note(
    alert_id: int,
    payload: NoteCreate,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> InvestigationNote:
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    note = InvestigationNote(alert_id=alert.id, body=payload.body)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

