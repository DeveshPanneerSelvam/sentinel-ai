from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session, selectinload

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Alert, User
from app.services.reports import render_incident_pdf

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{alert_id}/pdf")
def export_pdf(
    alert_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> Response:
    alert = db.query(Alert).options(selectinload(Alert.notes)).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    pdf = render_incident_pdf(alert)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident-{alert.id}.pdf"'},
    )

