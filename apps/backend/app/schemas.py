from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class NoteOut(BaseModel):
    id: int
    body: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    id: int
    title: str
    category: str
    severity: str
    risk_score: float
    mitre_technique_id: str
    mitre_technique_name: str
    explanation: str
    event_time: datetime | None
    entities: dict
    evidence: dict
    source_file: str
    created_at: datetime
    notes: list[NoteOut] = []

    model_config = {"from_attributes": True}


class UploadResult(BaseModel):
    parsed_events: int
    alerts_created: int
    alerts: list[AlertOut]

