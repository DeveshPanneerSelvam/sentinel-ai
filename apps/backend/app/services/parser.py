from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO

import pandas as pd


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    event_type: str
    user: str
    source_ip: str
    destination_ip: str | None
    action: str
    status: str
    country: str | None
    latitude: float | None
    longitude: float | None
    privilege: str | None
    bytes_out: float
    raw: dict[str, object]


REQUIRED_COLUMNS = {"timestamp", "event_type", "user", "source_ip", "action", "status"}


def parse_csv_logs(content: bytes) -> list[LogEvent]:
    text = content.decode("utf-8-sig")
    frame = pd.read_csv(StringIO(text)).fillna("")
    missing = REQUIRED_COLUMNS - set(frame.columns)
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise ValueError(f"CSV missing required columns: {missing_list}")

    events: list[LogEvent] = []
    for _, row in frame.iterrows():
        raw = row.to_dict()
        events.append(
            LogEvent(
                timestamp=_parse_timestamp(str(row["timestamp"])),
                event_type=str(row["event_type"]).strip().lower(),
                user=str(row["user"]).strip(),
                source_ip=str(row["source_ip"]).strip(),
                destination_ip=_optional_str(row.get("destination_ip")),
                action=str(row["action"]).strip().lower(),
                status=str(row["status"]).strip().lower(),
                country=_optional_str(row.get("country")),
                latitude=_optional_float(row.get("latitude")),
                longitude=_optional_float(row.get("longitude")),
                privilege=_optional_str(row.get("privilege")),
                bytes_out=_optional_float(row.get("bytes_out")) or 0.0,
                raw=raw,
            )
        )
    return sorted(events, key=lambda event: event.timestamp)


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _optional_str(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _optional_float(value: object) -> float | None:
    try:
        if value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None

