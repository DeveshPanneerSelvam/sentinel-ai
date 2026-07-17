from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from math import asin, cos, radians, sin, sqrt

import numpy as np
from sklearn.ensemble import IsolationForest

from app.services.llm import explain_alert
from app.services.mitre import technique_for
from app.services.parser import LogEvent


@dataclass(frozen=True)
class DetectedAlert:
    title: str
    category: str
    severity: str
    risk_score: float
    mitre_technique_id: str
    mitre_technique_name: str
    explanation: str
    event_time: object
    entities: dict[str, object]
    evidence: dict[str, object]


def detect_threats(events: list[LogEvent]) -> list[DetectedAlert]:
    candidates: list[dict[str, object]] = []
    candidates.extend(_detect_failed_login_bursts(events))
    candidates.extend(_detect_impossible_travel(events))
    candidates.extend(_detect_privilege_escalation(events))
    candidates.extend(_detect_beaconing(events))
    candidates.extend(_detect_ml_anomalies(events))

    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for candidate in candidates:
        key = (
            str(candidate["category"]),
            str(candidate["entities"].get("user") or candidate["entities"].get("source_ip")),
            str(candidate["event_time"]),
        )
        deduped[key] = candidate

    return [_hydrate_alert(candidate) for candidate in deduped.values()]


def _hydrate_alert(candidate: dict[str, object]) -> DetectedAlert:
    technique_id, technique_name = technique_for(str(candidate["category"]))
    candidate["mitre_technique_id"] = technique_id
    candidate["mitre_technique_name"] = technique_name
    candidate["severity"] = _severity(float(candidate["risk_score"]))
    candidate["explanation"] = explain_alert(candidate)
    return DetectedAlert(**candidate)


def _detect_failed_login_bursts(events: list[LogEvent]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    auth_failures = [
        event
        for event in events
        if event.event_type == "auth" and event.action == "login" and event.status == "failed"
    ]
    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in auth_failures:
        grouped[(event.user, event.source_ip)].append(event)

    for (user, source_ip), group in grouped.items():
        group = sorted(group, key=lambda event: event.timestamp)
        for index, start in enumerate(group):
            window = [
                event
                for event in group[index:]
                if event.timestamp - start.timestamp <= timedelta(minutes=10)
            ]
            if len(window) >= 5:
                alerts.append(
                    _candidate(
                        "Failed login burst",
                        "failed_login_burst",
                        min(95, 55 + len(window) * 7),
                        window[-1],
                        {"user": user, "source_ip": source_ip},
                        {"failed_attempts": len(window), "window_minutes": 10},
                    )
                )
                break
    return alerts


def _detect_impossible_travel(events: list[LogEvent]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    successes = [
        event
        for event in events
        if event.event_type == "auth" and event.action == "login" and event.status == "success"
    ]
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for event in successes:
        by_user[event.user].append(event)

    for user, user_events in by_user.items():
        ordered = sorted(user_events, key=lambda event: event.timestamp)
        for previous, current in zip(ordered, ordered[1:]):
            if None in (previous.latitude, previous.longitude, current.latitude, current.longitude):
                continue
            hours = max((current.timestamp - previous.timestamp).total_seconds() / 3600, 0.01)
            distance = _distance_km(
                previous.latitude,
                previous.longitude,
                current.latitude,
                current.longitude,
            )
            speed = distance / hours
            if distance >= 800 and speed >= 900:
                alerts.append(
                    _candidate(
                        "Impossible travel login",
                        "impossible_travel",
                        min(98, 70 + speed / 200),
                        current,
                        {"user": user, "source_ip": current.source_ip},
                        {
                            "from_country": previous.country,
                            "to_country": current.country,
                            "distance_km": round(distance, 1),
                            "hours_between": round(hours, 2),
                            "required_speed_kmh": round(speed, 1),
                        },
                    )
                )
    return alerts


def _detect_privilege_escalation(events: list[LogEvent]) -> list[dict[str, object]]:
    alerts = []
    for event in events:
        privileged = (event.privilege or "").lower() in {"admin", "root", "superuser"}
        action = event.action.lower()
        if event.event_type == "privilege" or "role" in action or "privilege" in action:
            alerts.append(
                _candidate(
                    "Privilege escalation or role change",
                    "privilege_escalation",
                    88 if privileged else 76,
                    event,
                    {"user": event.user, "source_ip": event.source_ip},
                    {"action": event.action, "privilege": event.privilege, "status": event.status},
                )
            )
    return alerts


def _detect_beaconing(events: list[LogEvent]) -> list[dict[str, object]]:
    alerts = []
    network_events = [event for event in events if event.event_type == "network" and event.destination_ip]
    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in network_events:
        grouped[(event.source_ip, event.destination_ip or "")].append(event)

    for (source_ip, destination_ip), group in grouped.items():
        ordered = sorted(group, key=lambda event: event.timestamp)
        if len(ordered) < 5:
            continue
        intervals = [
            (current.timestamp - previous.timestamp).total_seconds()
            for previous, current in zip(ordered, ordered[1:])
        ]
        if intervals and np.std(intervals) <= 15 and 60 <= np.mean(intervals) <= 900:
            alerts.append(
                _candidate(
                    "Periodic outbound beaconing",
                    "beaconing",
                    84,
                    ordered[-1],
                    {"source_ip": source_ip, "destination_ip": destination_ip, "user": ordered[-1].user},
                    {
                        "connection_count": len(ordered),
                        "mean_interval_seconds": round(float(np.mean(intervals)), 1),
                        "interval_stddev_seconds": round(float(np.std(intervals)), 1),
                    },
                )
            )
    return alerts


def _detect_ml_anomalies(events: list[LogEvent]) -> list[dict[str, object]]:
    if len(events) < 8:
        return []

    features = np.array(
        [
            [
                event.timestamp.hour,
                len(event.user),
                1 if event.status == "failed" else 0,
                1 if event.event_type == "network" else 0,
                event.bytes_out,
                float(event.latitude or 0),
                float(event.longitude or 0),
            ]
            for event in events
        ]
    )
    model = IsolationForest(contamination=min(0.25, max(0.05, 2 / len(events))), random_state=42)
    predictions = model.fit_predict(features)
    scores = model.decision_function(features)
    alerts = []
    for event, prediction, score in zip(events, predictions, scores):
        if prediction != -1:
            continue
        risk = min(92, 68 + abs(float(score)) * 100)
        alerts.append(
            _candidate(
                "ML anomaly detected",
                "ml_anomaly",
                risk,
                event,
                {"user": event.user, "source_ip": event.source_ip, "destination_ip": event.destination_ip},
                {
                    "model": "IsolationForest",
                    "anomaly_score": round(float(score), 4),
                    "bytes_out": event.bytes_out,
                    "event_type": event.event_type,
                },
            )
        )
    return alerts[:5]


def _candidate(
    title: str,
    category: str,
    risk_score: float,
    event: LogEvent,
    entities: dict[str, object],
    evidence: dict[str, object],
) -> dict[str, object]:
    return {
        "title": title,
        "category": category,
        "risk_score": round(float(risk_score), 1),
        "event_time": event.timestamp,
        "entities": entities,
        "evidence": evidence,
    }


def _severity(risk_score: float) -> str:
    if risk_score >= 85:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 45:
        return "medium"
    return "low"


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * radius * asin(sqrt(a))

