from pathlib import Path


def test_upload_logs_creates_alerts_and_pdf(client, token: str) -> None:
    sample = Path("../../sample-data/auth_network_logs.csv")
    with sample.open("rb") as handle:
        response = client.post(
            "/logs/upload",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("auth_network_logs.csv", handle, "text/csv")},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["parsed_events"] >= 10
    assert payload["alerts_created"] >= 4
    alert_id = payload["alerts"][0]["id"]

    note_response = client.post(
        f"/alerts/{alert_id}/notes",
        headers={"Authorization": f"Bearer {token}"},
        json={"body": "Escalated to incident response."},
    )
    assert note_response.status_code == 201

    pdf_response = client.get(
        f"/reports/{alert_id}/pdf",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert pdf_response.content.startswith(b"%PDF")

