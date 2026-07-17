from app.config import get_settings


def explain_alert(alert: dict[str, object]) -> str:
    settings = get_settings()
    if settings.openai_api_key:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=settings.openai_api_key)
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "Explain cybersecurity alerts clearly for a SOC analyst in 2 concise sentences.",
                    },
                    {"role": "user", "content": str(alert)},
                ],
                temperature=0.2,
                max_tokens=140,
            )
            content = response.choices[0].message.content
            if content:
                return content
        except Exception:
            pass

    category = str(alert.get("category", "suspicious activity")).replace("_", " ")
    risk = alert.get("risk_score", "unknown")
    evidence = alert.get("evidence", {})
    return (
        f"This alert is suspicious because it matches {category} behavior with a risk score of {risk}. "
        f"The supporting evidence is {evidence}, which should be reviewed against expected user and host activity."
    )

