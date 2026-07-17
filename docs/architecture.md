# Architecture

SentinelAI is organized around a small number of explicit backend modules:

- `routers/` exposes authenticated API workflows.
- `services/parser.py` normalizes uploaded CSV logs into typed events.
- `services/detection.py` owns all deterministic and ML detection logic.
- `services/mitre.py` centralizes ATT&CK mappings.
- `services/llm.py` explains alerts using OpenAI when configured, otherwise deterministic fallback text.
- `services/reports.py` renders a compact PDF incident report.

The first MVP intentionally uses synchronous SQLAlchemy because the write path is simple and easy to operate. `DATABASE_URL` can point at local PostgreSQL, Supabase, or SQLite for tests.

