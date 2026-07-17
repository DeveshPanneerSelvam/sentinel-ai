# sentinelai-threat-detection

ML-powered cybersecurity threat detection MVP with a Next.js dashboard, FastAPI API, PostgreSQL/Supabase-ready persistence, JWT auth, Isolation Forest anomaly detection, MITRE ATT&CK mapping, LLM-backed alert explanations, and PDF incident export.

## Features

- Upload CSV authentication and network logs
- Parse login, privilege, and network telemetry
- Detect failed login bursts, impossible travel, privilege escalation, beaconing, and statistical anomalies
- Score alert risk and map alerts to MITRE ATT&CK techniques
- Explain each alert with OpenAI when `OPENAI_API_KEY` is set, with deterministic local fallback text for demos and tests
- Dashboard for alerts, severity, timeline, investigation notes, and PDF incident reports
- Docker Compose for frontend, backend, and PostgreSQL
- GitHub Actions CI for backend tests and frontend lint/type checks

## Project Structure

```text
apps/
  backend/     FastAPI API, SQLAlchemy models, ML detection engine, tests
  frontend/    Next.js dashboard and upload UI
sample-data/   Demo CSV logs
docs/          Architecture notes
```

## Quick Start

1. Copy environment defaults:

```bash
cp .env.example .env
```

2. Run the full stack:

```bash
docker compose up --build
```

3. Open the dashboard at [http://localhost:3000](http://localhost:3000) and API docs at [http://localhost:8000/docs](http://localhost:8000/docs).

4. Sign up from the UI, upload `sample-data/auth_network_logs.csv`, then review generated alerts and export a PDF.

## Local Backend

```bash
cd apps/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Without `DATABASE_URL`, the backend uses a local SQLite database. For Supabase, set the SQLAlchemy connection string in `DATABASE_URL`, for example:

```bash
export DATABASE_URL="postgresql+psycopg://postgres:<password>@<host>:5432/postgres"
```

## Local Frontend

```bash
cd apps/frontend
npm install
npm run dev
```

## Tests

```bash
cd apps/backend
pytest

cd ../frontend
npm run lint
npm run typecheck
```

## Demo Credentials

Create any user from the dashboard or use the API:

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","password":"sentinel123"}'
```

## API Highlights

- `POST /auth/register`
- `POST /auth/login`
- `POST /logs/upload`
- `GET /alerts`
- `POST /alerts/{alert_id}/notes`
- `GET /reports/{alert_id}/pdf`

## Production Notes

- Replace `JWT_SECRET` with a strong secret from your secret manager.
- Use Supabase/PostgreSQL by setting `DATABASE_URL`.
- Enable OpenAI alert explanations with `OPENAI_API_KEY`.
- Put the FastAPI service behind TLS and restrict CORS origins to your deployed frontend.
- Add object storage for large raw log files; this MVP stores parsed alert metadata in the relational database.

