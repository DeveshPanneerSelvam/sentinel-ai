import os
import tempfile
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.gettempdir()}/sentinelai-test.db"
os.environ["JWT_SECRET"] = "test-secret"

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_db() -> Generator[None, None, None]:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def token(client: TestClient) -> str:
    response = client.post(
        "/auth/register",
        json={"email": "analyst@example.com", "password": "sentinel123"},
    )
    assert response.status_code == 201
    return response.json()["access_token"]

