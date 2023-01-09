import pytest
from fastapi.testclient import TestClient

from ..core.config import settings
from ..main import app


@pytest.fixture(scope="module")
def test_app():
    client = TestClient(app)
    yield client


@pytest.fixture(scope="module")
def user_authentication_headers(test_app: TestClient):
    data = {"username": settings.TEST_USERNAME, "password": settings.TEST_PASSWORD}
    r = test_app.post("/api/token", data=data)
    response = r.json()
    auth_token = response["access_token"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    return headers
