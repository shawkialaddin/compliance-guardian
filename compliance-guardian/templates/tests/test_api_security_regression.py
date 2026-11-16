"""Example pytest security regression tests for FastAPI/Django style services (adapt to your app)."""
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402  - your application

client = TestClient(app)


def test_cors_does_not_reflect_arbitrary_origin_with_credentials():
    r = client.options("/", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"


def test_object_level_authorization(auth_headers_user_a, resource_of_user_b):
    r = client.get(f"/orders/{resource_of_user_b}", headers=auth_headers_user_a)
    assert r.status_code in (403, 404)


def test_unsigned_jwt_rejected():
    unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    r = client.get("/me", headers={"Authorization": f"Bearer {unsigned}"})
    assert r.status_code == 401
