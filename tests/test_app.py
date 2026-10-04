from fastapi.testclient import TestClient

from sneppx_forge.app import app


def test_health_and_models():
    client = TestClient(app)
    r = client.get("/v1/models")
    assert r.status_code in (200, 401)
