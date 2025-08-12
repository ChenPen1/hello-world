import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_policy_and_scan(client):
    headers = {"x-api-key": "dev-secret"}
    payload = {
        "name": "default",
        "enabled": True,
        "detectors": ["EMAIL", "CREDIT_CARD"],
        "min_severity": "low",
        "actions": ["log"],
    }
    r = client.post("/policies", json=payload, headers=headers)
    assert r.status_code == 200

    scan = {
        "text": "Contact alice@example.com and cc 4111111111111111",
        "policy_name": "default",
    }
    r = client.post("/scan/text", json=scan, headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert any(f["detector"] == "EMAIL" for f in data)