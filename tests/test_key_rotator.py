"""Unit tests for Dynamic API Key Rotation Manager and OpenClaw exclusion."""

import time
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from src.agent.key_rotator import KeyRotationManager
from src.main import app


client = TestClient(app)


def test_key_rotator_round_robin(monkeypatch):
    """Verify keys are rotated in round-robin sequence."""
    test_keys = ["mock_key_AAA", "mock_key_BBB", "mock_key_CCC"]
    rotator = KeyRotationManager(api_keys=test_keys, excluded_suffixes=[])
    
    # Mock genai.Client so network calls aren't made
    monkeypatch.setattr("google.genai.Client", lambda api_key: MagicMock(api_key=api_key))

    c1, k1 = rotator.get_client()
    c2, k2 = rotator.get_client()
    c3, k3 = rotator.get_client()
    c4, k4 = rotator.get_client()

    assert k1 == "mock_key_AAA"
    assert k2 == "mock_key_BBB"
    assert k3 == "mock_key_CCC"
    assert k4 == "mock_key_AAA"  # Loops back around


def test_key_rotator_excludes_openclaw_keys(monkeypatch):
    """Verify keys ending with OpenClaw suffixes are strictly excluded from the pool."""
    test_keys = [
        "AQ.secret_SecLM_key_1111",
        "AQ.openclaw_agent_token_0ujA",
        "AQ.OpenClaw_Agent_token_xqhg",
        "AQ.secret_SecLM_key_2222"
    ]
    rotator = KeyRotationManager(
        api_keys=test_keys,
        excluded_suffixes=["0ujA", "xqhg"]
    )

    assert len(rotator._keys) == 2
    assert "AQ.secret_SecLM_key_1111" in rotator._keys
    assert "AQ.secret_SecLM_key_2222" in rotator._keys
    assert "AQ.openclaw_agent_token_0ujA" not in rotator._keys
    assert "AQ.OpenClaw_Agent_token_xqhg" not in rotator._keys


def test_key_rotator_cooldown_and_failover(monkeypatch):
    """Verify a 429-exhausted key enters cooldown and the next key is used."""
    monkeypatch.setattr("google.genai.Client", lambda api_key: MagicMock(api_key=api_key))
    test_keys = ["key_healthy", "key_to_fail"]
    rotator = KeyRotationManager(api_keys=test_keys, excluded_suffixes=[])

    # Mark key_to_fail with cooldown
    rotator.mark_exhausted("key_to_fail", cooldown_seconds=60.0, reason="429 Resource Exhausted")

    # Next 3 calls should all pick key_healthy
    for _ in range(3):
        _, key = rotator.get_client()
        assert key == "key_healthy"

    # Verify telemetry stats
    stats = rotator.get_stats()
    fail_stat = next(s for s in stats if s["masked_key"] == "...fail")
    assert fail_stat["is_healthy"] is False
    assert fail_stat["cooldown_remaining_sec"] > 0
    assert fail_stat["failed_requests"] == 1


def test_key_rotator_all_cooldown_fallback(monkeypatch):
    """Verify system safely falls back to the earliest expiring key if all keys are in cooldown."""
    monkeypatch.setattr("google.genai.Client", lambda api_key: MagicMock(api_key=api_key))
    test_keys = ["key_expiring_late", "key_expiring_soon"]
    rotator = KeyRotationManager(api_keys=test_keys, excluded_suffixes=[])

    now = time.time()
    rotator._key_metadata["key_expiring_late"]["cooldown_until"] = now + 100.0
    rotator._key_metadata["key_expiring_soon"]["cooldown_until"] = now + 5.0

    _, key = rotator.get_client()
    assert key == "key_expiring_soon"


def test_api_metrics_includes_key_rotation():
    """Verify /api/v1/metrics exposes key_rotation health statistics."""
    resp = client.get("/api/v1/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "key_rotation" in data
    assert isinstance(data["key_rotation"], list)
    assert len(data["key_rotation"]) >= 1
    assert "masked_key" in data["key_rotation"][0]
    assert "is_healthy" in data["key_rotation"][0]
