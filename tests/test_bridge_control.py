"""HTTP regressions for local policy writes and redacted UI event evidence."""

from __future__ import annotations

import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from qise.bridge.protocol import GuardCheckResponse, GuardResultSummary
from qise.bridge.server import BridgeServer
from qise.core.config import ShieldConfig
from qise.core.models import GuardContext
from qise.core.shield import Shield
from qise.product.policy import policy_path, set_guard_mode


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    monkeypatch.setenv("QISE_HOME", str(tmp_path / "qise"))
    monkeypatch.delenv("QISE_MODE", raising=False)
    set_guard_mode("command", "enforce")
    return BridgeServer(Shield(ShieldConfig(guards={"enabled": ["command"]})))


def control_app(bridge):
    app = web.Application()
    app.router.add_post("/v1/bridge/guard/mode", bridge._handle_set_guard_mode)
    app.router.add_post("/v1/guard/check", bridge._handle_guard_check)
    app.router.add_get("/v1/bridge/events", bridge._handle_events)
    return app


@pytest.mark.parametrize("origin", ["https://untrusted.example", "null", ""])
@pytest.mark.parametrize("content_type", ["text/plain", "application/json"])
async def test_browser_origin_cannot_change_guard_policy(bridge, origin, content_type):
    original_policy = policy_path().read_bytes()
    async with TestClient(TestServer(control_app(bridge))) as client:
        response = await client.post(
            "/v1/bridge/guard/mode",
            data=json.dumps({"guard_name": "command", "mode": "off"}),
            headers={"Origin": origin, "Content-Type": content_type},
        )
        # Assert the real persisted and in-memory protection before checking the
        # HTTP status: CORS read restrictions alone do not prevent a policy write.
        assert policy_path().read_bytes() == original_policy
        assert bridge._shield.config.guard_mode("command") == "enforce"
        assert response.status == 403
        assert "error" in await response.json()


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"])
async def test_policy_write_rejects_simple_request_content_types(bridge, content_type):
    original_policy = policy_path().read_bytes()
    async with TestClient(TestServer(control_app(bridge))) as client:
        response = await client.post(
            "/v1/bridge/guard/mode",
            data=json.dumps({"guard_name": "command", "mode": "off"}),
            headers={"Content-Type": content_type},
        )
        assert response.status == 415
        assert policy_path().read_bytes() == original_policy
        assert bridge._shield.config.guard_mode("command") == "enforce"


async def test_native_json_policy_write_remains_available(bridge):
    async with TestClient(TestServer(control_app(bridge))) as client:
        response = await client.post(
            "/v1/bridge/guard/mode",
            data=json.dumps({"guard_name": "command", "mode": "off"}),
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        assert response.status == 200
        assert await response.json() == {"ok": True}
        assert json.loads(policy_path().read_text())["modes"]["command"] == "off"
        assert not bridge._shield.check_sync(
            GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"}),
        ).should_block


async def test_ui_event_messages_are_redacted_without_changing_check_evidence(bridge, monkeypatch):
    secret = "sk-" + "testOnlySyntheticSecret" * 3
    message = f"Credential detected: {secret}"
    result = GuardCheckResponse(
        action="warn",
        guard_results=[GuardResultSummary(guard="credential", verdict="warn", message=message)],
    )
    monkeypatch.setattr(bridge, "_run_guard_pipeline", lambda request: result)
    pushed = []
    monkeypatch.setattr(bridge, "_notify_ws_clients", pushed.append)
    async with TestClient(TestServer(control_app(bridge))) as client:
        response = await client.post("/v1/guard/check", json={"type": "response"})
        assert response.status == 200
        assert (await response.json())["guard_results"][0]["message"] == message
        events_response = await client.get("/v1/bridge/events")
        events = await events_response.json()
    assert len(events) == len(pushed) == 1
    assert secret not in events[0]["message"]
    assert events[0] == pushed[0]
    assert events[0]["evidence_kind"] == "finding"
