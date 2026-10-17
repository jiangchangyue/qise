"""Protocol-level regressions: executable content never bypasses inspection."""

from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace

import pytest
from aiohttp import web

from qise.core.config import ShieldConfig
from qise.core.models import PipelineResult
from qise.proxy.config import ProxyConfig
from qise.proxy.context_injector import ContextInjector
from qise.proxy.interceptor import ProxyDecision, ProxyInterceptor
from qise.proxy.parser import ParsedResponse, RequestParser, ResponseParser
from qise.proxy.responses_streaming import ResponsesSSEStreamHandler
from qise.proxy.server import ProxyServer
from qise.proxy.sse import iter_frames
from qise.proxy.streaming import AnthropicSSEStreamHandler, SSEStreamHandler


class RecordingInterceptor:
    def __init__(self):
        self._config = ProxyConfig()
        self.checks = []
        self.threads = []

    def intercept_response(self, parsed, raw_body, agent_name="", request_context=None):
        self.checks.append(parsed)
        self.threads.append(threading.get_ident())
        if any("rm -rf /" in json.dumps(call.tool_args) for call in parsed.tool_calls):
            return ProxyDecision(action="block", block_reason="Dangerous command")
        return ProxyDecision(action="pass", modified_body=raw_body)


def sse(payload, event=None):
    return (
        (f"event: {event}\n" if event else "") + "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
    ).encode()


async def source(chunks):
    for chunk in chunks:
        yield chunk


async def collect(handler, chunks):
    return b"".join([chunk async for chunk in handler.process_stream(source(chunks))])


def chat_call(command="ls", index=0):
    return {
        "index": index,
        "id": f"call_{index}",
        "type": "function",
        "function": {"name": "bash", "arguments": json.dumps({"command": command})},
    }


def chat_packet(delta, finish=None, index=0):
    return {
        "id": "chatcmpl_1",
        "model": "test",
        "object": "chat.completion.chunk",
        "created": 1,
        "choices": [{"index": index, "delta": delta, "finish_reason": finish}],
    }


def responses_item(command="ls", kind="function_call"):
    return {
        "id": "fc_1",
        "call_id": "call_1",
        "type": kind,
        "name": "bash",
        ("arguments" if kind == "function_call" else "input"): json.dumps({"command": command})
        if kind == "function_call"
        else command,
        "status": "completed",
    }


def responses_chunks(command="ls", kind="function_call"):
    item = responses_item(command, kind)
    key = "arguments" if kind == "function_call" else "input"
    prefix = "response.function_call_arguments" if kind == "function_call" else "response.custom_tool_call_input"
    events = [
        {"type": "response.output_item.added", "output_index": 0, "item": {**item, key: "", "status": "in_progress"}},
        {"type": prefix + ".delta", "output_index": 0, "item_id": "fc_1", "delta": item[key]},
        {"type": prefix + ".done", "output_index": 0, "item_id": "fc_1", key: item[key]},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "output": [item]}},
    ]
    return [sse(event, event["type"]) for event in events]


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["", "Working..."])
@pytest.mark.parametrize("choice_index", [0, 1])
async def test_mixed_text_tool_delta_is_checked_before_tool_is_sent(text, choice_index):
    interceptor = RecordingInterceptor()
    chunks = [
        sse(chat_packet({"content": text, "tool_calls": [chat_call("rm -rf /")]}, index=choice_index)),
        sse(chat_packet({}, "tool_calls", choice_index)),
        b"data: [DONE]\n\n",
    ]
    output = await collect(SSEStreamHandler(interceptor), chunks)
    assert any(check.tool_calls for check in interceptor.checks)
    assert b'"tool_calls": [' not in output
    assert b"event: error" in output
    assert output.count(b"[DONE]") == 1
    assert all(ident != threading.get_ident() for ident in interceptor.threads)


@pytest.mark.asyncio
async def test_all_chat_choices_are_checked_and_finish_metadata_survives():
    interceptor = RecordingInterceptor()
    packet = chat_packet({"tool_calls": [chat_call()]})
    packet["choices"].append({"index": 1, "delta": {"tool_calls": [chat_call("pwd")]}, "finish_reason": None})
    finish = chat_packet({}, "tool_calls")
    finish["choices"].append({"index": 1, "delta": {}, "finish_reason": "tool_calls"})
    output = await collect(SSEStreamHandler(interceptor), [sse(packet), sse(finish), b"data: [DONE]\n\n"])
    frames = [frame async for frame in iter_frames(source([output]))]
    payloads = [json.loads(frame.data) for frame in frames if frame.data != "[DONE]"]
    assert len([check for check in interceptor.checks if check.tool_calls]) == 2
    assert {
        choice["index"]
        for packet in payloads
        for choice in packet["choices"]
        if choice["finish_reason"] == "tool_calls"
    } == {0, 1}
    assert all(packet["id"] == "chatcmpl_1" and packet["model"] == "test" for packet in payloads)
    assert b'"type": "function"' in output


@pytest.mark.asyncio
@pytest.mark.parametrize("end", [[], [b"data: [DONE]\n\n"], [sse(chat_packet({}, "length"))]])
async def test_chat_unfinished_tools_are_not_forwarded(end):
    output = await collect(
        SSEStreamHandler(RecordingInterceptor()), [sse(chat_packet({"tool_calls": [chat_call()]})), *end]
    )
    assert b"event: error" in output
    assert b'"tool_calls": [' not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", ['{"command":', "[]", "null", '"rm -rf /"', ""])
async def test_chat_invalid_arguments_do_not_become_empty_safe_dict(arguments):
    call = chat_call()
    call["function"]["arguments"] = arguments
    interceptor = RecordingInterceptor()
    output = await collect(
        SSEStreamHandler(interceptor),
        [sse(chat_packet({"tool_calls": [call]})), sse(chat_packet({}, "tool_calls")), b"data: [DONE]\n\n"],
    )
    assert b"event: error" in output
    assert b'"tool_calls": [' not in output
    assert interceptor.checks == []


@pytest.mark.asyncio
async def test_text_is_delivered_before_waiting_for_stream_completion():
    interceptor = RecordingInterceptor()
    stream = SSEStreamHandler(interceptor).process_stream(
        source(
            [
                sse(chat_packet({"content": "hello"})),
                b"data: [DONE]\n\n",
            ]
        )
    )
    assert b"hello" in await anext(stream)
    assert interceptor.checks == []
    assert b"[DONE]" in await anext(stream)
    with pytest.raises(StopAsyncIteration):
        await anext(stream)
    assert interceptor.checks[0].content == "hello"


@pytest.mark.asyncio
async def test_chunked_crlf_utf8_is_reassembled_without_corruption():
    packet = sse(chat_packet({"content": "你好"})).replace(b"\n", b"\r\n") + b"data: [DONE]\r\n\r\n"
    output = await collect(SSEStreamHandler(RecordingInterceptor()), [bytes([byte]) for byte in packet])
    assert "你好" in output.decode()
    assert b"event: error" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["function_call", "custom_tool_call"])
@pytest.mark.parametrize("command,blocked", [("ls", False), ("rm -rf /", True)])
async def test_responses_tools_are_buffered_checked_and_keep_original_events(kind, command, blocked):
    interceptor = RecordingInterceptor()
    chunks = responses_chunks(command, kind)
    output = await collect(ResponsesSSEStreamHandler(interceptor), chunks)
    assert len([check for check in interceptor.checks if check.tool_calls]) == 1
    if blocked:
        assert b"event: error" in output
        assert b"response.output_item.added" not in output
        assert b"response.completed" not in output
    else:
        assert output == b"".join(chunks)


@pytest.mark.asyncio
@pytest.mark.parametrize("cut", [1, 2, 3])
async def test_responses_eof_does_not_release_unfinished_call(cut):
    output = await collect(ResponsesSSEStreamHandler(RecordingInterceptor()), responses_chunks()[:cut])
    assert b"event: error" in output
    assert b"response.output_item.added" not in output


@pytest.mark.asyncio
async def test_responses_final_event_cannot_swap_checked_arguments():
    chunks = responses_chunks()
    chunks[-1] = sse(
        {
            "type": "response.completed",
            "response": {
                "status": "completed",
                "output": [responses_item("rm -rf /")],
            },
        }
    )
    output = await collect(ResponsesSSEStreamHandler(RecordingInterceptor()), chunks)
    assert b"event: error" in output
    assert b"response.completed" not in output
    assert b"rm -rf /" not in output


@pytest.mark.asyncio
async def test_responses_final_only_tool_is_checked():
    item = responses_item("rm -rf /")
    output = await collect(
        ResponsesSSEStreamHandler(RecordingInterceptor()),
        [
            sse(
                {
                    "type": "response.completed",
                    "response": {"output": [item]},
                }
            )
        ],
    )
    assert b"event: error" in output
    assert b"rm -rf /" not in output


@pytest.mark.asyncio
async def test_anthropic_partial_tool_input_is_not_forwarded():
    chunks = [
        sse(
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "name": "bash", "id": "t", "input": {}},
            }
        ),
        sse(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"command":'},
            }
        ),
        sse({"type": "content_block_stop", "index": 0}),
    ]
    output = await collect(AnthropicSSEStreamHandler(RecordingInterceptor()), chunks)
    assert b"event: error" in output
    assert b"content_block_start" not in output


def test_response_parser_inspects_every_choice_and_reasoning_content():
    body = {
        "choices": [
            {"message": {"content": "ok"}},
            {
                "message": {
                    "tool_calls": [chat_call("rm -rf /")],
                    "reasoning_content": "visible reasoning",
                }
            },
        ]
    }
    parsed = ResponseParser().parse(body)
    assert parsed.tool_calls[0].tool_args["command"] == "rm -rf /"
    assert parsed.reasoning == "visible reasoning"


def test_responses_parser_and_instructions_injection_preserve_protocol():
    body = {
        "model": "test",
        "instructions": "User instructions",
        "previous_response_id": "resp_old",
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "Hello"}]},
            {"type": "function_call_output", "call_id": "c", "output": "tool output"},
        ],
        "tools": [{"type": "function", "name": "bash", "description": "Run commands", "parameters": {}}],
    }
    original = copy.deepcopy(body)
    parsed = RequestParser().parse_responses(body)
    assert parsed.messages[-1].trust_boundary == "tool_result"
    injector = ContextInjector(SimpleNamespace(render_for_agent=lambda tool: "Security Context"))
    injected = injector.inject_responses(body)
    assert injected["instructions"] == "User instructions\n\nSecurity Context"
    assert injected["previous_response_id"] == "resp_old"
    assert body == original


def fake_shield(ingress=None, egress=None, output=None):
    return SimpleNamespace(
        config=ShieldConfig(),
        pipeline=SimpleNamespace(
            run_ingress=ingress or (lambda *args: PipelineResult()),
            run_egress=egress or (lambda *args: PipelineResult()),
            run_output=output or (lambda *args: PipelineResult()),
        ),
        get_security_context=lambda *args: "Do not delete protected files",
        context_provider=SimpleNamespace(render_for_agent=lambda tool: "Security Context"),
    )


@pytest.mark.parametrize("format", ["openai", "anthropic", "responses"])
def test_isolation_rewrites_only_inspected_text_and_preserves_images(format, tmp_path, monkeypatch):
    monkeypatch.setenv("QISE_HOME", str(tmp_path))
    blocks = [
        {"type": "text", "text": "first"},
        {"type": "image", "source": {"data": "KEEP"}},
        {"type": "text", "text": "second"},
    ]
    if format == "openai":
        body = {"messages": [{"role": "tool", "tool_call_id": "c", "content": blocks}]}
        parser = RequestParser().parse
    elif format == "anthropic":
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "c", "content": blocks},
                    ],
                }
            ]
        }
        parser = RequestParser().parse_anthropic
    else:
        for block in blocks:
            if block["type"] == "text":
                block["type"] = "input_text"
        body = {"input": [{"type": "function_call_output", "call_id": "c", "output": blocks}]}
        parser = RequestParser().parse_responses
    original = copy.deepcopy(body)
    shield = fake_shield(
        ingress=lambda ctx, modes: PipelineResult(
            verdict="warn",
            transformed_args={"content": "[untrusted]\n" + ctx.tool_args["content"]},
        )
    )
    decision = ProxyInterceptor(shield, ProxyConfig()).intercept_request(parser(body), body)
    assert "[untrusted]" in json.dumps(decision.modified_body)
    assert '"data": "KEEP"' in json.dumps(decision.modified_body)
    assert body == original


def test_guard_receives_request_history_and_active_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("QISE_HOME", str(tmp_path))
    captured = []

    def egress(ctx, modes):
        captured.append(ctx)
        return PipelineResult()

    interceptor = ProxyInterceptor(fake_shield(egress=egress), ProxyConfig())
    request = RequestParser().parse(
        {
            "messages": [
                {"role": "user", "content": "Clean temp files"},
                {"role": "assistant", "tool_calls": [chat_call("ls")]},
            ]
        }
    )
    response = ResponseParser().parse({"choices": [{"message": {"tool_calls": [chat_call("pwd")]}}]})
    interceptor.intercept_response(response, {}, request_context=request)
    assert captured[0].session_trajectory[0]["content"] == "Clean temp files"
    assert captured[0].tool_call_history[0].tool_args["command"] == "ls"
    assert captured[0].active_security_rules
    assert captured[0].framework_metadata["history_scope"] == "request_only"


def test_output_audit_does_not_claim_successful_block(tmp_path, monkeypatch):
    monkeypatch.setenv("QISE_HOME", str(tmp_path))
    interceptor = ProxyInterceptor(
        fake_shield(output=lambda *args: PipelineResult(verdict="block", blocked_by="credential"))
    )
    decision = interceptor.intercept_response(ParsedResponse(content="already delivered"), {}, audit_only=True)
    assert decision.action == "warn"
    assert "was not blocked" in decision.warnings[-1]


@pytest.mark.asyncio
async def test_responses_endpoint_runs_guards_instead_of_passthrough(tmp_path, monkeypatch):
    monkeypatch.setenv("QISE_HOME", str(tmp_path))
    server = ProxyServer(
        fake_shield(egress=lambda *args: PipelineResult(verdict="block", blocked_by="command")),
        ProxyConfig(upstream_base_url="https://example.test/v1"),
    )

    class Request:
        method = "POST"
        headers = {}
        match_info = {"path": "v1/responses"}

        async def json(self):
            return {"model": "test", "input": "List files", "tools": [{"type": "function", "name": "bash"}]}

    async def forward(*args, **kwargs):
        return web.json_response({"id": "r", "status": "completed", "output": [responses_item("rm -rf /")]})

    monkeypatch.setattr(server, "_forward_to_upstream", forward)
    response = await server._handle_request(Request())
    assert response.status == 403


@pytest.mark.asyncio
async def test_proxy_health_identifies_service_without_upstream(monkeypatch):
    monkeypatch.setenv("QISE_SERVICE_INSTANCE", "test-instance")
    server = ProxyServer(fake_shield(), ProxyConfig())
    request = SimpleNamespace(method="GET", match_info={"path": "_qise/health"})
    response = await server._handle_request(request)
    body = json.loads(response.text)
    assert body["service"] == "qise-proxy"
    assert body["instance_id"] == "test-instance"
    assert body["pid"] > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("api_format", ["openai", "anthropic", "responses"])
async def test_http_stream_blocks_tools_and_preserves_immediate_text(api_format, tmp_path, monkeypatch):
    from aiohttp.test_utils import TestClient, TestServer

    monkeypatch.setenv("QISE_HOME", str(tmp_path))
    path = {"openai": "/v1/chat/completions", "anthropic": "/v1/messages", "responses": "/v1/responses"}[api_format]
    captured = []
    if api_format == "openai":
        chunks = [
            sse(chat_packet({"content": "Working", "tool_calls": [chat_call("rm -rf /")]})),
            sse(chat_packet({}, "tool_calls")),
            b"data: [DONE]\n\n",
        ]
    elif api_format == "anthropic":
        chunks = [
            sse({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Working"}}),
            sse(
                {
                    "type": "content_block_start",
                    "index": 1,
                    "content_block": {
                        "type": "tool_use",
                        "name": "bash",
                        "id": "call_1",
                        "input": {"command": "rm -rf /"},
                    },
                }
            ),
            sse({"type": "content_block_stop", "index": 1}),
            sse({"type": "message_stop"}),
        ]
    else:
        chunks = [sse({"type": "response.output_text.delta", "delta": "Working"}), *responses_chunks("rm -rf /")]

    async def upstream_handler(request):
        captured.append((request.path, request.query_string, await request.json()))
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        for chunk in chunks:
            await response.write(chunk)
        await response.write_eof()
        return response

    upstream_app = web.Application()
    upstream_app.router.add_post(path, upstream_handler)
    async with TestServer(upstream_app) as upstream:
        proxy = ProxyServer(
            fake_shield(egress=lambda *args: PipelineResult(verdict="block", blocked_by="command")),
            ProxyConfig(upstream_base_url=str(upstream.make_url("/"))),
        )
        proxy_app = web.Application()
        proxy_app.router.add_route("*", "/{path:.*}", proxy._handle_request)
        try:
            async with TestClient(TestServer(proxy_app)) as client:
                body = {"model": "test", "stream": True}
                body["input" if api_format == "responses" else "messages"] = []
                response = await client.post(path + "?client=test", json=body)
                output = await response.text()
                assert response.status == 200
                assert response.headers["X-Qise-Text-Inspection"] == "post-stream-audit"
                assert "Working" in output
                assert "event: error" in output
                assert "rm -rf /" not in output
                assert captured[0][:2] == (path, "client=test")
        finally:
            await proxy.stop()


@pytest.mark.asyncio
async def test_streaming_upstream_error_stays_json(tmp_path, monkeypatch):
    from aiohttp.test_utils import TestClient, TestServer

    monkeypatch.setenv("QISE_HOME", str(tmp_path))

    async def upstream_handler(request):
        return web.json_response({"error": {"message": "rate limited"}}, status=429)

    upstream_app = web.Application()
    upstream_app.router.add_post("/v1/responses", upstream_handler)
    async with TestServer(upstream_app) as upstream:
        proxy = ProxyServer(fake_shield(), ProxyConfig(upstream_base_url=str(upstream.make_url("/"))))
        proxy_app = web.Application()
        proxy_app.router.add_route("*", "/{path:.*}", proxy._handle_request)
        try:
            async with TestClient(TestServer(proxy_app)) as client:
                response = await client.post("/v1/responses", json={"input": "Hello", "stream": True})
                assert response.status == 429
                assert response.content_type == "application/json"
                assert (await response.json())["error"]["message"] == "rate limited"
        finally:
            await proxy.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_responses_background_retrieval_is_inspected(stream, tmp_path, monkeypatch):
    from aiohttp.test_utils import TestClient, TestServer

    monkeypatch.setenv("QISE_HOME", str(tmp_path))

    async def upstream_handler(request):
        assert request.method == "GET"
        assert not await request.read()
        if not stream:
            return web.json_response({"id": "r", "status": "completed", "output": [responses_item("rm -rf /")]})
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        for frame in responses_chunks("rm -rf /"):
            await response.write(frame)
        await response.write_eof()
        return response

    upstream_app = web.Application()
    upstream_app.router.add_get("/v1/responses/resp_1", upstream_handler)
    async with TestServer(upstream_app) as upstream:
        proxy = ProxyServer(
            fake_shield(egress=lambda *args: PipelineResult(verdict="block", blocked_by="command")),
            ProxyConfig(upstream_base_url=str(upstream.make_url("/"))),
        )
        proxy_app = web.Application()
        proxy_app.router.add_route("*", "/{path:.*}", proxy._handle_request)
        try:
            async with TestClient(TestServer(proxy_app)) as client:
                response = await client.get("/v1/responses/resp_1" + ("?stream=true" if stream else ""))
                output = await response.text()
                assert "rm -rf /" not in output
                if stream:
                    assert response.status == 200
                    assert "event: error" in output
                else:
                    assert response.status == 403
        finally:
            await proxy.stop()
