"""Guard client-executed tools before forwarding them in a model stream.

Text is forwarded immediately. Its output check runs after transmission and is
an audit only: it cannot retract text or claim to have prevented a text leak.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from enum import StrEnum
from typing import Any

from qise.proxy.interceptor import ProxyDecision, ProxyInterceptor
from qise.proxy.parser import ParsedRequest, ParsedResponse, ParsedToolCall, ResponseParser, parse_tool_arguments
from qise.proxy.sse import MAX_BUFFER_BYTES, iter_frames

logger = logging.getLogger("qise.proxy.streaming")


class StreamState(StrEnum):
    IDLE = "idle"
    COLLECTING = "collecting"
    CHECK = "check"


class BufferedToolCall:
    def __init__(self, index: int) -> None:
        self.index = index
        self.tool_name = ""
        self.arguments_json = ""
        self.call_id = ""

    @property
    def tool_args(self) -> dict[str, Any]:
        if not self.arguments_json:
            return {}
        return parse_tool_arguments(self.arguments_json)[0]

    def is_complete(self) -> bool:
        return bool(self.tool_name)

    def parsed(self) -> ParsedToolCall:
        args, valid = parse_tool_arguments(self.arguments_json)
        if not self.tool_name or not valid:
            raise ValueError("Upstream returned an incomplete or invalid tool call")
        return ParsedToolCall(tool_name=self.tool_name, tool_args=args, call_id=self.call_id)


def _data_frame(payload: dict[str, Any]) -> bytes:
    return ("data: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode()


class StreamGuard:
    def __init__(
        self,
        interceptor: ProxyInterceptor,
        session_id: str | None = None,
        agent_name: str = "",
        request_context: ParsedRequest | None = None,
    ) -> None:
        self._interceptor = interceptor
        self._session_id = session_id
        self._agent_name = agent_name
        self._request_context = request_context
        self._parser = ResponseParser()
        self._text_chunks: list[str] = []
        self._reasoning: list[str] = []
        self._blocked = False
        self._output_checked = False

    async def _check(
        self, parsed: ParsedResponse, raw_body: dict[str, Any] | None = None, *, audit_only: bool = False
    ) -> ProxyDecision:
        kwargs: dict[str, Any] = {"parsed": parsed, "raw_body": raw_body or {}, "agent_name": self._agent_name}
        if self._request_context is not None:
            kwargs["request_context"] = self._request_context
        if audit_only and isinstance(self._interceptor, ProxyInterceptor):
            kwargs["audit_only"] = True
        return await asyncio.to_thread(self._interceptor.intercept_response, **kwargs)

    def _is_blocked(self, result: ProxyDecision) -> bool:
        config = getattr(self._interceptor, "_config", None)
        return result.action == "block" and (config is None or config.block_on_guard_block)

    async def _post_stream_output_check(self) -> None:
        if self._output_checked:
            return
        self._output_checked = True
        text = "".join(self._text_chunks)
        if text or self._reasoning:
            result = await self._check(
                ParsedResponse(content=text, reasoning="".join(self._reasoning)), audit_only=True
            )
            if result.action in {"warn", "block"}:
                logger.warning(
                    "Stream output audit (text already delivered): %s — %s",
                    result.action,
                    result.block_reason or "; ".join(result.warnings[:3]),
                )

    @staticmethod
    def _sse_error(message: str) -> bytes:
        return (
            "event: error\ndata: " + json.dumps({"error": {"type": "qise_guard_block", "message": message}}) + "\n\n"
        ).encode()


class SSEStreamHandler(StreamGuard):
    """Chat Completions: preserve tool deltas and completion metadata per choice."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._state = StreamState.IDLE
        self._buffered: dict[int, dict[int, BufferedToolCall]] = {}
        self._tool_frames: dict[int, list[dict[str, Any]]] = {}
        self._finished: set[int] = set()
        self._buffer_size = 0

    async def process_stream(self, upstream_resp: Any, session_id: str | None = None) -> AsyncGenerator[bytes, None]:
        self._session_id = session_id or self._session_id
        try:
            async for frame in iter_frames(upstream_resp):
                if frame.data == "[DONE]":
                    if self._buffered:
                        raise ValueError("Upstream ended before completing tool calls")
                    yield frame.encode()
                    await self._post_stream_output_check()
                    return
                if not frame.data:
                    yield frame.encode()
                    continue
                try:
                    chunk = json.loads(frame.data)
                except json.JSONDecodeError:
                    # The client cannot execute an invalid JSON event either.
                    yield frame.encode()
                    continue
                if not isinstance(chunk, dict):
                    raise ValueError("Invalid Chat Completions event")
                async for output in self._process_chunk(chunk, frame.raw):
                    yield output
                if self._blocked:
                    yield b"data: [DONE]\n\n"
                    return
            if self._buffered:
                raise ValueError("Upstream disconnected with unfinished tool calls")
            await self._post_stream_output_check()
        except Exception as exc:
            self._blocked = True
            logger.warning("SSE stream rejected: %s", exc)
            yield self._sse_error(str(exc))
            yield b"data: [DONE]\n\n"

    async def _process_chunk(self, chunk: dict[str, Any], original_line: str) -> AsyncGenerator[bytes, None]:
        choices = chunk.get("choices", [])
        if not choices:
            yield (original_line.rstrip("\n") + "\n\n").encode()
            return
        immediate = []
        finishing = []
        for ordinal, choice in enumerate(choices):
            choice_index = choice.get("index", ordinal)
            delta = choice.get("delta", {})
            finish = choice.get("finish_reason")
            if isinstance(delta.get("content"), str):
                self._text_chunks.append(delta["content"])
            for key in ("reasoning_content", "reasoning", "thinking"):
                if isinstance(delta.get(key), str):
                    self._reasoning.append(delta[key])
            calls = delta.get("tool_calls", [])
            legacy = delta.get("function_call")
            if legacy:
                calls = [*calls, {"index": -1, "function": legacy}]
            if calls:
                if choice_index in self._finished:
                    raise ValueError("Tool data arrived after its choice finished")
                by_index = self._buffered.setdefault(choice_index, {})
                for fragment in calls:
                    index = fragment.get("index", 0)
                    buf = by_index.setdefault(index, BufferedToolCall(index))
                    function = fragment.get("function", {})
                    if function.get("name"):
                        buf.tool_name += function["name"]
                    if isinstance(function.get("arguments"), str):
                        buf.arguments_json += function["arguments"]
                    if fragment.get("id"):
                        buf.call_id = fragment["id"]
                tool_delta = {key: value for key, value in delta.items() if key in {"tool_calls", "function_call"}}
                packet = {**chunk, "choices": [{**choice, "delta": tool_delta, "finish_reason": None}]}
                self._tool_frames.setdefault(choice_index, []).append(packet)
                self._buffer_size += len(json.dumps(packet))
                if self._buffer_size > MAX_BUFFER_BYTES:
                    raise ValueError("Buffered tool calls exceeded the proxy limit")
                self._state = StreamState.COLLECTING
            # Strip executable fields even when a provider combines text and tools.
            safe_delta = {key: value for key, value in delta.items() if key not in {"tool_calls", "function_call"}}
            if finish and choice_index in self._buffered:
                finishing.append((choice_index, choice))
                if safe_delta:
                    immediate.append({**choice, "delta": safe_delta, "finish_reason": None})
            elif safe_delta or finish is not None or not calls:
                immediate.append({**choice, "delta": safe_delta})
        if immediate:
            yield _data_frame({**chunk, "choices": immediate})
        for choice_index, choice in finishing:
            if choice["finish_reason"] not in {"tool_calls", "function_call", "stop"}:
                raise ValueError("Upstream truncated a tool call")
            parsed_calls = [buf.parsed() for buf in self._buffered[choice_index].values()]
            result = await self._check(ParsedResponse(tool_calls=parsed_calls, reasoning="".join(self._reasoning)))
            if self._is_blocked(result):
                self._blocked = True
                yield self._sse_error(result.block_reason or "Tool call blocked")
                return
            for packet in self._tool_frames.pop(choice_index):
                yield _data_frame(packet)
            del self._buffered[choice_index]
            self._finished.add(choice_index)
            # Preserve index, finish_reason, logprobs and outer response metadata.
            yield _data_frame({**chunk, "choices": [{**choice, "delta": {}}]})
        if not self._buffered:
            self._state = StreamState.IDLE
            self._buffer_size = 0


class AnthropicBufferedToolUse:
    def __init__(self, index: int, start_frame: str, content_block: dict[str, Any]) -> None:
        self.index = index
        self.frames = [start_frame]
        self.call_id = str(content_block.get("id") or "")
        self.tool_name = str(content_block.get("name") or "")
        self.initial_input = content_block.get("input", {})
        self.partial_json = ""

    @property
    def tool_args(self) -> dict[str, Any]:
        return parse_tool_arguments(self.partial_json if self.partial_json else self.initial_input)[0]

    def parsed(self) -> ParsedToolCall:
        args, valid = parse_tool_arguments(self.partial_json if self.partial_json else self.initial_input)
        if not self.tool_name or not valid:
            raise ValueError("Upstream returned an incomplete or invalid tool_use")
        return ParsedToolCall(tool_name=self.tool_name, tool_args=args, call_id=self.call_id)


class AnthropicSSEStreamHandler(StreamGuard):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._buffered: dict[int, AnthropicBufferedToolUse] = {}
        self._buffer_size = 0

    async def process_stream(self, upstream_resp: Any, session_id: str | None = None) -> AsyncGenerator[bytes, None]:
        self._session_id = session_id or self._session_id
        try:
            async for frame in iter_frames(upstream_resp):
                async for out in self._process_frame(frame.raw):
                    yield out
                if self._blocked:
                    return
                if frame.event == "message_stop" or (
                    frame.data and json.loads(frame.data).get("type") == "message_stop"
                ):
                    return
            if self._buffered:
                raise ValueError("Upstream disconnected with unfinished tool_use")
            await self._post_stream_output_check()
        except Exception as exc:
            self._blocked = True
            logger.warning("Anthropic SSE stream rejected: %s", exc)
            yield self._anthropic_error_event(str(exc)).encode()

    async def _process_frame(self, raw_frame: str) -> AsyncGenerator[bytes, None]:
        from qise.proxy.sse import parse_frame

        frame = parse_frame(raw_frame)
        if not frame.data:
            yield frame.encode()
            return
        payload = json.loads(frame.data)
        event = frame.event or payload.get("type", "")
        index = payload.get("index", 0)
        if event == "content_block_start":
            block = payload.get("content_block", {})
            if block.get("type") == "tool_use":
                if index in self._buffered:
                    raise ValueError("Duplicate unfinished tool_use block")
                self._buffered[index] = AnthropicBufferedToolUse(index, raw_frame + "\n\n", block)
                return
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                self._text_chunks.append(block["text"])
        elif event == "content_block_delta":
            delta = payload.get("delta", {})
            if index in self._buffered:
                buf = self._buffered[index]
                buf.frames.append(raw_frame + "\n\n")
                self._buffer_size += len(raw_frame)
                if self._buffer_size > MAX_BUFFER_BYTES:
                    raise ValueError("Buffered tool_use exceeded the proxy limit")
                if delta.get("type") == "input_json_delta":
                    buf.partial_json += delta.get("partial_json", "")
                return
            if delta.get("type") == "input_json_delta":
                raise ValueError("Tool arguments arrived without a tool_use start")
            if delta.get("type") == "text_delta":
                self._text_chunks.append(delta.get("text", ""))
            elif delta.get("type") == "thinking_delta":
                self._reasoning.append(delta.get("thinking", ""))
        elif event == "content_block_stop" and index in self._buffered:
            buf = self._buffered.pop(index)
            buf.frames.append(raw_frame + "\n\n")
            result = await self._check(ParsedResponse(tool_calls=[buf.parsed()], reasoning="".join(self._reasoning)))
            if self._is_blocked(result):
                self._blocked = True
                yield self._anthropic_error_event(
                    f"Qise blocked tool call '{buf.tool_name}': {result.block_reason or 'Tool call blocked'}"
                ).encode()
                return
            for saved in buf.frames:
                yield saved.encode()
            return
        elif event == "message_stop":
            if self._buffered:
                raise ValueError("Upstream stopped before completing tool_use")
            yield frame.encode()
            await self._post_stream_output_check()
            return
        yield frame.encode()

    @staticmethod
    def _anthropic_error_event(message: str) -> str:
        return (
            "event: error\ndata: "
            + json.dumps(
                {
                    "type": "error",
                    "error": {
                        "type": "permission_error",
                        "message": message,
                    },
                }
            )
            + "\n\n"
        )
