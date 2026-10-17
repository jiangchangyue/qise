"""Responses API SSE checks for client-executed function and custom tools.

The typed event sequence follows the OpenAI function-calling streaming guide:
https://developers.openai.com/api/docs/guides/function-calling#streaming
Hosted tools execute upstream and are not execution gates in this proxy.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Any

from qise.proxy.parser import ParsedResponse, responses_tool_call
from qise.proxy.sse import MAX_BUFFER_BYTES, SSEFrame, iter_frames
from qise.proxy.streaming import StreamGuard

_TOOL_TYPES = {"function_call", "custom_tool_call"}
_ARGUMENT_EVENTS = {
    "response.function_call_arguments.delta",
    "response.function_call_arguments.done",
    "response.custom_tool_call_input.delta",
    "response.custom_tool_call_input.done",
}


@dataclass
class BufferedResponseTool:
    item: dict[str, Any]
    frames: list[bytes] = field(default_factory=list)
    fragments: str = ""
    final_input: str | None = None

    @property
    def input_key(self) -> str:
        return "arguments" if self.item["type"] == "function_call" else "input"

    def complete(self, final: dict[str, Any]) -> dict[str, Any]:
        for key in ("id", "type", "call_id", "name"):
            if self.item.get(key) != final.get(key):
                raise ValueError("Tool identity changed during the response stream")
        value = final.get(self.input_key)

        # JSON strings may differ only in whitespace; compare their decoded forms.
        def equivalent(left: Any, right: Any) -> bool:
            if self.input_key == "arguments":
                try:
                    return json.loads(left) == json.loads(right)
                except (TypeError, ValueError):
                    return False
            return left == right

        for observed in (self.fragments or self.item.get(self.input_key), self.final_input):
            if observed and not equivalent(observed, value):
                raise ValueError("Tool arguments changed during the response stream")
        return final


class ResponsesSSEStreamHandler(StreamGuard):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._buffered: dict[int, BufferedResponseTool] = {}
        self._checked: dict[str, str] = {}
        self._buffer_size = 0
        self._complete = False

    async def process_stream(self, upstream_resp: Any, session_id: str | None = None) -> AsyncGenerator[bytes, None]:
        self._session_id = session_id or self._session_id
        try:
            async for frame in iter_frames(upstream_resp):
                async for output in self._process_frame(frame):
                    yield output
                if self._blocked or self._complete:
                    return
            raise ValueError("Upstream disconnected before the response completed")
        except Exception as exc:
            self._blocked = True
            payload = {"type": "error", "code": "qise_stream_rejected", "message": str(exc), "param": None}
            yield ("event: error\ndata: " + json.dumps(payload) + "\n\n").encode()

    def _save(self, buf: BufferedResponseTool, frame: SSEFrame) -> None:
        encoded = frame.encode()
        self._buffer_size += len(encoded)
        if self._buffer_size > MAX_BUFFER_BYTES:
            raise ValueError("Buffered Responses tools exceeded the proxy limit")
        buf.frames.append(encoded)

    async def _check_item(self, item: dict[str, Any]) -> None:
        call = responses_tool_call(item)
        if call is None:
            return
        if not call.tool_name or not call.arguments_valid or item.get("status") == "incomplete":
            raise ValueError("Upstream returned an incomplete or invalid tool call")
        key = str(item.get("id") or call.call_id)
        fingerprint = json.dumps(call.model_dump(), sort_keys=True)
        if key in self._checked:
            if self._checked[key] != fingerprint:
                raise ValueError("Completed tool call changed during the response stream")
            return
        result = await self._check(ParsedResponse(tool_calls=[call], reasoning="".join(self._reasoning)))
        if self._is_blocked(result):
            raise ValueError(result.block_reason or "Tool call blocked")
        self._checked[key] = fingerprint

    async def _process_frame(self, frame: SSEFrame) -> AsyncGenerator[bytes, None]:
        if not frame.data:
            yield frame.encode()
            return
        if frame.data == "[DONE]":
            raise ValueError("Response ended without a completed response event")
        payload = json.loads(frame.data)
        event = payload.get("type", frame.event)
        index = payload.get("output_index")
        item = payload.get("item", {})
        if event == "response.output_item.added" and item.get("type") in _TOOL_TYPES:
            if not isinstance(index, int) or index in self._buffered:
                raise ValueError("Invalid or duplicate Responses tool index")
            buf = BufferedResponseTool(item=dict(item))
            self._buffered[index] = buf
            self._save(buf, frame)
            return
        if event in _ARGUMENT_EVENTS:
            buf = self._buffered.get(index)
            if buf is None or (payload.get("item_id") and payload["item_id"] != buf.item.get("id")):
                raise ValueError("Tool arguments arrived without their matching output item")
            self._save(buf, frame)
            if event.endswith(".delta"):
                buf.fragments += payload.get("delta", "")
            else:
                buf.final_input = payload.get(buf.input_key)
            return
        if event == "response.output_item.done" and (item.get("type") in _TOOL_TYPES or index in self._buffered):
            buf = self._buffered.pop(index, None)
            if buf:
                item = buf.complete(item)
            await self._check_item(item)
            if buf:
                for saved in buf.frames:
                    yield saved
            yield frame.encode()
            return
        if event == "response.output_text.delta":
            self._text_chunks.append(payload.get("delta", ""))
        elif event in {"response.reasoning_summary_text.delta", "response.reasoning_text.delta"}:
            self._reasoning.append(payload.get("delta", ""))
        elif event in {"response.completed", "response.incomplete", "response.failed"}:
            if self._buffered:
                raise ValueError("Response ended with unfinished tool calls")
            response = payload.get("response", {})
            for output_item in response.get("output", []):
                if output_item.get("type") in _TOOL_TYPES:
                    if event != "response.completed":
                        raise ValueError("Incomplete response contained executable tools")
                    await self._check_item(output_item)
            yield frame.encode()
            self._complete = True
            # Prefer final text when supplied; checking still happens after delivery.
            final = self._parser.parse_responses(response)
            if final.content:
                self._text_chunks = [final.content]
            await self._post_stream_output_check()
            return
        elif event == "error":
            self._complete = True
        yield frame.encode()
