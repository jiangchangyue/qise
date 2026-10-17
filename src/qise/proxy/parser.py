"""Normalize supported model API messages for guard inspection.

Text paths retain the location of inspected input so isolation/sanitization can
be written back without dropping images or changing the surrounding protocol.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field


class ParsedToolCall(BaseModel):
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    call_id: str = ""
    arguments_valid: bool = True


class ParsedMessage(BaseModel):
    role: str
    content: str = ""
    tool_calls: list[ParsedToolCall] = Field(default_factory=list)
    tool_call_id: str = ""
    trust_boundary: str | None = None
    content_paths: list[list[str | int]] = Field(default_factory=list)


class ParsedToolDef(BaseModel):
    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class ParsedRequest(BaseModel):
    model: str = ""
    messages: list[ParsedMessage] = Field(default_factory=list)
    tools: list[ParsedToolDef] = Field(default_factory=list)
    stream: bool = False
    raw_body: dict[str, Any] = Field(default_factory=dict)
    api_format: str = "openai"


class ParsedResponse(BaseModel):
    content: str = ""
    tool_calls: list[ParsedToolCall] = Field(default_factory=list)
    reasoning: str = ""
    finish_reason: str = ""
    model: str = ""
    raw_body: dict[str, Any] = Field(default_factory=dict)


def _infer_trust_boundary(role: str, msg: dict[str, Any]) -> str | None:
    if role == "tool" or (role == "user" and (msg.get("tool_call_id") or msg.get("name"))):
        return "tool_result"
    return {
        "user": "user_input",
        "assistant": "agent_message",
        "system": "context_file",
        "developer": "context_file",
    }.get(role)


def _text_parts(value: Any, path: list[str | int]) -> tuple[str, list[list[str | int]]]:
    if isinstance(value, str):
        return value, [path]
    parts: list[str] = []
    paths: list[list[str | int]] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str):
                text, locations = item, [path + [index]]
            elif isinstance(item, dict) and item.get("type") in {"text", "input_text", "output_text", "summary_text"}:
                text, locations = _text_parts(item.get("text"), path + [index, "text"])
            else:
                continue
            parts.append(text)
            paths.extend(locations)
    return "\n".join(parts), paths


def _extract_content_text(value: Any) -> str:
    return _text_parts(value, [])[0]


def parse_tool_arguments(value: Any) -> tuple[dict[str, Any], bool]:
    """Never turn malformed executable arguments into an apparently safe {}."""
    if isinstance(value, dict):
        return value, True
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed, True
        except (ValueError, TypeError):
            pass
    return {"_raw_arguments": value}, False


def _chat_tool_call(tc: dict[str, Any]) -> ParsedToolCall:
    function = tc.get("function", {})
    args, valid = parse_tool_arguments(function.get("arguments", {}))
    return ParsedToolCall(
        tool_name=function.get("name", ""), tool_args=args, call_id=tc.get("id", ""), arguments_valid=valid
    )


def responses_tool_call(item: dict[str, Any]) -> ParsedToolCall | None:
    """Client-executed Responses tools; hosted tools are outside this boundary."""
    kind = item.get("type")
    if kind == "function_call":
        args, valid = parse_tool_arguments(item.get("arguments"))
    elif kind == "custom_tool_call":
        value = item.get("input")
        args, valid = {"input": value}, isinstance(value, str)
    else:
        return None
    return ParsedToolCall(
        tool_name=str(item.get("name") or ""),
        tool_args=args,
        call_id=str(item.get("call_id") or item.get("id") or ""),
        arguments_valid=valid,
    )


class RequestParser:
    def parse(self, body: dict[str, Any]) -> ParsedRequest:
        messages = []
        for index, msg in enumerate(body.get("messages", [])):
            role = msg.get("role", "")
            content, paths = _text_parts(msg.get("content"), ["messages", index, "content"])
            calls = [_chat_tool_call(tc) for tc in msg.get("tool_calls", [])]
            if msg.get("function_call"):
                calls.append(_chat_tool_call({"function": msg["function_call"]}))
            messages.append(
                ParsedMessage(
                    role=role,
                    content=content,
                    content_paths=paths,
                    tool_calls=calls,
                    tool_call_id=msg.get("tool_call_id", ""),
                    trust_boundary=_infer_trust_boundary(role, msg),
                )
            )
        tools = []
        for tool in body.get("tools", []):
            function = tool.get("function", {})
            if function:
                tools.append(
                    ParsedToolDef(
                        name=function.get("name", ""),
                        description=function.get("description", ""),
                        parameters=function.get("parameters", {}),
                    )
                )
        return ParsedRequest(
            model=body.get("model", ""), messages=messages, tools=tools, stream=body.get("stream", False), raw_body=body
        )

    def parse_anthropic(self, body: dict[str, Any]) -> ParsedRequest:
        messages = []
        system, paths = _text_parts(body.get("system"), ["system"])
        if system:
            messages.append(
                ParsedMessage(role="system", content=system, content_paths=paths, trust_boundary="context_file")
            )
        for index, msg in enumerate(body.get("messages", [])):
            role = msg.get("role", "")
            content = msg.get("content")
            text, paths = _text_parts(content, ["messages", index, "content"])
            calls = []
            if isinstance(content, list):
                for block_index, block in enumerate(content):
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        result, result_paths = _text_parts(
                            block.get("content"), ["messages", index, "content", block_index, "content"]
                        )
                        messages.append(
                            ParsedMessage(
                                role="tool",
                                content=result,
                                content_paths=result_paths,
                                tool_call_id=str(block.get("tool_use_id") or ""),
                                trust_boundary="tool_result",
                            )
                        )
                    elif block.get("type") == "tool_use":
                        args, valid = parse_tool_arguments(block.get("input", {}))
                        calls.append(
                            ParsedToolCall(
                                tool_name=str(block.get("name") or ""),
                                tool_args=args,
                                call_id=str(block.get("id") or ""),
                                arguments_valid=valid,
                            )
                        )
            if text or calls:
                messages.append(
                    ParsedMessage(
                        role=role,
                        content=text,
                        content_paths=paths,
                        tool_calls=calls,
                        trust_boundary=_infer_trust_boundary(role, msg),
                    )
                )
        tools = [
            ParsedToolDef(
                name=str(tool.get("name") or ""),
                description=str(tool.get("description") or ""),
                parameters=tool.get("input_schema") or {},
            )
            for tool in body.get("tools", [])
        ]
        return ParsedRequest(
            model=body.get("model", ""),
            messages=messages,
            tools=tools,
            stream=body.get("stream", False),
            raw_body=body,
            api_format="anthropic",
        )

    def parse_responses(self, body: dict[str, Any]) -> ParsedRequest:
        messages = []
        instructions = body.get("instructions")
        if isinstance(instructions, str):
            messages.append(
                ParsedMessage(
                    role="system", content=instructions, content_paths=[["instructions"]], trust_boundary="context_file"
                )
            )
        items = body.get("input", [])
        if isinstance(items, str):
            messages.append(
                ParsedMessage(role="user", content=items, content_paths=[["input"]], trust_boundary="user_input")
            )
        elif isinstance(items, list):
            for index, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                kind = item.get("type", "message")
                if kind in {"function_call_output", "custom_tool_call_output"}:
                    text, paths = _text_parts(item.get("output"), ["input", index, "output"])
                    messages.append(
                        ParsedMessage(
                            role="tool",
                            content=text,
                            content_paths=paths,
                            tool_call_id=str(item.get("call_id") or ""),
                            trust_boundary="tool_result",
                        )
                    )
                elif call := responses_tool_call(item):
                    messages.append(ParsedMessage(role="assistant", tool_calls=[call], trust_boundary="agent_message"))
                elif kind == "message":
                    role = item.get("role", "user")
                    text, paths = _text_parts(item.get("content"), ["input", index, "content"])
                    messages.append(
                        ParsedMessage(
                            role=role,
                            content=text,
                            content_paths=paths,
                            trust_boundary=_infer_trust_boundary(role, item),
                        )
                    )
        tools = []
        for tool in body.get("tools", []):
            if tool.get("type") in {"function", "custom"}:
                tools.append(
                    ParsedToolDef(
                        name=tool.get("name", ""),
                        description=tool.get("description", ""),
                        parameters=tool.get("parameters") or {},
                    )
                )
        return ParsedRequest(
            model=body.get("model", ""),
            messages=messages,
            tools=tools,
            stream=body.get("stream", False),
            raw_body=body,
            api_format="responses",
        )


class ResponseParser:
    def parse(self, body: dict[str, Any]) -> ParsedResponse:
        contents, calls, reasoning = [], [], []
        finish_reason = ""
        for choice in body.get("choices", []):
            message = choice.get("message", {})
            finish_reason = choice.get("finish_reason") or finish_reason
            text = _extract_content_text(message.get("content"))
            if text:
                contents.append(text)
            for key in ("thinking", "reasoning_content", "reasoning"):
                if isinstance(message.get(key), str):
                    reasoning.append(message[key])
            if isinstance(message.get("content"), list):
                reasoning.extend(
                    part.get("thinking", "")
                    for part in message["content"]
                    if isinstance(part, dict) and part.get("type") == "thinking"
                )
            calls.extend(_chat_tool_call(tc) for tc in message.get("tool_calls", []))
            if message.get("function_call"):
                calls.append(_chat_tool_call({"function": message["function_call"]}))
        return ParsedResponse(
            content="\n".join(contents),
            tool_calls=calls,
            reasoning="\n".join(reasoning),
            finish_reason=finish_reason,
            model=body.get("model", ""),
            raw_body=body,
        )

    def parse_anthropic(self, body: dict[str, Any]) -> ParsedResponse:
        contents, calls, reasoning = [], [], []
        for block in body.get("content", []):
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                contents.append(str(block.get("text") or ""))
            elif kind == "thinking":
                reasoning.append(str(block.get("thinking") or ""))
            elif kind == "tool_use":
                args, valid = parse_tool_arguments(block.get("input"))
                calls.append(
                    ParsedToolCall(
                        tool_name=str(block.get("name") or ""),
                        tool_args=args,
                        call_id=str(block.get("id") or ""),
                        arguments_valid=valid,
                    )
                )
        return ParsedResponse(
            content="\n".join(contents),
            tool_calls=calls,
            reasoning="\n".join(reasoning),
            finish_reason=str(body.get("stop_reason") or ""),
            model=str(body.get("model") or ""),
            raw_body=body,
        )

    def parse_responses(self, body: dict[str, Any]) -> ParsedResponse:
        contents, calls, reasoning = [], [], []
        for item in body.get("output", []):
            if not isinstance(item, dict):
                continue
            if call := responses_tool_call(item):
                calls.append(call)
            elif item.get("type") == "message":
                contents.append(_extract_content_text(item.get("content")))
            elif item.get("type") == "reasoning":
                reasoning.append(_extract_content_text(item.get("summary")))
        return ParsedResponse(
            content="\n".join(part for part in contents if part),
            tool_calls=calls,
            reasoning="\n".join(reasoning),
            finish_reason=str(body.get("status") or ""),
            model=str(body.get("model") or ""),
            raw_body=body,
        )

    def parse_stream_chunk(self, chunk: dict[str, Any]) -> ParsedResponse:
        # Deltas are partial; the stream handler validates final arguments.
        response = self.parse(
            {
                **chunk,
                "choices": [{**choice, "message": choice.get("delta", {})} for choice in chunk.get("choices", [])],
            }
        )
        response.raw_body = chunk
        return response
