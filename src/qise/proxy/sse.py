"""Small incremental SSE decoder shared by the supported API dialects."""

from __future__ import annotations

import codecs
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

MAX_BUFFER_BYTES = 8 * 1024 * 1024


@dataclass
class SSEFrame:
    raw: str
    event: str = ""
    data: str = ""

    def encode(self) -> bytes:
        return (self.raw + "\n\n").encode("utf-8")


def parse_frame(raw: str) -> SSEFrame:
    event = ""
    data = []
    for line in raw.splitlines():
        if line.startswith("event:"):
            event = line[6:].lstrip(" ")
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
    return SSEFrame(raw=raw, event=event, data="\n".join(data))


async def iter_frames(source: Any) -> AsyncIterator[SSEFrame]:
    """Accept arbitrary transport chunks, including split UTF-8 and CRLF."""
    chunks = source.content if hasattr(source, "content") else source
    decoder = codecs.getincrementaldecoder("utf-8")()
    buffer = ""
    lines: list[str] = []
    size = 0
    async for chunk in chunks:
        buffer += decoder.decode(chunk) if isinstance(chunk, bytes) else chunk
        if len(buffer) + size > MAX_BUFFER_BYTES:
            raise ValueError("SSE event exceeded the proxy buffer limit")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.removesuffix("\r")
            if not line:
                if lines:
                    yield parse_frame("\n".join(lines))
                lines, size = [], 0
            else:
                lines.append(line)
                size += len(line)
    buffer += decoder.decode(b"", final=True)
    # Incomplete SSE frames must not carry an executable event at EOF.
    if buffer or lines:
        raise ValueError("Upstream ended in an incomplete SSE event")
