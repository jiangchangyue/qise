"""BridgeServer — aiohttp HTTP server for Guard Pipeline analysis.

Receives guard check requests from the Rust Proxy, runs the Qise Guard
Pipeline (ingress/egress/output), and returns structured decisions.

Endpoints:
  POST /v1/guard/check           — Main guard analysis endpoint
  GET  /v1/bridge/health         — Health check
  GET  /v1/bridge/metrics        — Metrics snapshot
  GET  /v1/bridge/guards         — List all guards with real mode + strategy
  GET  /v1/bridge/events         — Recent security events
  POST /v1/bridge/guard/mode     — Set a guard's mode
  WS   /v1/bridge/events/stream  — WebSocket real-time event stream
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import deque
from contextlib import suppress
from typing import Any

from aiohttp import WSMsgType, web

from qise.bridge.protocol import (
    GuardCheckRequest,
    GuardCheckResponse,
    GuardResultSummary,
)
from qise.core.models import GuardContext
from qise.product.policy import guard_rows, refresh_guard_policy, set_guard_mode
from qise.product.privacy import redact_text

logger = logging.getLogger("qise.bridge")


class BridgeServer:
    """HTTP server that receives guard check requests from Rust Proxy."""

    def __init__(self, shield: Any, port: int = 8823, host: str = "127.0.0.1") -> None:
        self._shield = shield
        self._port = port
        self._host = host
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._event_buffer: deque[dict[str, str]] = deque(maxlen=1000)
        self._last_slm_latency_ms: int = 0
        self._ws_clients: list[web.WebSocketResponse] = []

    async def start(self) -> None:
        """Start the bridge server."""
        self._app = web.Application(client_max_size=10 * 1024 * 1024)
        self._app.router.add_post("/v1/guard/check", self._handle_guard_check)
        self._app.router.add_get("/v1/bridge/health", self._handle_health)
        self._app.router.add_get("/v1/bridge/metrics", self._handle_metrics)
        self._app.router.add_get("/v1/bridge/guards", self._handle_guards)
        self._app.router.add_get("/v1/bridge/events", self._handle_events)
        self._app.router.add_post("/v1/bridge/guard/mode", self._handle_set_guard_mode)
        self._app.router.add_get("/v1/bridge/events/stream", self._handle_events_stream)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()
        logger.info("Qise bridge listening on %s:%d", self._host, self._port)

    async def stop(self) -> None:
        """Stop the bridge server."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        logger.info("Qise bridge stopped")

    async def _handle_guard_check(self, request: web.Request) -> web.Response:
        """Handle POST /v1/guard/check — main guard analysis endpoint."""
        try:
            body = await request.json()
        except Exception as e:
            return web.json_response(
                {"error": f"Invalid JSON: {e}"},
                status=400,
            )

        try:
            req = GuardCheckRequest(**body)
        except Exception as e:
            return web.json_response(
                {"error": f"Invalid request: {e}"},
                status=400,
            )

        # Run guard analysis in thread pool to avoid blocking event loop
        result = await asyncio.to_thread(self._run_guard_pipeline, req)

        self._record_product_event(req, result)

        # Record guard events to the buffer and push to WebSocket clients
        for gr in result.guard_results:
            event_data = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "guard_name": gr.guard,
                "verdict": gr.verdict,
                "message": redact_text(gr.message),
                "evidence_kind": gr.evidence_kind,
            }
            self._event_buffer.append(event_data)
            # Push to WebSocket clients
            self._notify_ws_clients(event_data)

        return web.json_response(result.model_dump())


    def _record_product_event(self, req: GuardCheckRequest, result: GuardCheckResponse) -> None:
        if result.action not in {"warn", "block"}:
            return

        if req.type == "request":
            stage = "ingress"
            action_type = "request"
            if req.tools:
                action_name = req.tools[0].name
                resource: Any = req.tools[0].description
            elif req.messages:
                action_name = "content_check"
                resource = req.messages[0].content
            else:
                action_name = "content_check"
                resource = {"model": req.model}
        else:
            stage = "egress" if req.tool_calls else "output"
            action_type = "tool_call" if req.tool_calls else "output"
            action_name = req.tool_calls[0].tool_name if req.tool_calls else "output"
            resource = req.tool_calls[0].tool_args if req.tool_calls else req.content

        blocked_by = None
        if result.block_reason:
            blocked_by = result.block_reason.rsplit(":", 1)[-1].strip()

        with suppress(Exception):
            from qise.product.events import record_guard_event

            record_guard_event(
                stage=stage,
                source="bridge",
                verdict=result.action,
                action_type=action_type,
                action_name=action_name,
                resource=resource,
                blocked_by=blocked_by,
                warnings=result.warnings,
                guard_results=[gr.model_dump() for gr in result.guard_results],
            )

    def _run_guard_pipeline(self, req: GuardCheckRequest) -> GuardCheckResponse:
        """Run the appropriate guard pipeline based on request type.

        This runs synchronously in a thread pool, so it can call the
        synchronous Shield pipeline methods (which may call SLM via httpx).
        """
        refresh_guard_policy(self._shield)
        config = self._shield.config
        guard_modes = {
            name: config.guard_mode(name)
            for name in config.guards.enabled
        }

        start = time.monotonic()

        if req.type == "request":
            result = self._check_request(req, guard_modes)
        elif req.type == "response":
            result = self._check_response(req, guard_modes)
        else:
            result = GuardCheckResponse(
                action="pass",
                warnings=[f"Unknown check type: {req.type}"],
            )

        # Track SLM latency from guard results
        for gr in result.guard_results:
            if gr.latency_ms > 0:
                self._last_slm_latency_ms = gr.latency_ms

        # If no guard reported latency, estimate from total time
        if self._last_slm_latency_ms == 0 and result.guard_results:
            self._last_slm_latency_ms = int((time.monotonic() - start) * 1000)

        return result

    def _check_request(
        self, req: GuardCheckRequest, guard_modes: dict[str, str]
    ) -> GuardCheckResponse:
        """Ingress check: user messages and tool descriptions."""
        all_warnings: list[str] = []
        all_results: list[GuardResultSummary] = []
        should_block = False
        block_reason = ""

        # Check each user message for injection
        for msg in req.messages:
            if msg.role in ("user", "tool") and msg.content:
                trust_boundary = msg.trust_boundary or (
                    "user_input" if msg.role == "user" else "tool_result"
                )
                ctx = GuardContext(
                    tool_name="content_check",
                    tool_args={"content": msg.content},
                    trust_boundary=trust_boundary,
                    integration_mode="proxy",
                )
                result = self._shield.pipeline.run_ingress(ctx, guard_modes)
                all_results.extend(self._summarize_pipeline(result))
                all_warnings.extend(result.warnings)

                if result.should_block:
                    should_block = True
                    block_reason = f"Request blocked by guard: {result.blocked_by}"
                    break

        # Check tool descriptions for poisoning
        if not should_block:
            for tool_def in req.tools:
                if tool_def.description:
                    ctx = GuardContext(
                        tool_name=tool_def.name,
                        tool_args={},
                        tool_description=tool_def.description,
                        trust_boundary="tool_description",
                        integration_mode="proxy",
                    )
                    result = self._shield.pipeline.run_ingress(ctx, guard_modes)
                    all_results.extend(self._summarize_pipeline(result))
                    all_warnings.extend(result.warnings)

                    if result.should_block:
                        should_block = True
                        block_reason = f"Tool description blocked: {result.blocked_by}"
                        break

        # Get security context for injection
        security_context = ""
        if not should_block and req.tools:
            tool_names = [t.name for t in req.tools]
            if tool_names:
                security_context = self._shield.get_security_context(
                    tool_names[0], {}
                )

        # Determine action
        if should_block:
            action = "block"
        elif all_warnings:
            action = "warn"
        else:
            action = "pass"

        return GuardCheckResponse(
            action=action,
            guard_results=all_results,
            security_context=security_context,
            warnings=all_warnings,
            block_reason=block_reason,
        )

    def _check_response(
        self, req: GuardCheckRequest, guard_modes: dict[str, str]
    ) -> GuardCheckResponse:
        """Egress + Output check: tool calls, reasoning, and text content."""
        all_warnings: list[str] = []
        all_results: list[GuardResultSummary] = []
        should_block = False
        block_reason = ""

        # Check tool calls for dangerous actions (egress)
        for tc in req.tool_calls:
            ctx = GuardContext(
                tool_name=tc.tool_name,
                tool_args=tc.tool_args,
                integration_mode="proxy",
                agent_reasoning=req.reasoning or None,
            )
            result = self._shield.pipeline.run_egress(ctx, guard_modes)
            all_results.extend(self._summarize_pipeline(result))
            all_warnings.extend(result.warnings)

            if result.should_block:
                should_block = True
                block_reason = f"Tool call blocked by guard: {result.blocked_by}"
                break

        # Check response text for credential/PII leaks (output)
        if not should_block and req.content:
            ctx = GuardContext(
                tool_name="output",
                tool_args={"text": req.content},
                integration_mode="proxy",
            )
            result = self._shield.pipeline.run_output(ctx, guard_modes)
            all_results.extend(self._summarize_pipeline(result))
            all_warnings.extend(result.warnings)

            if result.should_block:
                should_block = True
                block_reason = f"Output blocked by guard: {result.blocked_by}"

        # Determine action
        if should_block:
            action = "block"
        elif all_warnings:
            action = "warn"
        else:
            action = "pass"

        return GuardCheckResponse(
            action=action,
            guard_results=all_results,
            security_context="",
            warnings=all_warnings,
            block_reason=block_reason,
        )

    def _summarize_pipeline(self, result: Any) -> list[GuardResultSummary]:
        """Summarize a PipelineResult into GuardResultSummary items."""
        summaries = []
        for gr in result.results:
            summaries.append(GuardResultSummary(
                guard=gr.guard_name,
                verdict=str(gr.verdict) if gr.verdict else "pass",
                message=gr.message or "",
                latency_ms=gr.latency_ms or 0,
                evidence_kind=gr.evidence_kind,
            ))
        return summaries

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Handle GET /v1/bridge/health."""
        from qise.product.service import profile_id
        slm_available = self._shield.model_router.is_available("slm")

        # Determine SLM mode: local (localhost/11434), cloud, or unavailable
        slm_mode = "unavailable"
        if slm_available:
            base_url = self._shield.model_router.slm_config.base_url
            slm_mode = "local" if "localhost:11434" in base_url or "127.0.0.1:11434" in base_url else "cloud"

        return web.json_response({
            "status": "ok",
            "service": "qise-bridge",
            "pid": os.getpid(),
            "instance_id": os.environ.get("QISE_SERVICE_INSTANCE", ""),
            "profile_id": profile_id(),
            "slm_available": slm_available,
            "slm_mode": slm_mode,
            "slm_latency_ms": self._last_slm_latency_ms,
        })

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Handle GET /v1/bridge/metrics."""
        metrics = self._shield.metrics.brief() if hasattr(self._shield, "metrics") else "{}"
        return web.json_response({
            "metrics": metrics,
            "slm_available": self._shield.model_router.is_available("slm"),
        })

    async def _handle_guards(self, request: web.Request) -> web.Response:
        """Handle GET /v1/bridge/guards — return all guards with real mode + strategy."""
        return web.json_response(guard_rows(self._shield))

    async def _handle_events(self, request: web.Request) -> web.Response:
        """Handle GET /v1/bridge/events — return recent security events."""
        limit = int(request.query.get("limit", "50"))
        events = list(self._event_buffer)[-limit:]
        return web.json_response(events)

    async def _handle_set_guard_mode(self, request: web.Request) -> web.Response:
        """Handle POST /v1/bridge/guard/mode — set a guard's mode."""
        # The desktop writes policy through the CLI. Do not allow web pages to
        # change local protections: CORS does not prevent simple POST writes.
        if "Origin" in request.headers:
            return web.json_response(
                {"error": "Browser-origin policy writes are not allowed; use the Qise CLI"},
                status=403,
            )
        if request.content_type != "application/json":
            return web.json_response(
                {"error": "Policy writes require application/json"}, status=415,
            )
        try:
            body = await request.json()
        except Exception as e:
            return web.json_response({"error": f"Invalid JSON: {e}"}, status=400)

        if not isinstance(body, dict):
            return web.json_response({"error": "Expected a JSON object"}, status=400)
        guard_name = body.get("guard_name", "")
        mode = body.get("mode", "")
        if not guard_name or not mode:
            return web.json_response(
                {"error": "guard_name and mode are required"}, status=400
            )

        if mode not in ("observe", "enforce", "off"):
            return web.json_response(
                {"error": f"Invalid mode: {mode}. Must be observe/enforce/off"}, status=400
            )

        try:
            for g in self._shield.pipeline.all_guards:
                if g.name == guard_name:
                    set_guard_mode(guard_name, mode)
                    refresh_guard_policy(self._shield)
                    logger.info("Set guard '%s' mode to '%s'", guard_name, mode)
                    return web.json_response({"ok": True})
        except Exception as e:
            logger.warning("Failed to set guard mode: %s", e)
            return web.json_response({"error": "Could not save guard policy; existing protection was retained"}, status=500)

        return web.json_response({"error": f"Guard not found: {guard_name}"}, status=404)

    def _get_pipeline_for_guard(self, guard_name: str) -> str:
        """Determine which pipeline a guard belongs to."""
        ingress = {"prompt", "tool_sanity", "context", "supply_chain"}
        egress = {"command", "filesystem", "network", "exfil", "resource", "tool_policy", "reasoning"}
        output = {"credential", "audit", "output"}
        if guard_name in ingress:
            return "ingress"
        elif guard_name in egress:
            return "egress"
        elif guard_name in output:
            return "output"
        return "unknown"

    # ------------------------------------------------------------------
    # WebSocket: real-time event stream
    # ------------------------------------------------------------------

    def _notify_ws_clients(self, event_data: dict[str, str]) -> None:
        """Send event data to all connected WebSocket clients."""
        # Schedule sends — fire and forget (errors handled on next poll)
        dead_clients: list[web.WebSocketResponse] = []
        for ws in self._ws_clients:
            try:
                # Use ensure_future to avoid blocking
                asyncio.ensure_future(ws.send_json(event_data))
            except Exception:
                dead_clients.append(ws)
        for ws in dead_clients:
            self._ws_clients.remove(ws)

    async def _handle_events_stream(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WS /v1/bridge/events/stream — real-time event push."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self._ws_clients.append(ws)
        logger.info("WebSocket client connected (total: %d)", len(self._ws_clients))

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    # Client can send ping as text
                    if msg.data == "ping":
                        await ws.send_str("pong")
                elif msg.type == WSMsgType.PING:
                    await ws.pong()
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            if ws in self._ws_clients:
                self._ws_clients.remove(ws)
            logger.info("WebSocket client disconnected (total: %d)", len(self._ws_clients))

        return ws
