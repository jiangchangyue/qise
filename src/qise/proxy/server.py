"""ProxyServer — aiohttp-based HTTP reverse proxy for Qise.

Intercepts Agent↔LLM traffic, runs guard checks, injects security context,
and forwards requests to the upstream LLM API.

Core flow:
  1. Parse request body
  2. Request interception (ingress checks)
  3. Inject SecurityContext (if enabled)
  4. Forward to upstream
  5. Receive response
  6. Response interception (egress/output checks)
  7. Return response to agent (or block)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import aiohttp
from aiohttp import web

from qise.proxy.config import ProxyConfig
from qise.proxy.context_injector import ContextInjector
from qise.proxy.interceptor import ProxyDecision, ProxyInterceptor
from qise.proxy.parser import ParsedRequest, RequestParser, ResponseParser
from qise.proxy.responses_streaming import ResponsesSSEStreamHandler
from qise.proxy.streaming import AnthropicSSEStreamHandler, SSEStreamHandler

logger = logging.getLogger("qise.proxy")


@dataclass(frozen=True)
class ResolvedProxyRoute:
    agent_name: str = ""
    upstream_base_url: str = ""
    upstream_api_key: str = ""
    upstream_api_key_env: str = ""


class ProxyServer:
    """aiohttp-based HTTP reverse proxy for AI agent security.

    Usage:
        from qise.core.shield import Shield
        from qise.proxy.server import ProxyServer

        shield = Shield.from_config()
        server = ProxyServer(shield)
        await server.start()
        # ... proxy is running on port 8822 ...
        await server.stop()
    """

    def __init__(
        self,
        shield: Any,
        config: ProxyConfig | None = None,
    ) -> None:
        """Initialize the proxy server.

        Args:
            shield: A Shield instance with configured pipeline.
            config: ProxyConfig for the server. If None, created from shield config.
        """
        self._shield = shield
        self._config = config or ProxyConfig.from_shield_config(shield.config)

        # Build components
        self._request_parser = RequestParser()
        self._response_parser = ResponseParser()
        self._context_injector = ContextInjector(shield.context_provider)
        self._interceptor = ProxyInterceptor(shield, self._config)

        # aiohttp app and runner
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._session: aiohttp.ClientSession | None = None

    @property
    def config(self) -> ProxyConfig:
        return self._config

    async def start(self) -> None:
        """Start the proxy server."""
        self._app = web.Application(client_max_size=int(self._config.max_request_body_mb * 1024 * 1024))
        self._app.router.add_route("*", "/{path:.*}", self._handle_request)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        site = web.TCPSite(
            self._runner,
            self._config.listen_host,
            self._config.listen_port,
        )
        await site.start()
        logger.info(
            "Qise proxy listening on %s:%d → %s",
            self._config.listen_host,
            self._config.listen_port,
            self._config.upstream_base_url or "(no upstream configured)",
        )

    async def stop(self) -> None:
        """Stop the proxy server and clean up resources."""
        if self._session:
            await self._session.close()
            self._session = None
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        logger.info("Qise proxy stopped")

    def _canonical_path_and_agent(self, path: str) -> tuple[str, str]:
        """Return (agent_name, OpenAI-compatible path) for agent-prefixed routes."""
        path_without_query = path.split("?")[0]
        parts = path_without_query.split("/")
        if len(parts) >= 5 and parts[1] in {"agent", "agents"} and parts[3] == "v1":
            try:
                from qise.product.agents import normalize_agent_key

                agent_name = normalize_agent_key(parts[2])
            except Exception:
                agent_name = parts[2].strip().lower()
            suffix = "/".join(parts[4:])
            canonical = "/v1" + (f"/{suffix}" if suffix else "")
            return agent_name, canonical
        return "", path_without_query

    def _protected_agent_records(self) -> dict[str, dict[str, Any]]:
        try:
            from qise.product.service import load_state

            protected = load_state().get("protected_agents", {})
        except Exception:
            return {}
        if not isinstance(protected, dict):
            return {}
        return {k: v for k, v in protected.items() if isinstance(v, dict)}

    def _route_from_record(self, agent_name: str, record: dict[str, Any]) -> ResolvedProxyRoute:
        upstream = str(record.get("upstream_url") or "").rstrip("/")
        env_key = str(record.get("proxy_env_key") or record.get("upstream_api_key_env") or "")
        return ResolvedProxyRoute(
            agent_name=agent_name,
            upstream_base_url=upstream,
            upstream_api_key=os.environ.get(env_key, "") if env_key else "",
            upstream_api_key_env=env_key,
        )

    def _route_from_auth(self, request: web.Request) -> ResolvedProxyRoute | None:
        auth = request.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        api_key = request.headers.get("X-Api-Key", "") or request.headers.get("x-api-key", "")
        if not token and not api_key:
            return None

        matches: list[ResolvedProxyRoute] = []
        for agent_name, record in self._protected_agent_records().items():
            env_key = str(record.get("proxy_env_key") or record.get("upstream_api_key_env") or "")
            env_value = os.environ.get(env_key) if env_key else ""
            if env_value and env_value in {token, api_key}:
                route = self._route_from_record(agent_name, record)
                if route.upstream_base_url:
                    matches.append(route)
        return matches[0] if len(matches) == 1 else None

    def _resolve_route(
        self,
        request: web.Request,
        body: dict[str, Any] | None = None,
        agent_hint: str = "",
    ) -> ResolvedProxyRoute:
        records = self._protected_agent_records()

        if agent_hint and agent_hint in records:
            route = self._route_from_record(agent_hint, records[agent_hint])
            if route.upstream_base_url:
                return route

        auth_route = self._route_from_auth(request)
        if auth_route is not None:
            return auth_route

        records_with_upstream = {
            name: record for name, record in records.items() if str(record.get("upstream_url") or "").strip()
        }
        if not agent_hint and len(records_with_upstream) == 1:
            name, record = next(iter(records_with_upstream.items()))
            route = self._route_from_record(name, record)
            if route.upstream_base_url:
                return route

        return ResolvedProxyRoute(
            agent_name=agent_hint,
            upstream_base_url=self._config.upstream_base_url.rstrip("/"),
            upstream_api_key=self._config.upstream_api_key,
        )

    def _api_format_for_path(self, path: str) -> str:
        return "anthropic" if path == "/v1/messages" or path.startswith("/v1/messages/") else "openai"

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Main request handler — all paths pass through here.

        For intercept_paths (e.g., /v1/chat/completions), run guard checks.
        For all other paths, forward transparently.
        """
        raw_path = "/" + request.match_info.get("path", "")
        if raw_path == "/_qise/health" and request.method == "GET":
            from qise import __version__
            from qise.product.service import profile_id

            return web.json_response(
                {
                    "service": "qise-proxy",
                    "version": __version__,
                    "pid": os.getpid(),
                    "instance_id": os.getenv("QISE_SERVICE_INSTANCE", ""),
                    "profile_id": profile_id(),
                }
            )
        agent_name, path_without_query = self._canonical_path_and_agent(raw_path)

        # Check if this path should be intercepted
        should_intercept = any(
            path_without_query == ip or path_without_query.startswith(ip + "/") for ip in self._config.intercept_paths
        )

        # Check if this path should passthrough without interception
        is_passthrough = any(path_without_query == pp for pp in self._config.passthrough_paths)

        if is_passthrough or not should_intercept:
            return await self._forward_request(request, path_override=path_without_query, agent_name=agent_name)

        # Intercept chat completion requests
        if path_without_query == "/v1/chat/completions" and request.method == "POST":
            return await self._handle_chat_completions(request, path_override=path_without_query, agent_name=agent_name)
        if path_without_query == "/v1/messages" and request.method == "POST":
            return await self._handle_anthropic_messages(
                request, path_override=path_without_query, agent_name=agent_name
            )

        if path_without_query == "/v1/responses" and request.method == "POST":
            return await self._handle_responses(request, path_override=path_without_query, agent_name=agent_name)
        if (
            request.method == "GET"
            and path_without_query.startswith("/v1/responses/")
            and len(path_without_query.split("/")) == 4
        ):
            return await self._handle_responses(request, path_override=path_without_query, agent_name=agent_name)

        # Other paths on intercepted routes: just forward
        return await self._forward_request(request, path_override=path_without_query, agent_name=agent_name)

    async def _handle_chat_completions(
        self,
        request: web.Request,
        *,
        path_override: str | None = None,
        agent_name: str = "",
    ) -> web.Response:
        return await self._handle_model_request(
            request, path_override=path_override, agent_name=agent_name, api_format="openai"
        )

    async def _handle_anthropic_messages(
        self,
        request: web.Request,
        *,
        path_override: str | None = None,
        agent_name: str = "",
    ) -> web.Response:
        return await self._handle_model_request(
            request, path_override=path_override, agent_name=agent_name, api_format="anthropic"
        )

    async def _handle_responses(
        self,
        request: web.Request,
        *,
        path_override: str | None = None,
        agent_name: str = "",
    ) -> web.Response:
        return await self._handle_model_request(
            request, path_override=path_override, agent_name=agent_name, api_format="responses"
        )

    async def _handle_model_request(
        self,
        request: web.Request,
        *,
        path_override: str | None,
        agent_name: str,
        api_format: str,
    ) -> web.Response:
        request_method = getattr(request, "method", "POST")
        request_parser = {
            "openai": self._request_parser.parse,
            "anthropic": self._request_parser.parse_anthropic,
            "responses": self._request_parser.parse_responses,
        }[api_format]
        response_parser = {
            "openai": self._response_parser.parse,
            "anthropic": self._response_parser.parse_anthropic,
            "responses": self._response_parser.parse_responses,
        }[api_format]
        injector = {
            "openai": self._context_injector.inject,
            "anthropic": self._context_injector.inject_anthropic,
            "responses": self._context_injector.inject_responses,
        }[api_format]
        try:
            body = {} if request_method == "GET" else await request.json()
            if not isinstance(body, dict):
                raise ValueError("Request body must be a JSON object")
            parsed_request = request_parser(body)
            if request_method == "GET":
                parsed_request.stream = getattr(request, "query", {}).get("stream") == "true"
        except (ValueError, TypeError, AttributeError) as exc:
            return web.json_response({"error": {"type": "invalid_request_error", "message": str(exc)}}, status=400)

        route = self._resolve_route(request, body, agent_name)
        agent_name = route.agent_name or agent_name
        request_decision = await asyncio.to_thread(
            self._interceptor.intercept_request, parsed_request, body, agent_name
        )
        if request_decision.action == "block" and self._config.block_on_guard_block:
            return self._block_response(request_decision, api_format=api_format)
        forward_body = None if request_method == "GET" else request_decision.modified_body
        if self._config.inject_security_context and forward_body is not None:
            forward_body = injector(forward_body)
        if parsed_request.stream:
            return await self._handle_streaming(
                request,
                forward_body,
                path_override=path_override,
                route=route,
                agent_name=agent_name,
                api_format=api_format,
                request_context=parsed_request,
            )

        upstream_response = await self._forward_to_upstream(
            request,
            forward_body,
            path_override=path_override,
            route=route,
            api_format=api_format,
        )
        if upstream_response.status != 200:
            return upstream_response
        try:
            response_body = self._response_json(upstream_response)
            parsed_response = response_parser(response_body)
        except (ValueError, TypeError, AttributeError):
            return web.json_response(
                {"error": {"type": "qise_upstream_error", "message": "Upstream returned an invalid model response"}},
                status=502,
            )
        decision = await asyncio.to_thread(
            self._interceptor.intercept_response,
            parsed_response,
            response_body,
            agent_name,
            parsed_request,
        )
        if decision.action == "block" and self._config.block_on_guard_block:
            return self._block_response(decision, api_format=api_format)
        headers = {
            key: value
            for key, value in upstream_response.headers.items()
            if key.lower() not in {"content-length", "content-type", "content-encoding"}
        }
        warnings = request_decision.warnings + decision.warnings
        if warnings:
            headers["X-Qise-Warnings"] = "; ".join(warnings[:5]).replace("\n", " ").replace("\r", " ")[:1000]
        if hasattr(self._shield, "metrics"):
            headers["X-Qise-Metrics"] = self._shield.metrics.brief()
        return web.json_response(decision.modified_body, headers=headers)

    def _upstream_url(self, path: str, upstream_base_url: str | None = None) -> str:
        base = (upstream_base_url if upstream_base_url is not None else self._config.upstream_base_url).rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        if base.endswith("/v1") and path.startswith("/v1/"):
            return base[:-3] + path
        return base + path

    def _response_json(self, response: web.Response) -> dict[str, Any]:
        body = response.body or b"{}"
        if isinstance(body, str):
            return json.loads(body)
        return json.loads(body.decode(response.charset or "utf-8"))

    def _build_forward_headers(
        self,
        request: web.Request,
        route: ResolvedProxyRoute,
        *,
        api_format: str,
        streaming: bool = False,
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        skip = {"host", "content-length", "transfer-encoding"}
        if streaming:
            skip.add("accept")
        for key, value in request.headers.items():
            key_lower = key.lower()
            if key_lower in skip:
                continue
            if route.upstream_api_key and key_lower in {"authorization", "x-api-key"}:
                continue
            headers[key] = value

        if api_format == "anthropic":
            if "anthropic-version" not in {key.lower() for key in headers}:
                headers["anthropic-version"] = "2023-06-01"
            if route.upstream_api_key:
                if route.upstream_api_key_env == "ANTHROPIC_AUTH_TOKEN":
                    headers["Authorization"] = f"Bearer {route.upstream_api_key}"
                else:
                    headers["X-Api-Key"] = route.upstream_api_key
        elif route.upstream_api_key:
            headers["Authorization"] = f"Bearer {route.upstream_api_key}"

        return headers

    async def _handle_streaming(
        self,
        request: web.Request,
        forward_body: dict[str, Any] | None,
        *,
        path_override: str | None = None,
        route: ResolvedProxyRoute | None = None,
        agent_name: str = "",
        api_format: str = "openai",
        request_context: ParsedRequest | None = None,
    ) -> web.StreamResponse:
        """Handle streaming (SSE) chat completion requests.

        Uses SSEStreamHandler to process chunks with guard interception.
        """
        route = route or self._resolve_route(request, forward_body, agent_name)
        path = path_override or self._canonical_path_and_agent("/" + request.match_info.get("path", ""))[1]
        if not route.upstream_base_url:
            resp = web.json_response(
                {"error": "Proxy upstream is not configured for this Agent route."},
                status=502,
            )
            return resp  # type: ignore[return-value]
        upstream_url = self._upstream_url(path, route.upstream_base_url)
        if query := getattr(request, "query_string", ""):
            upstream_url += "?" + query

        headers = self._build_forward_headers(request, route, api_format=api_format, streaming=True)

        session = await self._get_session()

        # Open streaming connection to upstream
        try:
            upstream_resp = await session.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                json=forward_body,
                timeout=aiohttp.ClientTimeout(total=self._config.request_timeout_s),
            )
        except (TimeoutError, aiohttp.ClientError) as e:
            logger.error("Upstream streaming request failed: %s", e)
            resp = web.json_response(
                {"error": f"Upstream request failed: {e}"},
                status=502,
            )
            return resp  # type: ignore[return-value]

        if upstream_resp.status != 200:
            try:
                data = await upstream_resp.read()
                return web.Response(body=data, status=upstream_resp.status, content_type=upstream_resp.content_type)
            finally:
                upstream_resp.release()
        stream_resp = web.StreamResponse(
            status=upstream_resp.status,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Qise-Text-Inspection": "post-stream-audit",
            },
        )
        try:
            await stream_resp.prepare(request)
            handler_class = {
                "openai": SSEStreamHandler,
                "anthropic": AnthropicSSEStreamHandler,
                "responses": ResponsesSSEStreamHandler,
            }[api_format]
            handler = handler_class(
                self._interceptor, agent_name=route.agent_name or agent_name, request_context=request_context
            )
            async for chunk in handler.process_stream(upstream_resp):
                await stream_resp.write(chunk)
            await stream_resp.write_eof()
            return stream_resp
        finally:
            # release() is synchronous, and must also run on disconnect/cancellation.
            upstream_resp.release()

    async def _forward_request(
        self,
        request: web.Request,
        *,
        path_override: str | None = None,
        agent_name: str = "",
    ) -> web.Response:
        """Forward a request to the upstream without interception."""
        body = await request.json() if request.method in ("POST", "PUT", "PATCH") else None
        path = path_override or self._canonical_path_and_agent("/" + request.match_info.get("path", ""))[1]
        return await self._forward_to_upstream(
            request,
            body,
            path_override=path,
            route=self._resolve_route(request, body, agent_name),
            api_format=self._api_format_for_path(path),
        )

    async def _forward_to_upstream(
        self,
        request: web.Request,
        body: dict[str, Any] | None = None,
        *,
        path_override: str | None = None,
        route: ResolvedProxyRoute | None = None,
        api_format: str | None = None,
    ) -> web.Response:
        """Forward the request to the upstream LLM API.

        Replaces the request's Host header and Authorization with the
        upstream's base URL and API key.
        """
        route = route or self._resolve_route(request, body)
        if not route.upstream_base_url:
            return web.json_response(
                {"error": "Proxy upstream is not configured for this Agent route."},
                status=502,
            )
        path = path_override or self._canonical_path_and_agent("/" + request.match_info.get("path", ""))[1]
        upstream_url = self._upstream_url(path, route.upstream_base_url)
        if query := getattr(request, "query_string", ""):
            upstream_url += "?" + query
        api_format = api_format or self._api_format_for_path(path)
        headers = self._build_forward_headers(request, route, api_format=api_format)

        # Get or create HTTP session
        session = await self._get_session()

        try:
            async with session.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                json=body,
                timeout=aiohttp.ClientTimeout(total=self._config.request_timeout_s),
            ) as resp:
                # Read the full response
                resp_body = await resp.read()
                content_type = resp.content_type

                # Build response headers (skip hop-by-hop + Content-Type which is set via content_type param)
                resp_headers = {}
                for key, value in resp.headers.items():
                    key_lower = key.lower()
                    if key_lower in ("transfer-encoding", "connection", "content-encoding", "content-type"):
                        continue
                    resp_headers[key] = value

                return web.Response(
                    body=resp_body,
                    status=resp.status,
                    content_type=content_type,
                    headers=resp_headers,
                )
        except (TimeoutError, aiohttp.ClientError) as e:
            logger.error("Upstream request failed: %s", e)
            return web.json_response(
                {"error": f"Upstream request failed: {e}"},
                status=502,
            )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the HTTP client session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    def _block_response(self, decision: ProxyDecision, *, api_format: str = "openai") -> web.Response:
        """Return an error response for blocked requests/responses."""
        if api_format == "anthropic":
            return web.json_response(
                {
                    "type": "error",
                    "error": {
                        "type": "permission_error",
                        "message": decision.block_reason,
                        "warnings": decision.warnings,
                        "guard_results": decision.guard_results,
                    },
                },
                status=403,
            )
        return web.json_response(
            {
                "error": {
                    "message": decision.block_reason,
                    "type": "qise_guard_block",
                    "warnings": decision.warnings,
                    "guard_results": decision.guard_results,
                }
            },
            status=403,
        )
