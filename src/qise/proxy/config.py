"""ProxyConfig — configuration for the Qise API proxy server.

Supports environment variable overrides (QISE_PROXY_*) and shield.yaml
integration via the existing IntegrationProxyConfig.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field


class ProxyConfig(BaseModel):
    """Configuration for the Qise HTTP proxy server.

    Attributes:
        listen_port: Port to listen on.
        listen_host: Host to bind to.
        upstream_base_url: Base URL of the upstream LLM API (e.g., https://api.anthropic.com).
        upstream_api_key: API key for the upstream LLM API.
        inject_security_context: Whether to inject SecurityContextProvider rules into system messages.
        block_on_guard_block: Whether to block requests when guards return BLOCK.
        passthrough_paths: URL paths that are forwarded without interception.
        intercept_paths: URL paths that trigger guard interception.
        request_timeout_s: Timeout for upstream requests.
        max_request_body_mb: Maximum request body size in MB.
    """

    listen_port: int = 8822
    listen_host: str = "127.0.0.1"
    upstream_base_url: str = ""
    upstream_api_key: str = ""
    inject_security_context: bool = True
    block_on_guard_block: bool = True
    passthrough_paths: list[str] = Field(
        default_factory=lambda: ["/v1/models"],
    )
    intercept_paths: list[str] = Field(
        default_factory=lambda: ["/v1/chat/completions", "/v1/messages", "/v1/responses"],
    )
    request_timeout_s: float = 120.0
    max_request_body_mb: float = 50.0

    @classmethod
    def from_shield_config(cls, shield_config: Any) -> ProxyConfig:
        """Create ProxyConfig from a ShieldConfig instance.

        Reads the integration.proxy section and applies env overrides.
        """
        proxy_cfg = shield_config.integration.proxy
        config = cls(
            listen_port=proxy_cfg.port,
            upstream_base_url=proxy_cfg.upstream_url.rstrip("/") if proxy_cfg.upstream_url else "",
            upstream_api_key=proxy_cfg.upstream_api_key,
        )
        config._apply_env_overrides()
        return config

    @classmethod
    def from_env(cls) -> ProxyConfig:
        """Create ProxyConfig from environment variables only."""
        config = cls()
        config._apply_env_overrides()
        return config

    def _apply_env_overrides(self) -> None:
        """Override config values from QISE_PROXY_* environment variables."""
        if val := os.getenv("QISE_PROXY_PORT"):
            self.listen_port = int(val)
        if val := os.getenv("QISE_PROXY_HOST"):
            self.listen_host = val
        if val := os.getenv("QISE_PROXY_UPSTREAM_URL"):
            self.upstream_base_url = val.rstrip("/")
        if val := os.getenv("QISE_PROXY_UPSTREAM_API_KEY"):
            self.upstream_api_key = val
        if val := os.getenv("QISE_PROXY_INJECT_CONTEXT"):
            self.inject_security_context = val.lower() in ("true", "1", "yes")
        if val := os.getenv("QISE_PROXY_BLOCK_ON_GUARD"):
            self.block_on_guard_block = val.lower() in ("true", "1", "yes")
        if not self.upstream_base_url:
            self.upstream_base_url = (os.getenv("OPENAI_API_BASE") or os.getenv("ANTHROPIC_BASE_URL") or "").rstrip("/")
        if not self.upstream_api_key:
            self.upstream_api_key = (
                os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN") or ""
            )
