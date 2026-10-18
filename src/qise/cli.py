"""CLI entry point for Qise.

Subcommands:
    qise check <tool_name> <tool_args_json>  — Single security check
    qise serve                                — Start MCP Server
    qise proxy start                          — Start HTTP proxy server
    qise bridge start                         — Start Python Bridge server
    qise context <tool_name>                  — Get security context text
    qise guards                               — List registered guards
    qise version                              — Print version
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from contextlib import suppress
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qise",
        description="Qise — AI-first runtime security framework for AI agents",
    )
    parser.add_argument("--config", help="Path to shield.yaml", default=None)
    subparsers = parser.add_subparsers(dest="command")

    # qise check
    check_parser = subparsers.add_parser("check", help="Run a single security check")
    check_parser.add_argument("tool_name", help="Tool name (e.g., bash, write_file)")
    check_parser.add_argument("tool_args", help="Tool arguments as JSON string")
    check_parser.add_argument(
        "--pipeline",
        choices=["ingress", "egress", "output"],
        default="egress",
        help="Pipeline to run (default: egress)",
    )
    check_parser.add_argument("--session-id", help="Session ID for tracking")

    # qise serve
    serve_parser = subparsers.add_parser("serve", help="Start MCP Server")
    serve_parser.add_argument(
        "--transport",
        choices=["stdio"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )

    # qise proxy
    proxy_parser = subparsers.add_parser("proxy", help="Proxy server commands")
    proxy_subparsers = proxy_parser.add_subparsers(dest="proxy_command")

    # qise proxy start
    proxy_start = proxy_subparsers.add_parser("start", help="Start HTTP proxy server")
    proxy_start.add_argument("--port", type=int, default=None, help="Listen port (default: from config)")
    proxy_start.add_argument("--host", default=None, help="Listen host (default: 127.0.0.1)")
    proxy_start.add_argument("--upstream", default=None, help="Upstream LLM API base URL")
    proxy_start.add_argument("--upstream-key", default=None, help="Upstream LLM API key")
    proxy_start.add_argument("--no-inject", action="store_true", help="Disable security context injection")
    proxy_start.add_argument("--observe", action="store_true", help="Never block, only warn (observe mode)")
    proxy_start.add_argument("--no-reload", action="store_true", help="Disable config hot-reload")

    # qise context
    context_parser = subparsers.add_parser("context", help="Get security context for a tool")
    context_parser.add_argument("tool_name", help="Tool name")
    context_parser.add_argument("--tool-args", help="Tool arguments as JSON string", default=None)

    # qise guards
    guards_parser = subparsers.add_parser("guards", help="List registered guards")
    guards_parser.add_argument("--metrics", action="store_true", help="Show runtime metrics")
    guards_parser.add_argument("--json", action="store_true", help="Output effective guard policy as JSON")
    guards_parser.add_argument("--set", nargs=2, metavar=("GUARD", "MODE"), help="Save a mode for all Qise services")

    # qise version
    subparsers.add_parser("version", help="Print version")

    # qise init
    init_parser = subparsers.add_parser("init", help="Generate shield.yaml configuration file")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing shield.yaml")

    # qise doctor
    doctor_parser = subparsers.add_parser("doctor", help="Diagnose local Qise readiness")
    doctor_parser.add_argument("--json", action="store_true", help="Output JSON")

    # qise status
    status_parser = subparsers.add_parser("status", help="Show Qise protection status")
    status_parser.add_argument("--json", action="store_true", help="Output JSON")

    # qise agents
    agents_parser = subparsers.add_parser("agents", help="Detect installed Agents available to Qise")
    agents_parser.add_argument("--json", action="store_true", help="Output JSON")
    agents_parser.add_argument(
        "--include-missing",
        action="store_true",
        help="Also show supported Agents that were not detected",
    )

    # qise events
    events_parser = subparsers.add_parser("events", help="Show Qise security events")
    events_parser.add_argument("--limit", type=int, default=50, help="Maximum events to show")
    events_parser.add_argument("--since", default=None, help="Filter by duration like 1h/30m/2d or ISO timestamp")
    events_parser.add_argument("--stage", default=None, help="Filter by event stage, e.g. preflight/proxy/runtime")
    events_parser.add_argument("--json", action="store_true", help="Output JSON")

    # qise protect
    protect_parser = subparsers.add_parser("protect", help="Protect an installed Agent")
    protect_parser.add_argument("agent", help="Agent name: codex, openclaw, claude-code, opencode, workbuddy, or custom")
    protect_parser.add_argument("--base-url", default="", help="Upstream/manual base URL for custom Agents")
    protect_parser.add_argument("--experimental", action="store_true", help="Allow experimental integrations")

    # qise restore
    restore_parser = subparsers.add_parser("restore", help="Restore Agent config modified by Qise")
    restore_parser.add_argument("agent", help="Agent name or 'all'")

    # qise run
    run_parser = subparsers.add_parser("run", help="Run an Agent under Qise Runtime Observer")
    run_parser.add_argument("--agent", required=True, help="Agent name for runtime evidence correlation")
    run_parser.add_argument("--cwd", default=None, help="Working directory for the Agent command")
    run_parser.add_argument("--poll-interval", type=float, default=1.0, help="Observer polling interval in seconds")
    run_parser.add_argument(
        "--no-file-snapshot",
        action="store_true",
        help="Disable before/after working directory diff",
    )
    run_parser.add_argument("run_command", nargs=argparse.REMAINDER, help="Command to run after --")

    # qise stop
    subparsers.add_parser("stop", help="Stop Qise managed services")

    # qise slm
    slm_parser = subparsers.add_parser("slm", help="Manage Qise local SLM protection")
    slm_subparsers = slm_parser.add_subparsers(dest="slm_command")
    slm_start = slm_subparsers.add_parser("start", help="Start and configure Qise second-layer SLM")
    slm_start.add_argument("--model", default="qwen3:4b", help="SLM model name (default: qwen3:4b)")
    slm_start.add_argument(
        "--base-url",
        default="http://localhost:11434/v1",
        help="OpenAI-compatible SLM base URL (default: local Ollama)",
    )
    slm_start.add_argument("--api-key", default="", help="Optional API key for a custom SLM endpoint")
    slm_start.add_argument("--timeout-ms", type=int, default=10000, help="SLM request timeout in milliseconds")
    slm_start.add_argument("--no-install", action="store_true", help="Do not auto-install Ollama if missing")
    slm_start.add_argument("--no-pull", action="store_true", help="Do not auto-pull the Ollama model if missing")
    slm_start.add_argument("--no-verify", action="store_true", help="Write config without verifying chat/completions")
    slm_stop = slm_subparsers.add_parser("stop", help="Disable Qise second-layer SLM")
    slm_stop.add_argument(
        "--keep-server",
        action="store_true",
        help="Disable Qise SLM but leave local model server running",
    )
    slm_status = slm_subparsers.add_parser("status", help="Show Qise SLM status")
    slm_status.add_argument("--json", action="store_true", help="Output JSON")

    # qise scan
    scan_parser = subparsers.add_parser("scan", help="Preflight scan Agent assets")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON")
    scan_parser.add_argument("--agents", default="", help="Comma-separated Agent names for automatic scan")
    scan_parser.add_argument(
        "--include-missing",
        action="store_true",
        help="Also scan known Agents that are not installed",
    )
    scan_parser.add_argument("--no-skills", action="store_true", help="Skip Agent files/skills during automatic scan")
    scan_parser.add_argument("--no-mcp", action="store_true", help="Skip MCP config candidates during automatic scan")
    scan_parser.add_argument(
        "--no-agent-config",
        action="store_true",
        help="Skip Agent config checks during automatic scan",
    )
    scan_subparsers = scan_parser.add_subparsers(dest="scan_command")
    scan_all = scan_subparsers.add_parser("all", help="Automatically scan all detected Agents")
    scan_all.add_argument("--json", action="store_true", help="Output JSON")
    scan_all.add_argument("--agents", default="", help="Comma-separated Agent names to scan")
    scan_all.add_argument(
        "--include-missing",
        action="store_true",
        help="Also scan known Agents that are not installed",
    )
    scan_all.add_argument("--no-skills", action="store_true", help="Skip Agent files/skills")
    scan_all.add_argument("--no-mcp", action="store_true", help="Skip MCP config candidates")
    scan_all.add_argument("--no-agent-config", action="store_true", help="Skip Agent config checks")
    scan_agent = scan_subparsers.add_parser("agent", help="Automatically scan one detected Agent")
    scan_agent.add_argument("agent", help="Agent name: codex, openclaw, claude-code")
    scan_agent.add_argument("--json", action="store_true", help="Output JSON")
    scan_agent.add_argument("--no-skills", action="store_true", help="Skip Agent files/skills")
    scan_agent.add_argument("--no-mcp", action="store_true", help="Skip MCP config candidates")
    scan_agent.add_argument("--no-agent-config", action="store_true", help="Skip Agent config checks")
    scan_mcp = scan_subparsers.add_parser("mcp", help="Scan an MCP config file")
    scan_mcp.add_argument("path", help="Path to MCP JSON/YAML config")
    scan_mcp.add_argument("--json", action="store_true", help="Output JSON")
    scan_skill = scan_subparsers.add_parser("skill", help="Scan a Skill directory or file")
    scan_skill.add_argument("path", help="Path to Skill directory or file")
    scan_skill.add_argument("--json", action="store_true", help="Output JSON")
    scan_agent_config = scan_subparsers.add_parser("agent-config", help="Scan an installed Agent config")
    scan_agent_config.add_argument("agent", help="Agent name: codex, openclaw, claude-code")
    scan_agent_config.add_argument("--json", action="store_true", help="Output JSON")

    # qise adapters
    adapters_parser = subparsers.add_parser("adapters", help="Framework adapter integration")
    adapters_subparsers = adapters_parser.add_subparsers(dest="adapter_name")

    # qise adapters nanobot
    adapters_subparsers.add_parser("nanobot", help="Show Nanobot integration code snippet")

    # qise adapters hermes
    adapters_subparsers.add_parser("hermes", help="Show Hermes integration code snippet")

    # qise adapters nexau
    adapters_subparsers.add_parser("nexau", help="Show NexAU integration code snippet")

    # qise adapters langgraph
    adapters_subparsers.add_parser("langgraph", help="Show LangGraph integration code snippet")

    # qise adapters openai-agents
    adapters_subparsers.add_parser("openai-agents", help="Show OpenAI Agents SDK integration code snippet")

    # qise bridge
    from qise.bridge.cli import add_bridge_parser
    add_bridge_parser(subparsers)

    return parser


def _summarize_guard_results_for_event(result: Any) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for gr in result.results:
        summary: dict[str, Any] = {
            "guard": gr.guard_name,
            "verdict": gr.verdict,
            "confidence": gr.confidence,
            "message": gr.message,
            "evidence_kind": gr.evidence_kind,
        }
        if gr.risk_attribution:
            summary["risk_source"] = gr.risk_attribution.risk_source
        summaries.append(summary)
    return summaries


def _record_cli_check_event(args: argparse.Namespace, result: Any, tool_args: dict[str, Any]) -> None:
    if not result.should_block and not result.warnings:
        return
    try:
        from qise.product.events import record_guard_event

        record_guard_event(
            stage=args.pipeline,
            source="cli-check",
            verdict="block" if result.should_block else "warn",
            action_type="tool_call",
            action_name=args.tool_name,
            resource=tool_args,
            blocked_by=result.blocked_by,
            warnings=result.warnings,
            guard_results=_summarize_guard_results_for_event(result),
        )
    except Exception:
        # Product event logging must never change the guard decision.
        pass


def _get_shield(config_path: str | None = None):
    from qise.core.shield import Shield
    from qise.product.policy import refresh_guard_policy
    from qise.product.status import load_config

    config, _ = load_config(config_path)
    shield = Shield(config)
    refresh_guard_policy(shield)
    return shield


def _cmd_check(args: argparse.Namespace) -> int:
    shield = _get_shield(args.config)

    try:
        tool_args = json.loads(args.tool_args)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in tool_args: {e}", file=sys.stderr)
        return 1

    from qise.core.models import GuardContext

    ctx = GuardContext(
        tool_name=args.tool_name,
        tool_args=tool_args,
        session_id=args.session_id,
    )

    result = shield.check_sync(ctx, pipeline_kind=args.pipeline)

    response: dict = {
        "verdict": result.verdict,
        "blocked_by": result.blocked_by,
        "warnings": result.warnings,
    }
    for gr in result.results:
        if gr.risk_attribution:
            response["risk_attribution"] = gr.risk_attribution.model_dump()
            break

    _record_cli_check_event(args, result, tool_args)
    print(json.dumps(response, indent=2))
    return 1 if result.should_block else 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        from qise.mcp_server import main as mcp_main
    except ImportError:
        print('MCP support is optional. Install it with: pip install "qise[mcp]"', file=sys.stderr)
        return 2
    asyncio.run(mcp_main(config_path=args.config))
    return 0


def _cmd_context(args: argparse.Namespace) -> int:
    shield = _get_shield(args.config)

    tool_args = None
    if args.tool_args:
        try:
            tool_args = json.loads(args.tool_args)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON in --tool-args: {e}", file=sys.stderr)
            return 1

    context_text = shield.get_security_context(args.tool_name, tool_args)
    if context_text:
        print(context_text)
    return 0


def _cmd_guards(args: argparse.Namespace) -> int:
    from qise.product.policy import guard_rows, set_guard_mode

    if args.set:
        try:
            set_guard_mode(*args.set)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    shield = _get_shield(args.config)
    if args.json:
        print(json.dumps(guard_rows(shield), indent=2))
        return 0

    # Header
    print(f"{'Name':<20} {'Pipeline':<10} {'Strategy':<12} {'Mode':<10}")
    print("-" * 52)

    ingress_names = {g.name for g in shield.pipeline.ingress.guards}
    egress_names = {g.name for g in shield.pipeline.egress.guards}
    output_names = {g.name for g in shield.pipeline.output.guards}

    for guard in shield.pipeline.all_guards:
        if guard.name in ingress_names:
            pipeline = "ingress"
        elif guard.name in egress_names:
            pipeline = "egress"
        elif guard.name in output_names:
            pipeline = "output"
        else:
            pipeline = "unknown"

        mode = shield.config.guard_mode(guard.name)
        print(f"{guard.name:<20} {pipeline:<10} {guard.primary_strategy:<12} {mode:<10}")

    print(f"\nTotal: {len(shield.pipeline.all_guards)} guards")

    if args.metrics:
        metrics = shield.get_metrics()
        print("\n--- Metrics ---")
        print(json.dumps(metrics, indent=2, default=str))

    return 0


def _cmd_version(args: argparse.Namespace) -> int:
    from qise import __version__ as v

    print(f"qise {v}")
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    """Start the HTTP proxy server."""
    if not args.proxy_command:
        print("Error: specify a proxy subcommand (e.g., 'qise proxy start')", file=sys.stderr)
        return 1

    if args.proxy_command != "start":
        print(f"Error: unknown proxy subcommand '{args.proxy_command}'", file=sys.stderr)
        return 1

    from qise.proxy.config import ProxyConfig
    from qise.proxy.server import ProxyServer

    shield = _get_shield(args.config)
    proxy_config = ProxyConfig.from_shield_config(shield.config)

    # Apply CLI overrides
    if args.port is not None:
        proxy_config.listen_port = args.port
    if args.host is not None:
        proxy_config.listen_host = args.host
    if args.upstream is not None:
        proxy_config.upstream_base_url = args.upstream.rstrip("/")
        if args.upstream_key is None and "anthropic" in proxy_config.upstream_base_url.lower():
            import os

            proxy_config.upstream_api_key = (
                os.getenv("ANTHROPIC_API_KEY")
                or os.getenv("ANTHROPIC_AUTH_TOKEN")
                or proxy_config.upstream_api_key
            )
    if args.upstream_key is not None:
        proxy_config.upstream_api_key = args.upstream_key
    if args.no_inject:
        proxy_config.inject_security_context = False
    if args.observe:
        proxy_config.block_on_guard_block = False

    if not proxy_config.upstream_base_url:
        print(
            "Error: proxy upstream is not configured. Use --upstream, "
            "integration.proxy.upstream_url, QISE_PROXY_UPSTREAM_URL, OPENAI_API_BASE, or ANTHROPIC_BASE_URL.",
            file=sys.stderr,
        )
        return 2

    server = ProxyServer(shield, proxy_config)

    # Config hot-reload (enabled by default, disabled with --no-reload)
    watcher = None
    if not args.no_reload:
        try:
            from qise.core.config_watcher import ConfigWatcher
            config_path = args.config or "shield.yaml"
            from pathlib import Path
            if Path(config_path).exists():
                watcher = ConfigWatcher(config_path, shield.reconfigure)
        except Exception:
            pass  # Non-critical: hot-reload is optional

    async def _run() -> None:
        if watcher:
            watcher.start()
        await server.start()
        print(f"Qise proxy running on {proxy_config.listen_host}:{proxy_config.listen_port}")
        print(f"Upstream: {proxy_config.upstream_base_url or '(not configured)'}")
        if watcher and watcher.is_running:
            print(f"Config hot-reload: watching {watcher.config_path}")
        print("Press Ctrl+C to stop")
        try:
            # Run forever until interrupted

            loop = asyncio.get_event_loop()
            stop_event = asyncio.Event()

            def _signal_handler() -> None:
                stop_event.set()

            from qise.product.service import install_stop_handlers
            install_stop_handlers(loop, stop_event)

            await stop_event.wait()
        finally:
            await server.stop()
            if watcher:
                watcher.stop()

    with suppress(KeyboardInterrupt):
        asyncio.run(_run())
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    """Generate a shield.yaml configuration file."""
    from pathlib import Path

    config_path = Path("shield.yaml")
    if config_path.exists() and not args.force:
        print(f"Error: {config_path} already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    content = _default_shield_yaml()
    config_path.write_text(content)
    print(f"Created {config_path}")
    print("Edit this file to customize guard modes, model endpoints, and data paths.")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    from qise.product.doctor import render_doctor, run_doctor

    report = run_doctor(args.config)
    print(render_doctor(report, json_output=args.json))
    return 1 if report.get("errors") else 0


def _cmd_status(args: argparse.Namespace) -> int:
    from qise.product.status import get_status, render_status

    status = get_status(args.config)
    print(render_status(status, json_output=args.json))
    return 0


def _cmd_events(args: argparse.Namespace) -> int:
    from qise.product.events import format_events, load_events

    events = load_events(limit=args.limit, since=args.since, stage=args.stage)
    if args.json:
        print(json.dumps(events, indent=2, sort_keys=True))
    else:
        print(format_events(events))
    return 0


def _cmd_protect(args: argparse.Namespace) -> int:
    from qise.product.agents import protect_agent

    try:
        code, message = protect_agent(
            args.agent,
            base_url=args.base_url,
            experimental=args.experimental,
            config_path=args.config,
        )
    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    print(message)
    return code


def _cmd_restore(args: argparse.Namespace) -> int:
    from qise.product.agents import restore_agent

    code, message = restore_agent(args.agent)
    print(message)
    return code


def _cmd_run(args: argparse.Namespace) -> int:
    from qise.product.runtime import run_observed_command

    command = list(args.run_command or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("Error: provide an Agent command after --, e.g. qise run --agent codex -- codex", file=sys.stderr)
        return 1

    print(
        f"Qise Runtime Observer: agent={args.agent}, command={' '.join(command)}",
        file=sys.stderr,
    )
    try:
        result = run_observed_command(
            agent_name=args.agent,
            command=command,
            cwd=args.cwd,
            poll_interval_s=args.poll_interval,
            snapshot_files=not args.no_file_snapshot,
        )
    except Exception as exc:
        print(f"Error: runtime observer failed: {exc}", file=sys.stderr)
        return 1

    print(
        "Qise Runtime Observer: "
        f"exit={result.returncode}, correlation_id={result.correlation_id}, "
        f"processes={len(result.process_tree)}, "
        f"network={len(result.network)}, "
        f"file_changes={sum(len(result.file_changes.get(key, [])) for key in ('added', 'modified', 'deleted'))}",
        file=sys.stderr,
    )
    return result.returncode


def _cmd_stop(args: argparse.Namespace) -> int:
    from qise.product.agents import restore_agent
    from qise.product.service import stop_managed_services

    try:
        code, message = restore_agent("all")
        if code:
            print(message, file=sys.stderr)
            return code
    except (OSError, ValueError) as exc:
        print(f"Could not restore Agent settings; Qise was left running: {exc}", file=sys.stderr)
        return 1
    stopped, notes = stop_managed_services()
    if not stopped and not notes:
        print(
            "No Qise managed background services are recorded. "
            "If proxy/bridge is running in the foreground, stop it with Ctrl+C in that terminal."
        )
        return 0
    for line in stopped:
        print(line)
    for line in notes:
        print(line)
    return 1 if notes else 0


def _cmd_slm(args: argparse.Namespace) -> int:
    from qise.product.slm import render_slm_status, slm_status, start_slm, stop_slm

    if not args.slm_command:
        print("Error: specify an SLM command: qise slm start|stop|status", file=sys.stderr)
        return 1

    if args.slm_command == "start":
        result = start_slm(
            config_path=args.config,
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            timeout_ms=args.timeout_ms,
            no_install=args.no_install,
            no_pull=args.no_pull,
            no_verify=args.no_verify,
        )
        print(result.message)
        return result.code

    if args.slm_command == "stop":
        result = stop_slm(config_path=args.config, keep_server=args.keep_server)
        print(result.message)
        return result.code

    if args.slm_command == "status":
        print(render_slm_status(slm_status(config_path=args.config), json_output=args.json))
        return 0

    print(f"Error: unknown SLM command '{args.slm_command}'", file=sys.stderr)
    return 1


def _cmd_scan(args: argparse.Namespace) -> int:
    from pathlib import Path

    from qise.product.scan import (
        iter_scan_reports,
        record_scan_event,
        render_collection,
        render_report,
        scan_agent_assets,
        scan_agent_config,
        scan_all_agent_assets,
        scan_mcp,
        scan_skill,
    )

    def _selected_agents() -> list[str] | None:
        raw = getattr(args, "agents", "") or ""
        values = [item.strip() for item in raw.split(",") if item.strip()]
        return values or None

    def _scan_options() -> dict[str, bool]:
        return {
            "include_skills": not getattr(args, "no_skills", False),
            "include_mcp": not getattr(args, "no_mcp", False),
            "include_agent_config": not getattr(args, "no_agent_config", False),
        }

    if not any(_scan_options().values()) and args.scan_command in {None, "all", "agent"}:
        print("Error: at least one automatic scan category must be enabled.", file=sys.stderr)
        return 1

    try:
        if args.scan_command in {None, "all"}:
            collection = scan_all_agent_assets(
                agents=_selected_agents(),
                include_missing=getattr(args, "include_missing", False),
                **_scan_options(),
            )
            for report in iter_scan_reports(collection):
                record_scan_event(report)
            print(render_collection(collection, json_output=args.json))
            return 1 if collection.verdict == "block" else 0
        if args.scan_command == "agent":
            collection = scan_agent_assets(args.agent, **_scan_options())
            for report in iter_scan_reports(collection):
                record_scan_event(report)
            print(render_collection(collection, json_output=args.json))
            return 1 if collection.verdict == "block" else 0
        if args.scan_command == "mcp":
            report = scan_mcp(Path(args.path))
        elif args.scan_command == "skill":
            report = scan_skill(Path(args.path))
        elif args.scan_command == "agent-config":
            report = scan_agent_config(args.agent)
        else:
            print(f"Error: unknown scan target '{args.scan_command}'", file=sys.stderr)
            return 1
        record_scan_event(report)
        print(render_report(report, json_output=args.json))
        return 1 if report.verdict == "block" else 0
    except FileNotFoundError:
        print(f"Error: path not found: {args.path}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: scan failed: {exc}", file=sys.stderr)
        return 1


def _cmd_agents(args: argparse.Namespace) -> int:
    from qise.product.agents import detect_agents, render_agents

    agents = detect_agents(include_missing=args.include_missing)
    print(render_agents(agents, json_output=args.json))
    return 0


def _cmd_bridge(args: argparse.Namespace) -> int:
    """Start the Python Bridge server."""
    from qise.bridge.cli import cmd_bridge
    return cmd_bridge(args)


def _default_shield_yaml() -> str:
    """Return the default shield.yaml content."""
    return """\
version: "1.0"

# Integration mode: proxy | mcp | sdk
integration:
  mode: proxy
  proxy:
    port: 8822
    auto_takeover: true
    crash_recovery: true

# Model configuration (leave empty for rule-only mode)
models:
  slm:
    base_url: ""
    model: ""
    timeout_ms: 10000
  llm:
    base_url: ""
    model: ""
    timeout_ms: 5000
  embedding:
    base_url: ""
    model: ""

# Guard configuration
guards:
  enabled:
    - prompt
    - command
    - credential
    - reasoning
    - filesystem
    - network
    - exfil
    - resource
    - audit
    - tool_sanity
    - context
    - output
    - tool_policy
    - supply_chain
  config:
    # AI-first guards default to observe (need SLM for reliable detection)
    prompt:
      mode: observe
    reasoning:
      mode: observe
    exfil:
      mode: observe
    tool_sanity:
      mode: observe
    context:
      mode: observe
    supply_chain:
      mode: observe
    output:
      mode: observe
    audit:
      mode: observe
    resource:
      mode: observe

    # Rules-based guards default to enforce (low false-positive rate)
    # Uncomment to change:
    # command:
    #   mode: enforce
    # filesystem:
    #   mode: enforce
    # network:
    #   mode: enforce
    # credential:
    #   mode: enforce
    # tool_policy:
    #   mode: enforce

# Data paths
data:
  threat_patterns_dir: "./data/threat_patterns"
  security_contexts_dir: "./data/security_contexts"
  baselines_dir: "./data/baselines"

# Logging
logging:
  level: INFO
  format: json
  output: stderr
"""


def _nexau_snippet() -> str:
    return """\
# NexAU Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Add the middleware to your NexAU Agent:

from qise import Shield
from qise.adapters.nexau import QiseNexauMiddleware

shield = Shield.from_config()
middleware = QiseNexauMiddleware(shield)

# Register with NexAU Agent
agent = NexAUAgent(middlewares=[middleware])

# The middleware will:
#   - before_agent: check agent startup args
#   - after_agent: check agent output for leaks
#   - before_model: inject SecurityContext into messages
#   - after_model: check reasoning + filter dangerous tool calls
#   - before_tool: secondary egress check before tool execution
#   - after_tool: check tool results for injection
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        prompt:
#          mode: enforce    # Block injection attempts
"""


def _langgraph_snippet() -> str:
    return """\
# LangGraph Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Wrap your tools with Qise security checks:

from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)

# Wrap tools for LangGraph ToolNode
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]

# Or use async version for async tools
safe_tools = [wrapper.awrap_tool_call(tool) for tool in my_async_tools]

# Add pre-model hook for SecurityContext injection
graph.add_node("pre_model", wrapper.qise_pre_model_hook)

# The wrapper will:
#   - wrap_tool_call: check tool args, raise ToolException on block
#   - awrap_tool_call: async version of wrap_tool_call
#   - qise_pre_model_hook: inject SecurityContext into state messages
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        filesystem:
#          mode: enforce    # Block path traversal
"""


def _openai_agents_snippet() -> str:
    return """\
# OpenAI Agents SDK Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Add guardrails to your Agent:

from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)

# Register with OpenAI Agent
agent = Agent(
    name="my-agent",
    guardrails=[
        guardrails.input_guardrail,
        guardrails.output_guardrail,
    ],
)

# Wrap tools with tool guardrails
for tool in tools:
    tool = guardrails.wrap_tool(tool)

# The guardrails will:
#   - input_guardrail: check user input for injection
#   - output_guardrail: check agent output for leaks
#   - tool_input_guardrail: check tool call arguments
#   - tool_output_guardrail: check tool results for injection
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        credential:
#          mode: enforce    # Block credential leaks
"""


def _cmd_adapters(args: argparse.Namespace) -> int:
    """Show adapter integration code snippets."""
    if not args.adapter_name:
        # List all adapters
        print("Available adapters:\n")
        print("  nanobot       — Nanobot AgentHook integration (recommended)")
        print("  hermes        — Hermes Plugin hook integration")
        print("  nexau         — NexAU Middleware integration (6 hooks)")
        print("  langgraph     — LangGraph tool wrapper integration")
        print("  openai-agents — OpenAI Agents SDK guardrails integration")
        print("\nUse 'qise adapters <name>' for integration code snippet.")
        return 0

    snippets = {
        "nanobot": _nanobot_snippet(),
        "hermes": _hermes_snippet(),
        "nexau": _nexau_snippet(),
        "langgraph": _langgraph_snippet(),
        "openai-agents": _openai_agents_snippet(),
    }

    snippet = snippets.get(args.adapter_name)
    if snippet is None:
        print(f"Error: unknown adapter '{args.adapter_name}'", file=sys.stderr)
        return 1

    print(snippet)
    return 0


def _nanobot_snippet() -> str:
    return """\
# Nanobot Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Add the hook to your AgentLoop:

from qise import Shield
from qise.adapters.nanobot import QiseNanobotHook

shield = Shield.from_config()
hook = QiseNanobotHook(shield)

# Pass the hook to your AgentLoop
loop = AgentLoop(hooks=[hook])

# The hook will:
#   - before_execute_tools: check each tool call, remove dangerous ones
#   - after_iteration: check tool results for injection, output for leaks
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        prompt:
#          mode: enforce    # Block injection attempts
#        credential:
#          mode: enforce    # Block credential leaks
#
# Default mode is "observe" (log only, never block).
"""


def _hermes_snippet() -> str:
    return """\
# Hermes Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Create a Hermes plugin:
#
#    plugins/qise/plugin.yaml:
#      name: qise-security
#      provides_hooks: [pre_tool_call, post_tool_call, transform_tool_result, post_llm_call]
#
#    plugins/qise/__init__.py:

from qise import Shield
from qise.adapters.hermes import QiseHermesAdapter

def register(ctx):
    shield = Shield.from_config()
    adapter = QiseHermesAdapter(shield)
    # Wrap tools with security checks before passing to Agent
    # Note: Hermes-ai does not have a plugin/hook system,
    # so use adapter.wrap_tool() on each tool function.

# The adapter will:
#   - wrap_tool: block dangerous tool calls (raises RuntimeError)
#   - check_agent_output: check LLM output for credential/PII leaks
# For full protection, use Proxy mode instead.
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        prompt:
#          mode: enforce    # Block injection attempts
#        credential:
#          mode: enforce    # Block credential leaks
#
# Default mode is "observe" (log only, never block).
"""


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help(sys.stderr)
        sys.exit(1)

    dispatch = {
        "check": _cmd_check,
        "serve": _cmd_serve,
        "proxy": _cmd_proxy,
        "bridge": _cmd_bridge,
        "init": _cmd_init,
        "adapters": _cmd_adapters,
        "context": _cmd_context,
        "guards": _cmd_guards,
        "doctor": _cmd_doctor,
        "status": _cmd_status,
        "agents": _cmd_agents,
        "events": _cmd_events,
        "protect": _cmd_protect,
        "restore": _cmd_restore,
        "run": _cmd_run,
        "stop": _cmd_stop,
        "slm": _cmd_slm,
        "scan": _cmd_scan,
        "version": _cmd_version,
    }

    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
