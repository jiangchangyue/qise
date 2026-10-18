"""Bridge CLI — `qise bridge start` command.

Starts the Python Bridge HTTP server for Guard Pipeline analysis.
Receives guard check requests from the Rust Proxy and returns decisions.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logger = logging.getLogger("qise.bridge.cli")


def add_bridge_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the `bridge` subcommand to the CLI parser."""
    bridge_parser = subparsers.add_parser("bridge", help="Bridge server commands")
    bridge_subparsers = bridge_parser.add_subparsers(dest="bridge_command")

    # qise bridge start
    start_parser = bridge_subparsers.add_parser("start", help="Start Python Bridge server")
    start_parser.add_argument("--port", type=int, default=8823, help="Listen port (default: 8823)")
    start_parser.add_argument("--host", default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    start_parser.add_argument("--config", default=argparse.SUPPRESS, help="Path to shield.yaml")


def cmd_bridge_start(args: argparse.Namespace) -> int:
    """Handle `qise bridge start` — start the Bridge HTTP server."""
    from qise.bridge.server import BridgeServer
    from qise.cli import _get_shield
    shield = _get_shield(args.config)
    server = BridgeServer(
        shield=shield,
        port=args.port,
        host=args.host,
    )

    # Configure logging
    log_level = shield.config.logging.level if hasattr(shield.config, "logging") else "INFO"
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    async def _run() -> None:
        await server.start()
        print(f"Qise bridge running on {args.host}:{args.port}")
        print("Press Ctrl+C to stop")
        try:
            loop = asyncio.get_event_loop()
            stop_event = asyncio.Event()

            def _signal_handler() -> None:
                stop_event.set()

            from qise.product.service import install_stop_handlers
            install_stop_handlers(loop, stop_event)

            await stop_event.wait()
        finally:
            await server.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    return 0


def cmd_bridge(args: argparse.Namespace) -> int:
    """Handle `qise bridge` subcommands."""
    if not args.bridge_command:
        print("Error: specify a bridge subcommand (e.g., 'qise bridge start')", file=sys.stderr)
        return 1

    if args.bridge_command == "start":
        return cmd_bridge_start(args)

    print(f"Error: unknown bridge subcommand '{args.bridge_command}'", file=sys.stderr)
    return 1
