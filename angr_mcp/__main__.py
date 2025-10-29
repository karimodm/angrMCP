"""Command-line entry point for running the angr MCP server."""

from __future__ import annotations

import argparse
import logging

from mcp.server.fastmcp.utilities.logging import configure_logging

from .server import mcp


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch the angr MCP server.")
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Shortcut for --log-level=DEBUG.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse"),
        default="stdio",
        help="Transport mode for the MCP server.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface for SSE transport (ignored for stdio).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Port for SSE transport (ignored for stdio).",
    )
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else getattr(logging, args.log_level.upper(), logging.WARN)
    log_level_name = logging.getLevelName(log_level)
    configure_logging(log_level_name)

    logger = logging.getLogger("angr_mcp")
    logger.info("Starting angr MCP server using %s transport", args.transport)

    if args.transport == "sse":
        mcp.settings.log_level = log_level_name
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        try:
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
