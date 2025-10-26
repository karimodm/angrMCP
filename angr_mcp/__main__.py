"""Command-line entry point for running the angr MCP server over stdio."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

import mcp.server.stdio
from mcp import types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from .server import AngrMCPServer


@dataclass(frozen=True)
class ToolSpec:
    """Describes a tool exposed by the MCP server."""

    name: str
    method: Callable[..., Any]
    description: str
    input_schema: Optional[Dict[str, Any]]
    output_schema: Optional[Dict[str, Any]]
    model: types.Tool


def _discover_tool_specs(server: AngrMCPServer, schema_dir: Path) -> Mapping[str, ToolSpec]:
    """Collect callable handlers on the angr MCP server."""

    specs: Dict[str, ToolSpec] = {}
    for name in sorted(dir(server)):
        if name.startswith("_"):
            continue
        attr = getattr(server, name)
        if not callable(attr):
            continue

        doc = inspect.getdoc(attr) or f"{name} handler"
        input_schema = _load_schema(schema_dir / f"{name}.request.json")
        output_schema = _load_schema(schema_dir / f"{name}.response.json")

        effective_input = input_schema or {"type": "object"}
        effective_output = output_schema or {"type": "object"}

        tool_kwargs: Dict[str, Any] = {
            "name": name,
            "description": doc.strip(),
            "inputSchema": effective_input,
            "outputSchema": effective_output,
        }

        specs[name] = ToolSpec(
            name=name,
            method=attr,
            description=doc.strip(),
            input_schema=input_schema,
            output_schema=output_schema,
            model=types.Tool(**tool_kwargs),
        )

    return specs


def _load_schema(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def _resolve_version(project_root: Path) -> str:
    try:
        from importlib.metadata import version

        return version("angr-mcp")
    except Exception:  # pylint:disable=broad-except
        pass

    try:
        import tomllib

        pyproject = project_root / "pyproject.toml"
        if pyproject.is_file():
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            return data.get("project", {}).get("version", "0.0.0")
    except Exception:  # pylint:disable=broad-except
        pass

    return "0.0.0"


async def _serve_stdio(server: AngrMCPServer, tools: Mapping[str, ToolSpec], *, version: str) -> None:
    """Run the MCP server using stdio transport."""

    logger = logging.getLogger("angr_mcp")
    mcp_server = Server("angr-mcp")

    @mcp_server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        logger.debug("Listing %d tools", len(tools))
        return [spec.model for spec in tools.values()]

    @mcp_server.call_tool()
    async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> Any:
        if name not in tools:
            raise ValueError(f"Unknown tool: {name}")

        spec = tools[name]
        params = arguments or {}
        try:
            if inspect.iscoroutinefunction(spec.method):
                return await spec.method(**params)  # type: ignore[misc]
            return await asyncio.to_thread(spec.method, **params)
        except TypeError as exc:
            raise ValueError(f"Invalid arguments for {name}: {exc}") from exc

    init_options = InitializationOptions(
        server_name="angr-mcp",
        server_version=version,
        capabilities=mcp_server.get_capabilities(
            notification_options=NotificationOptions(),
            experimental_capabilities={},
        ),
    )

    logger.info("Starting angr MCP stdio server with %d registered tools", len(tools))
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await mcp_server.run(read_stream, write_stream, init_options)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch the angr MCP server over stdio.")
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
        "--schema-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "schemas",
        help="Directory containing JSON Schemas for tool inputs/outputs.",
    )
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    server = AngrMCPServer()
    schema_dir = args.schema_dir.resolve()
    project_root = Path(__file__).resolve().parent.parent

    tools = _discover_tool_specs(server, schema_dir)
    if not tools:
        raise RuntimeError("No public tools found on AngrMCPServer.")

    version = _resolve_version(project_root)
    asyncio.run(_serve_stdio(server, tools, version=version))


if __name__ == "__main__":
    main()
