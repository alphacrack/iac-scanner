"""MCP server — expose iac-scanner as tools to Claude Desktop / Cursor / Continue.dev.

In this mode iac-scanner does NOT call any LLM itself. The MCP host (Claude Desktop,
Cursor, Zed, Continue.dev, etc.) calls our tools, and the host's own LLM reasons
over the results. That's why this mode is *keyless* for iac-scanner.

Tools exposed:
  - scan_iac_path       : read IaC files at a path, with secret redaction + skip-list
  - run_rule_engine     : run Checkov if installed, returning framework-mapped findings
  - list_iac_types      : introspection — what IaC formats this server supports
  - iac_analysis_prompt : returns a ready-to-use analysis prompt template

Entry point: `iac-scan-mcp` (see pyproject.toml `[project.scripts]`).

Install: `pip install iac-scanner[mcp]`
Run standalone: `iac-scan-mcp`
Configure Claude Desktop: add to `mcpServers` in `claude_desktop_config.json`:
    {
      "mcpServers": {
        "iac-scanner": {
          "command": "iac-scan-mcp"
        }
      }
    }
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from iac_scanner import __version__
from iac_scanner.factory import create_scanner
from iac_scanner.orchestration.tasks import ANALYSIS_SYSTEM, ANALYSIS_USER, FIX_SYSTEM, FIX_USER
from iac_scanner.rules import is_available, run_rule_engine
from iac_scanner.scanners._filters import InputTooLargeError


def _import_mcp() -> Any:
    """Import the MCP SDK lazily so the rest of iac-scanner doesn't hard-depend on it."""
    try:
        import mcp.server.stdio
        from mcp.server import NotificationOptions, Server
        from mcp.server.models import InitializationOptions
        from mcp.types import TextContent, Tool

        return {
            "mcp_module": mcp,
            "Server": Server,
            "InitializationOptions": InitializationOptions,
            "NotificationOptions": NotificationOptions,
            "Tool": Tool,
            "TextContent": TextContent,
        }
    except ImportError as e:  # pragma: no cover — covered by mcp[]-not-installed path
        raise SystemExit(
            "The MCP Python SDK is not installed. Run `pip install iac-scanner[mcp]` to enable the MCP server."
        ) from e


def _tool_schemas(Tool: Any) -> list[Any]:
    """Return the list of MCP tool definitions exposed by this server."""
    return [
        Tool(
            name="scan_iac_path",
            description=(
                "Read Infrastructure-as-Code at the given path. Supports Terraform "
                "(directory with main.tf) and AWS CDK (directory with index.ts/js). "
                "Secrets are redacted and known secret files (tfstate, tfvars, .env) "
                "are skipped. Input is size-capped at 200KB by default. Returns the "
                "raw content plus metadata (iac_type, entry_path, file list)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to an IaC directory or entry file.",
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="run_rule_engine",
            description=(
                "Run the Checkov rule engine against a path (if installed). Returns "
                "deterministic, framework-mapped findings with CWE/CIS/NIST tags. "
                "Safe to combine with the host LLM's own analysis for hybrid coverage."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to scan with Checkov."},
                    "iac_type": {
                        "type": "string",
                        "enum": ["terraform", "cdk"],
                        "description": "IaC type; controls Checkov --framework.",
                    },
                },
                "required": ["path", "iac_type"],
            },
        ),
        Tool(
            name="list_iac_types",
            description="List the IaC formats this server can scan.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="iac_analysis_prompt",
            description=(
                "Return ready-to-use analysis + fix prompt templates. Host LLMs can "
                "apply these prompts to content returned by scan_iac_path to produce "
                "findings without iac-scanner needing an API key."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


async def _call_tool(
    name: str,
    arguments: dict[str, Any],
    TextContent: Any,
) -> list[Any]:
    """Dispatch an MCP tool call. Returns a list of content parts for the host."""
    if name == "scan_iac_path":
        result = _tool_scan_iac_path(arguments.get("path", ""))
    elif name == "run_rule_engine":
        result = _tool_run_rule_engine(
            arguments.get("path", ""),
            arguments.get("iac_type", ""),
        )
    elif name == "list_iac_types":
        result = {"supported": ["terraform", "cdk"], "version": __version__}
    elif name == "iac_analysis_prompt":
        result = {
            "analysis_system": ANALYSIS_SYSTEM,
            "analysis_user_template": ANALYSIS_USER,
            "fix_system": FIX_SYSTEM,
            "fix_user_template": FIX_USER,
        }
    else:
        result = {"error": f"Unknown tool: {name}"}
    return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


def _tool_scan_iac_path(raw_path: str) -> dict[str, Any]:
    """Body of the scan_iac_path tool. Returns JSON-friendly dict."""
    if not raw_path:
        return {"error": "path is required"}
    path = Path(raw_path).expanduser()
    if not path.exists():
        return {"error": f"Path not found: {path}"}
    try:
        scanner = create_scanner(path)
        scan_result = scanner.scan()
    except ValueError as e:
        return {"error": str(e)}
    except InputTooLargeError as e:
        return {"error": str(e)}
    return {
        "iac_type": scan_result.iac_type,
        "entry_path": str(scan_result.entry_path),
        "raw_content": scan_result.raw_content,
        "metadata": scan_result.metadata,
    }


def _tool_run_rule_engine(raw_path: str, iac_type: str) -> dict[str, Any]:
    """Body of the run_rule_engine tool."""
    if not raw_path or not iac_type:
        return {"error": "path and iac_type are required"}
    if not is_available("checkov"):
        return {
            "error": (
                "Checkov is not installed. Install with "
                "`pip install iac-scanner[rules]` in the environment running iac-scan-mcp."
            )
        }
    try:
        findings = run_rule_engine(Path(raw_path), iac_type, engine="checkov")
    except Exception as e:  # noqa: BLE001
        return {"error": f"Checkov failed: {e}"}
    return {
        "findings": [f.model_dump(exclude_none=True, mode="json") for f in findings],
        "count": len(findings),
    }


async def _serve() -> None:
    """Run the MCP server over stdio until the host disconnects."""
    mcp_deps = _import_mcp()
    Server = mcp_deps["Server"]
    InitializationOptions = mcp_deps["InitializationOptions"]
    NotificationOptions = mcp_deps["NotificationOptions"]
    Tool = mcp_deps["Tool"]
    TextContent = mcp_deps["TextContent"]
    mcp = mcp_deps["mcp_module"]

    server: Any = Server("iac-scanner")

    @server.list_tools()  # type: ignore[untyped-decorator]
    async def list_tools() -> list[Any]:
        return _tool_schemas(Tool)

    @server.call_tool()  # type: ignore[untyped-decorator]
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
        return await _call_tool(name, arguments, TextContent)

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="iac-scanner",
                server_version=__version__,
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main() -> None:
    """Entry point for the `iac-scan-mcp` console script."""
    import asyncio

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
