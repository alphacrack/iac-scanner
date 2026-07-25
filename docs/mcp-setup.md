---
layout: default
title: MCP server setup
permalink: /mcp-setup/
---

# MCP server setup

Use iac-scanner from Claude Desktop, Cursor, or Continue without configuring an
LLM API key in iac-scanner. The host application supplies the model.

## Install and verify

```bash
pip install "iac-scanner[mcp]"
iac-scan-mcp --help
```

The help command prints:

```text
Usage: iac-scan-mcp [--help]

Start the iac-scanner MCP server over stdio.
```

If your client cannot find `iac-scan-mcp`, use the command's absolute path from
`which iac-scan-mcp` (macOS/Linux) or `where iac-scan-mcp` (Windows).

## Claude Desktop

Open the configuration file for your operating system:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Add the server, preserving any existing entries:

```json
{
  "mcpServers": {
    "iac-scanner": {
      "command": "iac-scan-mcp"
    }
  }
}
```

Save the file and fully restart Claude Desktop.

## Cursor

Create `.cursor/mcp.json` in the workspace, or open **Settings → MCP**, and add:

```json
{
  "mcpServers": {
    "iac-scanner": {
      "command": "iac-scan-mcp"
    }
  }
}
```

Reload the server from Cursor's MCP settings after saving.

## Continue

Current Continue versions accept Claude/Cursor JSON format in a workspace MCP
block. Save this as `.continue/mcpServers/iac-scanner.json`:

```json
{
  "mcpServers": {
    "iac-scanner": {
      "command": "iac-scan-mcp"
    }
  }
}
```

Older Continue installations using `~/.continue/config.json` need the legacy
shape:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "iac-scan-mcp",
          "args": []
        }
      }
    ]
  }
}
```

MCP tools are available in Continue's Agent mode.

## First prompt

> Scan the Terraform in `~/work/infra` and suggest a fix for anything critical.

The host should call `scan_iac_path`. If Checkov is installed, it can also call
`run_rule_engine`.

## Troubleshooting

- Confirm `iac-scan-mcp --help` works in a new terminal.
- Restart the host after editing its configuration.
- Check that the JSON file parses and has only one top-level `mcpServers` key.
- Use an absolute command path when a GUI host has a different `PATH`.
- Reinstall with the MCP extra if the server reports a missing MCP Python SDK.
