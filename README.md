# Defensia MCP Server

Ask your servers about their security status using any AI assistant that supports MCP (Model Context Protocol).

> "Are my servers under attack right now?"
> "Which IPs should I permanently block?"
> "Give me a security briefing for the last 24 hours"

## Quick Start

### 1. Get your API token

Go to **[defensia.cloud/settings/api-tokens](https://defensia.cloud/settings/api-tokens)** and create a new token.

### 2. Configure your AI client

#### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "defensia": {
      "command": "npx",
      "args": ["-y", "@defensia/mcp-server"],
      "env": {
        "DEFENSIA_API_TOKEN": "your-token-here"
      }
    }
  }
}
```

#### Claude Code

```bash
claude mcp add defensia -- npx -y @defensia/mcp-server
# Then set the env var in your shell or .env
export DEFENSIA_API_TOKEN=your-token-here
```

#### Cursor / Windsurf

Add to your MCP config (Settings > MCP Servers):

```json
{
  "defensia": {
    "command": "npx",
    "args": ["-y", "@defensia/mcp-server"],
    "env": {
      "DEFENSIA_API_TOKEN": "your-token-here"
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `get_security_overview` | High-level stats: server counts, events today, active bans |
| `list_servers` | All monitored servers with status, IPs, and resource usage |
| `get_server_details` | Deep dive into a specific server: events, bans, WAF, metrics |
| `search_events` | Search security events by type, severity, or server |
| `get_active_bans` | Currently blocked IPs with reasons and expiry |
| `get_security_briefing` | Full security report: incidents, trends, WAF, CVEs, recommendations |

## Example Queries

- "Are any of my servers offline?"
- "Show me all critical events from today"
- "What bots are hitting my servers?"
- "Give me a 24-hour security briefing"
- "Which IPs are banned right now?"
- "Is my server smartsalus under attack?"
- "What SQL injection attempts happened this week?"

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEFENSIA_API_TOKEN` | Yes | — | Your Defensia API token |
| `DEFENSIA_API_URL` | No | `https://defensia.cloud` | API base URL (for self-hosted) |

## Self-hosted

If you run Defensia on your own infrastructure, set `DEFENSIA_API_URL` to your panel URL:

```json
{
  "env": {
    "DEFENSIA_API_TOKEN": "your-token",
    "DEFENSIA_API_URL": "https://security.yourcompany.com"
  }
}
```

## License

MIT
