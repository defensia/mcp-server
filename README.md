<p align="center">
  <img src="https://defensia.cloud/img/logo.svg" alt="Defensia" width="200">
</p>

<h3 align="center">Ask your servers if they're under attack</h3>

<p align="center">
  MCP server that connects your AI assistant to Defensia's real-time security monitoring.<br>
  Query server status, active threats, banned IPs, WAF activity, and vulnerabilities — in natural language.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@defensia/mcp-server"><img src="https://img.shields.io/npm/v/@defensia/mcp-server?label=npm&color=brightgreen" alt="npm version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-18+-339933?logo=node.js&logoColor=white" alt="Node.js"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-8A2BE2?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggOHoiLz48L3N2Zz4=" alt="MCP compatible"></a>
  <a href="https://defensia.cloud"><img src="https://img.shields.io/badge/Defensia-cloud-FF6B35?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAxTDMgNXY2YzcgNSA5IDEwIDkgMTAgMC01LjE5LTktMTAtOS0xMFY1bDktNHoiLz48L3N2Zz4=" alt="Defensia"></a>
</p>

<p align="center">
  <a href="https://defensia.cloud">Website</a> ·
  <a href="https://defensia.cloud/docs">Docs</a> ·
  <a href="https://github.com/defensia/agent">Agent</a> ·
  <a href="https://defensia.cloud/pricing">Pricing</a> ·
  <a href="https://github.com/defensia/mcp-server/issues">Issues</a>
</p>

---

## The problem

You have servers protected by Defensia. Attacks are being blocked, events are being logged, bans are being applied. But to check the status, you need to open the dashboard, navigate tabs, filter events, compare charts.

**What if you could just ask?**

```
You:    "Are my servers under attack right now?"
Claude: "Yes — your server 'web-prod-01' is receiving a brute force attack from
         3 IPs in China. 47 events in the last 15 minutes. All 3 IPs have been
         automatically banned. CPU peaked at 23% during the attack but has
         returned to baseline (8%). No action needed."
```

This MCP server gives your AI assistant direct access to Defensia's security data — server status, active threats, banned IPs, WAF analysis, vulnerability findings, and incident briefings.

---

## Quick start

### 1. Get your API token

Go to **[defensia.cloud/settings/api-tokens](https://defensia.cloud/settings/api-tokens)** and create a new token.

### 2. Connect your AI assistant

<details open>
<summary><strong>Claude Desktop</strong></summary>

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

</details>

<details>
<summary><strong>Claude Code</strong></summary>

```bash
claude mcp add defensia -e DEFENSIA_API_TOKEN=your-token-here -- npx -y @defensia/mcp-server
```

</details>

<details>
<summary><strong>Cursor</strong></summary>

Add to `.cursor/mcp.json` in your project:

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

</details>

<details>
<summary><strong>Windsurf</strong></summary>

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

</details>

<details>
<summary><strong>Any MCP-compatible client</strong></summary>

The server communicates over **stdio** using the [Model Context Protocol](https://modelcontextprotocol.io). Any client that supports MCP can connect:

```bash
DEFENSIA_API_TOKEN=your-token npx @defensia/mcp-server
```

</details>

---

## What you can ask

Once connected, just ask questions in natural language. The AI will call the right tools automatically.

### Server status
- *"Are any of my servers offline?"*
- *"What's the CPU and memory usage on web-prod-01?"*
- *"Which servers have WAF disabled?"*

### Active threats
- *"Am I under attack right now?"*
- *"Show me all critical events from today"*
- *"What SQL injection attempts happened in the last 24 hours?"*
- *"Are there any brute force attacks targeting my SSH?"*

### Bot activity
- *"What bots are hitting my servers?"*
- *"Are bots consuming my Apache workers?"*
- *"Which unknown user agents are making the most requests?"*

### IP intelligence
- *"Which IPs are banned right now?"*
- *"Show me all bans that are about to expire"*
- *"What IPs have been banned more than 3 times?"*

### Security briefing
- *"Give me a security briefing for the last 24 hours"*
- *"What happened while I was sleeping?"*
- *"Any recommendations to improve my security posture?"*

---

## Available tools

| Tool | Description |
|---|---|
| `get_security_overview` | High-level dashboard stats — server counts, events today, active bans |
| `list_servers` | All monitored servers with status, IP, resource usage, and active ban count |
| `get_server_details` | Deep dive into one server — recent events, active bans, WAF config, metrics |
| `search_events` | Search security events by severity, type (brute_force, sql_injection, bot_detected...), or server |
| `get_active_bans` | All currently blocked IPs with reason, escalation count, and expiry |
| `get_security_briefing` | Full security report — incidents grouped by type, trends vs yesterday, WAF scoring, CVE findings, resource alerts, and actionable recommendations |

### Event types you can search

`brute_force` · `sql_injection` · `xss_attempt` · `path_traversal` · `rce_attempt` · `ssrf_attempt` · `shellshock` · `web_shell` · `header_injection` · `env_probe` · `config_probe` · `scanner_detected` · `wp_bruteforce` · `xmlrpc_abuse` · `404_flood` · `honeypot_triggered` · `bot_detected` · `bot_crawl` · `bot_unknown` · `port_scan` · `flood` · `geoblock` · `mail_brute_force` · `ftp_brute_force` · `db_brute_force`

---

## How it works

```
┌─────────────────────────────────────────────────────┐
│              Your AI assistant                       │
│  (Claude Desktop, Claude Code, Cursor, Windsurf)    │
└──────────────────────┬──────────────────────────────┘
                       │  MCP protocol (stdio)
                       ▼
              ┌─────────────────┐
              │  Defensia MCP   │  ← This package
              │  Server (Node)  │     Runs locally
              └────────┬────────┘
                       │  HTTPS + Bearer token
                       ▼
              ┌─────────────────┐
              │  Defensia API   │  ← Your dashboard
              │  (REST + Auth)  │     defensia.cloud
              └────────┬────────┘
           ┌───────────┼───────────┐
           ▼           ▼           ▼
      ┌─────────┐ ┌─────────┐ ┌─────────┐
      │ Agent 1 │ │ Agent 2 │ │ Agent N │  ← Your servers
      │ (VPS)   │ │(Docker) │ │  (K8s)  │
      └─────────┘ └─────────┘ └─────────┘
```

The MCP server runs as a **local process** on your machine. It connects to the Defensia API using your personal token — your credentials never leave your environment. Responses are cached (30s for stats, 60s for briefings) to keep the experience fast.

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DEFENSIA_API_TOKEN` | Yes | — | Your Defensia API token (created in dashboard) |
| `DEFENSIA_API_URL` | No | `https://defensia.cloud` | API base URL (for self-hosted instances) |

### Self-hosted Defensia

If you run Defensia on your own infrastructure:

```json
{
  "env": {
    "DEFENSIA_API_TOKEN": "your-token",
    "DEFENSIA_API_URL": "https://security.yourcompany.com"
  }
}
```

---

## Security

- **Read-only by default** — the MCP server only reads data from your Defensia dashboard. It cannot modify firewall rules, change server configurations, or access your servers directly.
- **Token stays local** — your API token is stored in your local MCP config file. It is never sent anywhere except to the Defensia API.
- **No telemetry** — this package collects zero analytics, sends zero telemetry, and phones home to nobody.
- **Open source** — every line of code is in this repo. Audit it before installing.

---

## Requirements

- [Node.js 18+](https://nodejs.org) (for `npx`)
- A [Defensia](https://defensia.cloud) account with at least one connected server
- An API token from your Defensia dashboard

---

## What is Defensia?

[Defensia](https://defensia.cloud) is a server security platform that detects and blocks attacks in real time. It consists of a lightweight [Go agent](https://github.com/defensia/agent) that runs on your Linux servers and a cloud dashboard for monitoring and management.

**What it detects:** SSH brute force (15 patterns), web application attacks (SQL injection, XSS, RCE, path traversal, and 12 more OWASP types), bot activity (70+ fingerprints), malware, port scans, and vulnerability scanning.

**How it works:** Install a single binary on your server. It monitors auth logs and web access logs, detects attacks using pattern matching and cumulative scoring, and blocks malicious IPs automatically via iptables. Everything is visible in real time on your dashboard — or now, through this MCP server.

---

## Contributing

Contributions welcome. Please [open an issue](https://github.com/defensia/mcp-server/issues) before submitting large changes.

```bash
git clone https://github.com/defensia/mcp-server.git
cd mcp-server
npm install
npm run build
```

---

## License

[MIT](LICENSE) — use it however you want.

---

<p align="center">
  <a href="https://defensia.cloud">defensia.cloud</a> · Built for developers who run their own servers
</p>
