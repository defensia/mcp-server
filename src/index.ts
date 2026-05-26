#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { DefensiaClient } from './client.js';
import type { Briefing, DashboardStats, Server, SecurityEvent, Ban, PaginatedResponse } from './client.js';

// ── Config ───────────────────────────────────────────────────

const DEFENSIA_API_URL = process.env.DEFENSIA_API_URL || 'https://defensia.cloud';
const DEFENSIA_API_TOKEN = process.env.DEFENSIA_API_TOKEN;

if (!DEFENSIA_API_TOKEN) {
  console.error('Error: DEFENSIA_API_TOKEN environment variable is required.');
  console.error('Create an API token at https://defensia.cloud/settings/api-tokens');
  process.exit(1);
}

const client = new DefensiaClient({
  baseUrl: DEFENSIA_API_URL,
  apiToken: DEFENSIA_API_TOKEN,
});

// ── Simple cache ─────────────────────────────────────────────

const cache = new Map<string, { data: unknown; expires: number }>();

function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
  const entry = cache.get(key);
  if (entry && entry.expires > Date.now()) {
    return Promise.resolve(entry.data as T);
  }
  return fn().then(data => {
    cache.set(key, { data, expires: Date.now() + ttlMs });
    return data;
  });
}

// ── Formatters ───────────────────────────────────────────────

function formatStats(stats: DashboardStats): string {
  const s = stats.servers;
  const e = stats.events;
  const b = stats.bans;

  const lines = [
    `## Security Overview`,
    ``,
    `### Servers (${s.total})`,
    `- Online: ${s.online}`,
    `- Offline: ${s.offline}${s.offline > 0 ? ' ⚠' : ''}`,
    `- Warning: ${s.warning}${s.warning > 0 ? ' ⚠' : ''}`,
    ``,
    `### Events Today`,
    `- Total: ${e.today}`,
    `- Critical: ${e.critical}${e.critical > 0 ? ' 🔴' : ''}`,
    `- All-time: ${e.total}`,
    ``,
    `### Active Bans`,
    `- Active: ${b.active}`,
    `- All-time: ${b.total}`,
  ];

  return lines.join('\n');
}

function formatServer(server: Server): string {
  const statusIcon = server.status === 'online' ? '🟢' : server.status === 'offline' ? '🔴' : '🟡';
  const lines = [
    `## ${statusIcon} ${server.name} (${server.hostname})`,
    ``,
    `- **IP:** ${server.ip_address}`,
    `- **Status:** ${server.status}`,
    `- **OS:** ${server.os} ${server.os_version}`,
    `- **Agent version:** ${server.version}`,
    `- **Last seen:** ${server.last_seen_at}`,
    `- **Mode:** ${server.monitor_mode ? 'Monitor (observe-only)' : 'Active (blocking)'}`,
    `- **WAF:** ${server.waf_config ? 'Enabled' : 'Disabled'}`,
    ``,
    `### Resources`,
    `- CPU: ${server.cpu_percent !== null ? server.cpu_percent + '%' : 'N/A'}`,
    `- Memory: ${server.memory_percent !== null ? server.memory_percent + '%' : 'N/A'}`,
    `- Disk: ${server.disk_percent !== null ? server.disk_percent + '%' : 'N/A'}`,
    `- Active bans: ${server.active_bans_count}`,
  ];

  if (server.events?.length) {
    lines.push('', '### Recent Events');
    for (const e of server.events.slice(0, 10)) {
      const sev = e.severity === 'critical' ? '🔴' : e.severity === 'high' ? '🟠' : e.severity === 'warning' ? '🟡' : '⚪';
      lines.push(`- ${sev} **${e.type}** from ${e.source_ip || 'unknown'} ${e.country_code ? `(${e.country_code})` : ''} — ${e.occurred_at}`);
    }
  }

  if (server.bans?.length) {
    lines.push('', '### Active Bans');
    for (const b of server.bans.slice(0, 10)) {
      lines.push(`- ${b.ip_address} — ${b.reason} (expires: ${b.expires_at || 'permanent'})`);
    }
  }

  return lines.join('\n');
}

function formatServerList(data: PaginatedResponse<Server>): string {
  const lines = [
    `## Servers (${data.total} total, page ${data.current_page}/${data.last_page})`,
    '',
  ];

  for (const s of data.data) {
    const icon = s.status === 'online' ? '🟢' : s.status === 'offline' ? '🔴' : '🟡';
    const cpu = s.cpu_percent !== null ? `CPU ${s.cpu_percent}%` : '';
    const mem = s.memory_percent !== null ? `MEM ${s.memory_percent}%` : '';
    const metrics = [cpu, mem].filter(Boolean).join(', ');
    lines.push(`${icon} **${s.name}** (ID: ${s.id}) — ${s.status} | ${s.ip_address} | ${metrics || 'no metrics'} | Bans: ${s.active_bans_count}`);
  }

  return lines.join('\n');
}

function formatEvents(data: PaginatedResponse<SecurityEvent>): string {
  const lines = [
    `## Security Events (${data.total} total, page ${data.current_page}/${data.last_page})`,
    '',
  ];

  for (const e of data.data) {
    const sev = e.severity === 'critical' ? '🔴' : e.severity === 'high' ? '🟠' : e.severity === 'warning' ? '🟡' : '⚪';
    const server = e.agent ? e.agent.name : `agent#${e.agent_id}`;
    lines.push(`${sev} **${e.type}** on ${server} from ${e.source_ip || 'unknown'} ${e.country_code ? `(${e.country_code})` : ''} — ${e.occurred_at}`);
    if (e.details && Object.keys(e.details).length > 0) {
      const detail = JSON.stringify(e.details);
      if (detail.length < 200) {
        lines.push(`  Details: ${detail}`);
      }
    }
  }

  return lines.join('\n');
}

function formatBans(data: PaginatedResponse<Ban>): string {
  const lines = [
    `## Active Bans (${data.total} total, page ${data.current_page}/${data.last_page})`,
    '',
  ];

  for (const b of data.data) {
    const server = b.agent ? b.agent.name : 'global';
    const expires = b.expires_at || 'permanent';
    const escalation = b.ban_count > 1 ? ` (offense #${b.ban_count})` : '';
    lines.push(`- **${b.ip_address}** on ${server} — ${b.reason}${escalation} | Expires: ${expires}`);
  }

  return lines.join('\n');
}

function formatBriefing(briefing: Briefing): string {
  const s = briefing.summary;
  const statusLabel = briefing.status === 'all_clear' ? '✅ All Clear'
    : briefing.status === 'incidents_handled' ? '🟡 Incidents Handled'
    : '🔴 Attention Needed';

  const lines = [
    `## Security Briefing — ${briefing.period.label}`,
    `**Status: ${statusLabel}**`,
    ``,
    `### Summary`,
    `- Events: ${s.total_events} (${s.critical_events} critical)`,
    `- Bans: ${s.bans_created} created, ${s.bans_active} active`,
    `- Servers: ${s.servers_online} online, ${s.servers_offline} offline, ${s.servers_warning} warning`,
  ];

  // Trends
  const t = briefing.trends;
  if (t.events_delta_percent !== 0) {
    const direction = t.events_delta_percent > 0 ? '📈 up' : '📉 down';
    lines.push(`- Trend: ${direction} ${Math.abs(t.events_delta_percent)}% vs previous period`);
  }
  if (t.top_attack_type) {
    lines.push(`- Top attack type: ${t.top_attack_type}`);
  }
  if (Object.keys(t.top_countries).length > 0) {
    const countries = Object.entries(t.top_countries).map(([c, n]) => `${c} (${n})`).join(', ');
    lines.push(`- Top source countries: ${countries}`);
  }

  // WAF
  if (briefing.waf.total > 0) {
    lines.push('', `### WAF Activity (${briefing.waf.total} events)`);
    for (const w of briefing.waf.by_type) {
      lines.push(`- ${w.label}: ${w.count}`);
    }
    if (briefing.waf.scoring) {
      const ws = briefing.waf.scoring;
      lines.push(`- Blocked: ${ws.blocked} | Observed: ${ws.observed} | Throttled: ${ws.throttled}`);
      if (ws.top_ips.length > 0) {
        lines.push('', '**Top suspicious IPs:**');
        for (const ip of ws.top_ips) {
          lines.push(`  - ${ip.ip} — score ${ip.max_score}, action: ${ip.action}, category: ${ip.category}`);
        }
      }
    }
  }

  // Incidents
  if (briefing.incidents.length > 0) {
    lines.push('', `### Incidents (${briefing.incidents.length})`);
    for (const inc of briefing.incidents.slice(0, 10)) {
      lines.push(`- ${inc.narrative}`);
    }
  }

  // Resources
  const warningResources = briefing.resources.filter(r => r.disk_warning || (r.cpu_current && r.cpu_current > 80));
  if (warningResources.length > 0) {
    lines.push('', '### Resource Warnings');
    for (const r of warningResources) {
      const issues = [];
      if (r.disk_warning) issues.push(`disk ${r.disk_current}%`);
      if (r.cpu_current && r.cpu_current > 80) issues.push(`CPU ${r.cpu_current}%`);
      lines.push(`- **${r.server}**: ${issues.join(', ')}`);
    }
  }

  // Security (CVE)
  if (briefing.security.open_critical > 0 || briefing.security.open_high > 0) {
    lines.push('', '### Vulnerability Findings');
    if (briefing.security.open_critical > 0) lines.push(`- 🔴 ${briefing.security.open_critical} critical vulnerabilities open`);
    if (briefing.security.open_high > 0) lines.push(`- 🟠 ${briefing.security.open_high} high-severity findings open`);
  }

  // Recommendations
  if (briefing.recommendations.length > 0) {
    lines.push('', '### Recommendations');
    for (const rec of briefing.recommendations) {
      const icon = rec.severity === 'critical' ? '🔴' : '🟡';
      lines.push(`${icon} **${rec.title}** — ${rec.description}`);
    }
  }

  return lines.join('\n');
}

// ── MCP Server ───────────────────────────────────────────────

const server = new McpServer({
  name: 'defensia',
  version: '0.1.0',
});

// Tool 1: Security Overview
server.tool(
  'get_security_overview',
  'Get a high-level security overview of all your servers: counts, events today, active bans, and server status.',
  {},
  async () => {
    try {
      const stats = await cached('stats', 30_000, () => client.getStats());
      return { content: [{ type: 'text', text: formatStats(stats) }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${(err as Error).message}` }], isError: true };
    }
  },
);

// Tool 2: List Servers
server.tool(
  'list_servers',
  'List all monitored servers with their status, IP, resource usage, and active ban count.',
  { page: z.number().optional().describe('Page number (default 1)') },
  async ({ page }) => {
    try {
      const data = await cached(`servers-${page || 1}`, 30_000, () => client.getServers(page || 1));
      return { content: [{ type: 'text', text: formatServerList(data) }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${(err as Error).message}` }], isError: true };
    }
  },
);

// Tool 3: Server Details
server.tool(
  'get_server_details',
  'Get detailed info about a specific server including recent events, active bans, resources, and WAF config. Use list_servers first to find the server ID.',
  { server_id: z.number().describe('The server ID') },
  async ({ server_id }) => {
    try {
      const server = await client.getServer(server_id);
      return { content: [{ type: 'text', text: formatServer(server) }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${(err as Error).message}` }], isError: true };
    }
  },
);

// Tool 4: Search Events
server.tool(
  'search_events',
  'Search security events across all servers. Filter by severity (info/warning/high/critical), event type (brute_force, sql_injection, bot_detected, etc.), or specific server.',
  {
    severity: z.enum(['info', 'warning', 'high', 'critical']).optional().describe('Filter by severity'),
    type: z.string().optional().describe('Filter by event type: brute_force, sql_injection, xss_attempt, path_traversal, rce_attempt, scanner_detected, bot_detected, 404_flood, port_scan, flood, geoblock, etc.'),
    server_id: z.number().optional().describe('Filter by server ID'),
    page: z.number().optional().describe('Page number (default 1)'),
  },
  async (params) => {
    try {
      const data = await client.getEvents(params);
      return { content: [{ type: 'text', text: formatEvents(data) }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${(err as Error).message}` }], isError: true };
    }
  },
);

// Tool 5: Active Bans
server.tool(
  'get_active_bans',
  'List all currently active IP bans across your servers, with reason, escalation count, and expiry.',
  { page: z.number().optional().describe('Page number (default 1)') },
  async ({ page }) => {
    try {
      const data = await client.getBans(page || 1);
      return { content: [{ type: 'text', text: formatBans(data) }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${(err as Error).message}` }], isError: true };
    }
  },
);

// Tool 6: Security Briefing
server.tool(
  'get_security_briefing',
  'Get a comprehensive security briefing with incidents, trends, WAF activity, resource warnings, vulnerability findings, and recommendations. This is the most complete view of your security posture.',
  {
    period: z.enum(['6 hours', '12 hours', '24 hours', '7 days']).optional().describe('Time period (default: 12 hours)'),
  },
  async ({ period }) => {
    try {
      const briefing = await cached(`briefing-${period || '12 hours'}`, 60_000, () => client.getBriefing(period || '12 hours'));
      return { content: [{ type: 'text', text: formatBriefing(briefing) }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Error: ${(err as Error).message}` }], isError: true };
    }
  },
);

// ── Start ────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Failed to start Defensia MCP server:', err);
  process.exit(1);
});
