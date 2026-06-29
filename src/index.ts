#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { DefensiaClient } from './client.js';
import { registerTools } from './tools.js';

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

const server = new McpServer({
  name: 'defensia',
  version: '0.3.0',
});

registerTools(server, client);

// ── Start ────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Failed to start Defensia MCP server:', err);
  process.exit(1);
});
