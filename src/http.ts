#!/usr/bin/env node

/**
 * Remote MCP server for Defensia — serves over HTTP at mcp.defensia.cloud.
 *
 * Each client session sends a Bearer token in the Authorization header.
 * The token is forwarded to the Defensia API to scope results to that user's org.
 *
 * Protocol: Streamable HTTP (MCP 2025-03-26 spec)
 * Endpoint: POST /mcp (JSON-RPC over HTTP with optional SSE streaming)
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { DefensiaClient } from './client.js';
import { registerTools } from './tools.js';

const PORT = parseInt(process.env.PORT || '3100', 10);
const DEFENSIA_API_URL = process.env.DEFENSIA_API_URL || 'https://defensia.cloud';

// Track active transports for cleanup
const activeSessions = new Map<string, StreamableHTTPServerTransport>();

function extractToken(req: IncomingMessage): string | null {
  const auth = req.headers['authorization'];
  if (!auth) return null;
  const parts = auth.split(' ');
  if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') return parts[1];
  return null;
}

async function handleMcp(req: IncomingMessage, res: ServerResponse) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Extract token from Authorization header
  const token = extractToken(req);
  if (!token) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Missing Authorization: Bearer <token> header' }));
    return;
  }

  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  // Handle existing session
  if (sessionId && activeSessions.has(sessionId)) {
    const transport = activeSessions.get(sessionId)!;
    await transport.handleRequest(req, res);
    return;
  }

  // New session — only POST allowed for initialization
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed. Use POST to initialize a session.' }));
    return;
  }

  // Create a new MCP server + transport per session
  const client = new DefensiaClient({
    baseUrl: DEFENSIA_API_URL,
    apiToken: token,
  });

  const mcpServer = new McpServer({
    name: 'defensia',
    version: '0.3.0',
  });

  // Use a hash of the token as cache prefix to avoid cross-user cache leaks
  const cachePrefix = token.slice(-8);
  registerTools(mcpServer, client, cachePrefix);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => `dfs-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
  });

  // Clean up on close
  transport.onclose = () => {
    const sid = transport.sessionId;
    if (sid) activeSessions.delete(sid);
  };

  await mcpServer.connect(transport);

  // Store for future requests
  if (transport.sessionId) {
    activeSessions.set(transport.sessionId, transport);
  }

  await transport.handleRequest(req, res);
}

// ── Health check + routing ──────────────────────────────────

const httpServer = createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);

  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', sessions: activeSessions.size }));
    return;
  }

  if (url.pathname === '/mcp') {
    try {
      await handleMcp(req, res);
    } catch (err) {
      console.error('[mcp-http] Error handling request:', err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    }
    return;
  }

  // Root — info page
  if (url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      name: 'Defensia MCP Server',
      version: '0.3.0',
      protocol: 'streamable-http',
      endpoint: '/mcp',
      docs: 'https://defensia.cloud/docs/mcp',
      auth: 'Bearer token required (create at https://defensia.cloud/settings/api-tokens)',
    }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Defensia MCP server (HTTP) listening on port ${PORT}`);
  console.log(`Endpoint: http://0.0.0.0:${PORT}/mcp`);
});
