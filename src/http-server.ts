#!/usr/bin/env node

import express, { Request, Response } from 'express';
import cors from 'cors';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { BusinessCentralClient } from './business-central-client.js';
import { createMCPServer } from './server.js';

// Read configuration from environment variables
const BC_URL_SERVER = process.env.BC_URL_SERVER;
const BC_COMPANY = process.env.BC_COMPANY;
const PORT = parseInt(process.env.PORT || '3000');

if (!BC_URL_SERVER || !BC_COMPANY) {
  console.error('Error: BC_URL_SERVER and BC_COMPANY environment variables are required');
  process.exit(1);
}

// Create Business Central client
const bcClient = new BusinessCentralClient({
  serverUrl: BC_URL_SERVER,
  companyName: BC_COMPANY,
});

async function main() {
  // Create single transport instance with session management
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => {
      const sessionId = `bc-${Date.now()}-${Math.random().toString(36).substring(7)}`;
      console.log(`Generated new session ID: ${sessionId}`);
      return sessionId;
    },
    onsessioninitialized: (sessionId) => {
      console.log(`Session initialized: ${sessionId}`);
    },
    onsessionclosed: (sessionId) => {
      console.log(`Session closed: ${sessionId}`);
    },
  });

  // Create MCP server and connect to transport
  const server = createMCPServer(bcClient);
  await server.connect(transport);

  // Create Express app
  const app = express();

  // Configure CORS to expose the mcp-session-id header (required for browser-based clients)
  app.use(cors({
    origin: '*',  // Allow all origins (Smithery needs this)
    exposedHeaders: ['mcp-session-id'],  // Expose session ID header to browsers
    allowedHeaders: ['Content-Type', 'mcp-session-id', 'Accept'],  // Allow these headers in requests
  }));

  // Health check endpoint
  app.get('/health', (req: Request, res: Response) => {
    res.json({ status: 'healthy', service: 'business-central-mcp' });
  });

  // All MCP requests (POST, GET, DELETE) are handled by the transport
  app.all('/mcp', async (req: Request, res: Response) => {
    console.log(`${req.method} /mcp - Session: ${req.headers['mcp-session-id'] || 'new'}`);

    try {
      await transport.handleRequest(req, res);
    } catch (error) {
      console.error('Error handling MCP request:', error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error',
            data: error instanceof Error ? error.message : String(error),
          },
          id: null,
        });
      }
    }
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`Business Central MCP server running on http://localhost:${PORT}`);
    console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
    console.log(`Health check available at http://localhost:${PORT}/health`);
  });

  // Handle server shutdown
  process.on('SIGINT', async () => {
    console.log('Shutting down server...');

    try {
      await transport.close();
      console.log('Transport closed successfully');
    } catch (error) {
      console.error('Error closing transport:', error);
    }

    console.log('Server shutdown complete');
    process.exit(0);
  });
}

main().catch((error) => {
  console.error('Failed to start HTTP server:', error);
  process.exit(1);
});
