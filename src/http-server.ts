#!/usr/bin/env node

import express, { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
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

// Create Express app
const app = express();
app.use(express.json());

// Map to store transports by session ID
const transports: Record<string, StreamableHTTPServerTransport> = {};

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'business-central-mcp' });
});

// MCP POST endpoint - handles JSON-RPC messages
app.post('/mcp', async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (sessionId) {
    console.log(`Received MCP request for session: ${sessionId}`);
  } else {
    console.log('New MCP connection request');
  }

  try {
    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports[sessionId]) {
      // Reuse existing transport
      transport = transports[sessionId];
    } else {
      // Create new transport
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sessionId) => {
          console.log(`New session initialized: ${sessionId}`);
          transports[sessionId] = transport;
        },
        onsessionclosed: (sessionId) => {
          console.log(`Session closed: ${sessionId}`);
          delete transports[sessionId];
        },
      });

      // Create a new server instance for this connection
      const server = createMCPServer(bcClient);

      // Connect server to transport
      await server.connect(transport);
    }

    // Handle the request
    await transport.handleRequest(req, res);
  } catch (error) {
    console.error('Error handling MCP POST request:', error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error',
        },
        id: null,
      });
    }
  }
});

// MCP GET endpoint - handles SSE streams for notifications
app.get('/mcp', async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }

  const lastEventId = req.headers['last-event-id'] as string | undefined;

  if (lastEventId) {
    console.log(`Client reconnecting with Last-Event-ID: ${lastEventId}`);
  } else {
    console.log(`Establishing new SSE stream for session ${sessionId}`);
  }

  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
});

// MCP DELETE endpoint - handles session termination
app.delete('/mcp', async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }

  console.log(`Received session termination request for session ${sessionId}`);

  try {
    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
  } catch (error) {
    console.error('Error handling session termination:', error);
    if (!res.headersSent) {
      res.status(500).send('Error processing session termination');
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

  // Close all active transports to properly clean up resources
  for (const sessionId in transports) {
    try {
      console.log(`Closing transport for session ${sessionId}`);
      await transports[sessionId].close();
      delete transports[sessionId];
    } catch (error) {
      console.error(`Error closing transport for session ${sessionId}:`, error);
    }
  }

  console.log('Server shutdown complete');
  process.exit(0);
});
