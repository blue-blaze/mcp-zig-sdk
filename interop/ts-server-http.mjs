// The TypeScript SDK serving 2026-07-28 over Streamable HTTP, for this SDK's client.
//
// `createMcpHandler` is the v2 entry that serves the modern revision per request;
// `legacy: 'reject'` means a 2025-era request is refused rather than served, so a passing
// interop run cannot be one that silently used the older protocol.
//
// Usage: node ts-server-http.mjs [port]

import { createServer } from 'node:http';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { buildServer } from './ts-server-common.mjs';

const port = Number(process.argv[2] ?? 8792);

const handler = createMcpHandler(buildServer, { legacy: 'reject' });
const nodeHandler = toNodeHandler(handler);

const httpServer = createServer((req, res) => {
    if (!req.url?.startsWith('/mcp')) {
        res.writeHead(404).end();
        return;
    }
    nodeHandler(req, res).catch((error) => {
        console.error('handler failed:', error);
        if (!res.headersSent) res.writeHead(500).end();
    });
});

httpServer.listen(port, '127.0.0.1', () => {
    // The Zig side waits for this line rather than sleeping, so a slow start cannot look
    // like a protocol failure.
    console.log(`ts-server-http listening on 127.0.0.1:${port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
        httpServer.close();
        handler.close?.();
        process.exit(0);
    });
}
