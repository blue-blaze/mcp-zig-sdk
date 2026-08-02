// The TypeScript SDK serving 2026-07-28 over stdio, for this SDK's stdio client.
//
// `serveStdio` rather than `server.connect(new StdioServerTransport())`: the latter
// speaks only the 2025 protocol no matter how new the SDK is. `legacy: 'reject'` refuses
// a 2025-era opening outright, so a passing run cannot be one that quietly fell back.

import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { buildServer } from './ts-server-common.mjs';

await serveStdio(buildServer, { legacy: 'reject' });
