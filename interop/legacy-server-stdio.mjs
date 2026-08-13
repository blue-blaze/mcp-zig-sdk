// The TypeScript SDK serving the *2025* protocol over stdio, for this SDK's legacy
// fallback to be checked against.
//
// `server.connect(new StdioServerTransport())` is the pre-2026 path however new the SDK
// is — the note in ts-server-stdio.mjs says so, and that is exactly what is wanted here:
// a server that answers `server/discover` with `-32601`, requires `initialize`, and never
// sends `resultType` or a cache hint. The same `buildServer` as every other leg, so any
// difference in the results is the protocol era and nothing else.
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { buildServer } from './ts-server-common.mjs';

const server = buildServer();
await server.connect(new StdioServerTransport());
