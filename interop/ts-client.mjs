// The official TypeScript SDK as a *client*, talking to this SDK's server.
//
// Pinned to 2026-07-28 with `{ pin: ... }` rather than `'auto'`: a pin has no legacy
// fallback, so if this SDK's server were not understood the run fails instead of
// quietly renegotiating down to a 2025 handshake and reporting success for the wrong
// protocol.
//
// Usage: node ts-client.mjs <url>

import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const url = process.argv[2];
if (!url) {
    console.error('usage: node ts-client.mjs <url>');
    process.exit(2);
}

const checks = [];
function check(name, ok, detail) {
    checks.push({ name, ok, detail });
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
}

const client = new Client(
    { name: 'ts-sdk-interop-client', version: '1.0.0' },
    { versionNegotiation: { mode: { pin: '2026-07-28' } } },
);

const transport = new StreamableHTTPClientTransport(new URL(url));
await client.connect(transport);

check('connect pinned to 2026-07-28', client.getProtocolEra() === 'modern', `era=${client.getProtocolEra()}`);
check(
    'negotiated revision',
    client.getNegotiatedProtocolVersion() === '2026-07-28',
    client.getNegotiatedProtocolVersion(),
);

// Server identity moved into result `_meta` in the final revision, so this reads back
// what our server stamps there rather than a body field.
const version = client.getServerVersion();
check('server identity in result _meta', version?.name !== undefined, JSON.stringify(version));

const tools = await client.listTools();
const names = tools.tools.map((t) => t.name).sort();
check('tools/list', names.length > 0, names.join(', '));

// A comptime-generated JSON Schema has to survive a round trip through another
// implementation's validator, which is the part most likely to be subtly wrong.
const executeSql = tools.tools.find((t) => t.name === 'execute_sql');
check(
    'comptime inputSchema is usable by the other SDK',
    executeSql?.inputSchema?.properties?.region?.type === 'string',
    JSON.stringify(executeSql?.inputSchema?.properties?.region),
);
check(
    'x-mcp-header annotation survives',
    executeSql?.inputSchema?.properties?.region?.['x-mcp-header'] === 'Region',
    executeSql?.inputSchema?.properties?.region?.['x-mcp-header'],
);

// The TS client mirrors annotated arguments into `Mcp-Param-Region` and our server
// validates the header against the body. Both halves have to agree or this is -32020.
const sql = await client.callTool({
    name: 'execute_sql',
    arguments: { region: 'us-east-1', query: 'select 1' },
});
check(
    'tools/call with Mcp-Param-* mirroring',
    sql.content?.[0]?.text?.includes('us-east-1'),
    sql.content?.[0]?.text,
);

// Progress arrives on the response's own SSE stream while the handler runs.
const progress = [];
const counted = await client.callTool(
    { name: 'count', arguments: { to: 3 } },
    { onprogress: (p) => progress.push(p.progress) },
);
check('tools/call result', counted.content?.[0]?.text === '1 2 3', counted.content?.[0]?.text);
check('progress notifications arrived', progress.length === 3, progress.join(','));

const resources = await client.listResources();
check(
    'resources/list',
    resources.resources.some((r) => r.uri === 'file:///readme.md'),
    resources.resources.map((r) => r.uri).join(', '),
);

const read = await client.readResource({ uri: 'file:///readme.md' });
check('resources/read', read.contents?.[0]?.text?.length > 0, `${read.contents?.[0]?.text?.slice(0, 24)}…`);

// A tool that fails is a successful response with isError, not a JSON-RPC error. Getting
// this backwards is a common interop break, so it is checked explicitly.
const failed = await client.callTool({ name: 'count', arguments: { to: 0 } });
check('a failing tool is isError, not a protocol error', failed.isError === true, `isError=${failed.isError}`);

await client.close();

const failures = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failures.length}/${checks.length} checks passed`);
process.exit(failures.length === 0 ? 0 : 1);
