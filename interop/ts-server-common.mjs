// A 2026-07-28 server built with the official TypeScript SDK, for this SDK's client to
// talk to.
//
// The tools are chosen to exercise the parts of the protocol where two independent
// implementations are most likely to disagree: a JSON Schema this SDK must generate a
// matching request for, an `x-mcp-header` annotation the client has to learn from
// `tools/list` and mirror into `Mcp-Param-*`, per-request progress and logging that only
// flow when the client opts in via `_meta`, and a resource read.

import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';

export function buildServer() {
    const server = new McpServer(
        { name: 'ts-sdk-interop-server', version: '1.0.0' },
        // `logging` has to be declared for `ctx.mcpReq.log` to emit anything.
        { capabilities: { tools: {}, resources: {}, prompts: {}, logging: {} } },
    );

    server.registerTool(
        'add',
        {
            description: 'Adds two integers.',
            inputSchema: { a: z.number().int(), b: z.number().int() },
        },
        async ({ a, b }) => ({ content: [{ type: 'text', text: String(a + b) }] }),
    );

    server.registerTool(
        'echo_region',
        {
            description: 'Echoes a region that is also mirrored into a header.',
            // The annotation lives in the emitted `inputSchema`, which is the only place
            // a client can learn it from — so this is what makes the client's
            // `tools/list`-then-call ordering a real requirement rather than a quirk.
            inputSchema: {
                region: z.string().describe('The region').meta({ 'x-mcp-header': 'Region' }),
                note: z.string().optional(),
            },
        },
        async ({ region, note }) => ({
            content: [{ type: 'text', text: `region=${region}${note ? ` note=${note}` : ''}` }],
        }),
    );

    server.registerTool(
        'count',
        {
            description: 'Counts up, reporting progress and logging as it goes.',
            inputSchema: { to: z.number().int().min(1).max(20) },
        },
        async ({ to }, ctx) => {
            // Absent `logLevel` in the request envelope means the server emits nothing,
            // so this only appears when our client asked for it.
            await ctx.mcpReq.log('info', `counting to ${to}`);

            // Progress is opt-in per request: the token comes from the caller's `_meta`,
            // and with no token the server must stay silent.
            const progressToken = ctx.mcpReq._meta?.progressToken;
            const parts = [];
            for (let i = 1; i <= to; i += 1) {
                parts.push(String(i));
                if (progressToken !== undefined) {
                    await ctx.mcpReq.notify({
                        method: 'notifications/progress',
                        params: { progressToken, progress: i, total: to },
                    });
                }
            }
            return { content: [{ type: 'text', text: parts.join(' ') }] };
        },
    );

    server.registerResource(
        'readme',
        'file:///ts-readme.md',
        { mimeType: 'text/markdown' },
        async (uri) => ({
            contents: [{ uri: uri.href, mimeType: 'text/markdown', text: '# Served by the TypeScript SDK' }],
        }),
    );

    server.registerPrompt(
        'greet',
        { description: 'Greets someone.', argsSchema: { who: z.string() } },
        ({ who }) => ({
            messages: [{ role: 'user', content: { type: 'text', text: `Say hello to ${who}` } }],
        }),
    );

    return server;
}
