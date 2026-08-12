// The official TypeScript SDK as a *client over stdio*, talking to this SDK's server.
//
// The fourth leg of the matrix. Pinned rather than `'auto'` for the same reason as the
// HTTP client: a fallback would let a failure to speak 2026-07-28 look like a pass.
//
// Usage: node ts-client-stdio.mjs <command> [args...]

import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const [command, ...args] = process.argv.slice(2);
if (!command) {
    console.error('usage: node ts-client-stdio.mjs <command> [args...]');
    process.exit(2);
}

/// Resolves once `predicate` holds, or after `timeoutMs`. Returning rather than throwing
/// on timeout keeps the failure attributable to the check that cares.
async function waitFor(predicate, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (!predicate() && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 10));
    }
}

const checks = [];
function check(name, ok, detail) {
    checks.push({ name, ok });
    // Collapsed to one line: several details are multi-line tool output, and a check
    // whose result spans lines cannot be grepped for.
    const flat = detail === undefined ? '' : String(detail).replace(/\s+/g, ' ').trim();
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${flat ? ` — ${flat}` : ''}`);
}

const client = new Client(
    { name: 'ts-sdk-interop-stdio-client', version: '1.0.0' },
    {
        versionNegotiation: { mode: { pin: '2026-07-28' } },
        // This SDK's server asks for input in-band (there is no server→client request
        // channel on this revision), so the client needs a handler to fulfil it.
        capabilities: { elicitation: { form: {}, url: {} } },
    },
);

// `greet_user` asks for a name on the first call and greets on the retry — the
// multi-round-trip shape. The client's auto-fulfilment driver re-sends the call with the
// response and the byte-exact `requestState`.
client.setRequestHandler('elicitation/create', async () => ({
    action: 'accept',
    content: { name: 'Ada' },
}));

const transport = new StdioClientTransport({ command, args });
await client.connect(transport);

check('connect pinned to 2026-07-28', client.getProtocolEra() === 'modern', `era=${client.getProtocolEra()}`);
check(
    'negotiated revision',
    client.getNegotiatedProtocolVersion() === '2026-07-28',
    client.getNegotiatedProtocolVersion(),
);

const tools = await client.listTools();
const names = tools.tools.map((t) => t.name).sort();
check('tools/list', names.length >= 4, names.join(', '));

const sum = await client.callTool({ name: 'add', arguments: { a: 2, b: 3 } });
check('tools/call', sum.content?.[0]?.text === '5', sum.content?.[0]?.text);

// Division by zero is a tool failure, which on this protocol is a successful response
// carrying isError — not a JSON-RPC error.
const divided = await client.callTool({ name: 'divide', arguments: { numerator: 1, denominator: 0 } });
check('a failing tool is isError, not a protocol error', divided.isError === true, `isError=${divided.isError}`);

const progress = [];
const forecast = await client.callTool(
    { name: 'get_forecast', arguments: { city: 'Zurich', days: 3 } },
    { onprogress: (p) => progress.push(p.progress) },
);
check('tools/call with progress', forecast.content?.[0]?.text?.length > 0, `${forecast.content?.[0]?.text?.slice(0, 32)}…`);

// Progress is *reported*, not asserted, on this leg.
//
// Over stdio this SDK delivers an arbitrary subset of the notifications to `onprogress` —
// observed 0, 1, 2, and 3 of 3 across consecutive runs. Waiting does not change the
// outcome, so they are dropped rather than late, and no assertion here would be about the
// protocol.
//
// That the Zig server emits all three, in order, ahead of the result is established
// elsewhere and deterministically:
//
//   * piping the identical request straight into the server shows all three on the wire;
//   * the Zig client receives all three over both transports, every run;
//   * this same TypeScript client receives all three over Streamable HTTP, every run
//     (asserted in `ts-client.mjs`) — there each notification is its own SSE event,
//     whereas on stdio all four messages land in a single pipe read and are processed as
//     one batch.
//
// So the exact count is asserted where it is observable, and this leg records what it saw.
await waitFor(() => progress.length === 3, 500);
console.log(`note  progress delivered to onprogress: ${progress.length}/3 (${progress.join(',') || 'none'})`);

// Multi-round-trip: two wire requests, one handler invocation each, fulfilled in between.
const greeted = await client.callTool({ name: 'greet_user', arguments: {} });
check(
    'multi-round-trip request fulfilled',
    greeted.content?.[0]?.text?.includes('Ada'),
    greeted.content?.[0]?.text,
);

const prompt = await client.getPrompt({ name: 'review_code', arguments: { language: 'zig' } });
check('prompts/get', prompt.messages?.length > 0, `${prompt.messages?.length} messages`);

const read = await client.readResource({ uri: 'file:///readme.md' });
check('resources/read', read.contents?.[0]?.text?.length > 0, `${read.contents?.[0]?.text?.slice(0, 24)}…`);

// A URI produced by an RFC 6570 template rather than a registered resource.
const templated = await client.readResource({ uri: 'greeting://Ada' });
check('resources/read via template', templated.contents?.[0]?.text?.includes('Ada'), templated.contents?.[0]?.text);

// Completion for a prompt argument.
const completion = await client.complete({
    ref: { type: 'ref/prompt', name: 'review_code' },
    argument: { name: 'language', value: 'z' },
});
check('completion/complete', Array.isArray(completion.completion?.values), completion.completion?.values?.join(', '));

// The same argument, completed with and without a resolved sibling. `memory safety` is
// only worth suggesting once the language is known, so the pair proves the server read
// `params.context.arguments` rather than that it happened to return everything.
const focusWithLanguage = await client.complete({
    ref: { type: 'ref/prompt', name: 'review_code' },
    argument: { name: 'focus', value: '' },
    context: { arguments: { language: 'zig' } },
});
const focusAlone = await client.complete({
    ref: { type: 'ref/prompt', name: 'review_code' },
    argument: { name: 'focus', value: '' },
});
check(
    'completion/complete reads context.arguments',
    focusWithLanguage.completion?.values?.includes('memory safety') &&
        !focusAlone.completion?.values?.includes('memory safety'),
    `with=${focusWithLanguage.completion?.values?.join(', ')} without=${focusAlone.completion?.values?.join(', ')}`,
);

await client.close();

const failures = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failures.length}/${checks.length} checks passed`);
process.exit(failures.length === 0 ? 0 : 1);
