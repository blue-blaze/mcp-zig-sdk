# `spec/schema.json`

Not written here. This is the official JSON Schema for the Model Context Protocol,
revision **2026-07-28**, copied verbatim from the specification repository:

- Source: <https://github.com/modelcontextprotocol/modelcontextprotocol>
- Path: `schema/2026-07-28/schema.json`
- Retrieved: 2026-07-28
- Licence: Apache-2.0 (the MCP project is completing a transition from MIT; new
  specification contributions are Apache-2.0)

It is vendored rather than fetched so that `zig build spec` is reproducible and works
offline: the schema is the thing being validated against, and a check whose reference
can change underneath it is not a check.

Unmodified. If it is ever updated, replace the whole file and record the new revision
above rather than editing it in place — a locally patched schema would validate this
SDK against a protocol nobody else implements.
