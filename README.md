# n8n Workflow Linter

Client-side public beta for scanning exported n8n workflow JSON files.

Find risky nodes in your n8n workflow before they break production. Upload your workflow JSON and get a local reliability report.

## Scope

- JSON upload, paste input, and demo workflow examples
- Local browser scanner with a Web Worker
- n8n parser, graph helpers, and deterministic risk rules
- Active scan excludes disabled nodes and non-operational nodes such as Sticky Note / NoOp
- Security rules for known secret formats, credential-shaped values, credential IDs, URL query credentials, and pinned data
- Reliability rules for webhook validation/auth, HubSpot create dedupe, HTTP timeout/retry/error handling, frequent schedules, duplicate write paths, and disconnected action nodes
- Verdict, severity grouped report, parser warnings, markdown report export, and fix checklist copy

Out of scope for the MVP: auth, payment, n8n API connection, team features, marketplace integration, server-side workflow storage, and auto-fix.

## Public beta checks

- `tests/fixtures/clean-*.json` workflows should have zero critical/high findings.
- Clean corpus non-info findings should stay at or below 0.05 findings per total node.
- Risky reference workflows should catch webhook auth, webhook direct write, HubSpot create without dedupe, HTTP hardening gaps, credential leaks, and pinned data.
- Workflow JSON stays in the browser. The app does not add analytics, server uploads, or storage.
- `npm run test:privacy` builds production output and fails if unexpected network, storage, or analytics APIs appear in `dist/`.

## Development

```bash
npm install
npm run dev
npm run test
npm run build
npm run test:privacy
```

Use `npm.cmd` instead of `npm` on Windows PowerShell if script execution policy blocks npm shims.
