# n8n Workflow Linter

Client-side public beta for checking whether exported n8n workflow JSON files are safe to share or ready for production review.

Upload your workflow JSON and get a local safe-to-share and production-readiness report before sharing a template, asking for feedback, or putting a workflow into production.

Live public beta: https://n8n-workflow-linter.vercel.app

## How to use

1. Open the live beta URL.
2. Export a workflow JSON file from n8n, or choose one of the sample workflows.
3. Drop, choose, or paste the workflow JSON.
4. Click `Scan workflow`.
5. Review the verdict, grouped findings, fix steps, and downloadable markdown report.
6. Send feedback from the app with the exported markdown report, not raw workflow JSON.

## Privacy

- Workflow JSON is parsed and scanned in your browser.
- The scanner does not require auth, payment, n8n API access, or a team account.
- The app does not intentionally upload workflow JSON, store workflow data, or add analytics.
- `npm run test:privacy` builds the production bundle and fails if unexpected network, storage, analytics APIs, or external asset origins appear in `dist/`.

Do not send raw workflow JSON as feedback unless you have removed secrets, customer data, pinned data, and private credential IDs.

## Scope

- JSON upload, paste input, and demo workflow examples
- Local browser scanner with a Web Worker
- n8n parser, graph helpers, and deterministic risk rules
- Active scan excludes disabled nodes and non-operational nodes such as Sticky Note / NoOp
- Security rules for known secret formats, credential-shaped values, credential IDs, URL query credentials, and pinned data
- Injection rules for webhook data reaching a SQL query or an AI prompt with no validation step in between
- Reliability rules for webhook validation/auth, HubSpot email requirements, grouped HTTP/app retry and error handling, workflow error workflow settings, frequent schedules, duplicate write paths, and disconnected action nodes
- Verdict, severity grouped report, parser warnings, markdown report export, and fix checklist copy

Out of scope for the MVP: auth, payment, n8n API connection, team features, marketplace integration, server-side workflow storage, and auto-fix.

## What it checks

- Public webhook exposure and missing webhook authentication
- Webhook payloads reaching write/action nodes before validation
- Direct webhook-to-write paths
- HubSpot contact writes that can run without a required email check
- External app nodes such as HubSpot, Slack, and databases without retry or error handling
- Missing workflow-level error workflow settings
- Search/list nodes that can silently stop a branch on zero results
- Branching workflows missing `settings.executionOrder: "v1"`
- Duplicate CRM/database/API write paths from the same trigger
- HTTP request timeout, retry, error branch, and pagination signals
- Frequent schedule triggers that can amplify failures
- Known hardcoded secret formats, credential-shaped values, URL credentials, real credential IDs, and pinned data
- Disabled nodes, Sticky Note/no-op handling, disconnected action nodes, and default node names

## What it does not guarantee

- It cannot prove runtime behavior, API permissions, credential validity, rate limits, or business logic correctness.
- It cannot inspect your n8n instance, executions, or environment variables.
- It does not auto-fix workflows.
- It is a pre-production reliability review, not a replacement for testing the workflow in n8n.

## Public beta checks

- `tests/fixtures/clean-*.json` workflows should have zero critical/high findings.
- Clean corpus non-info findings should stay at or below 0.01 findings per total node.
- HTTP-heavy workflows should report grouped hardening issues instead of repeating the same fix card per node.
- Risky reference workflows should catch grouped webhook exposure, HubSpot missing-email risk, HTTP/app hardening gaps, credential leaks, and pinned data.
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

## Beta feedback

Use the in-app feedback links or reply in the public n8n community thread. Send only the exported markdown report and a short note about what looked wrong. Avoid sharing raw workflow JSON.

Useful feedback includes:

- The verdict shown by the scanner
- Finding IDs that looked wrong
- Whether the workflow is a clean workflow, intentionally risky workflow, or real production workflow
- Expected result versus actual result
- n8n node types involved, with sensitive names and values redacted

## Launch docs

- `docs/launch-checklist.md`: founder checklist for the first public beta pass
- `docs/beta-launch-copy.md`: short post, community post, direct message, and feedback request copy
- `docs/beta-test-plan.md`: manual real-workflow test plan and result log template

## License

[MIT](LICENSE) © Eyyüp İsa Karakaşlı
