# Beta launch copy

Live beta: https://n8n-workflow-linter.vercel.app

## Short post

I built a small browser-based linter for exported n8n workflows.

It scans workflow JSON locally and flags production risks like public webhooks without auth, write paths without validation, HubSpot create steps without dedupe, weak HTTP retry/error handling, pinned data, and embedded secrets.

No login. No n8n API connection. No workflow upload to a server.

Try it here: https://n8n-workflow-linter.vercel.app

Useful feedback: false positives, missed risks, confusing report copy, and real n8n exports that fail to parse.

## n8n community post

I am testing a public beta for an n8n Workflow Linter:

https://n8n-workflow-linter.vercel.app

It reads exported workflow JSON in the browser and gives a reliability/security report before a workflow is shared or used in production.

Current checks include:

- webhook auth and validation gaps
- direct webhook-to-write paths
- HubSpot create without dedupe/search/upsert
- duplicate CRM/database/API write paths
- HTTP timeout, retry, error branch, and pagination signals
- pinned data, hardcoded secrets, credential-shaped values, and real credential IDs
- disabled nodes and default node names

The beta does not connect to your n8n instance and does not upload workflow JSON to a server.

I am looking for feedback on false positives, missed risks, confusing findings, and real exported workflows that do not parse correctly. Please do not share raw workflow JSON publicly if it contains secrets, customer data, pinned data, or private credential IDs.

## Direct message

I shipped a small public beta that checks exported n8n workflow JSON for production risks before sharing or deploying it:

https://n8n-workflow-linter.vercel.app

It runs locally in the browser, no login or n8n connection. If you have 5 minutes, scan one workflow and tell me whether the report looks accurate or noisy.

Please do not send raw workflow JSON unless it is fully sanitized. The exported markdown report is enough.

## Feedback request

When you send feedback, the most useful format is:

- Verdict shown
- Finding IDs that looked wrong
- Expected result
- Actual result
- Safe redacted workflow shape, for example `Webhook -> IF -> HubSpot search -> IF -> update/create`
