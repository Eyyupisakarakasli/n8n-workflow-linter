# Public beta test plan

Use this plan for the first 5-10 real n8n workflow exports before wider distribution.

## Goal

Confirm that the scanner is useful for real n8n users without giving false confidence or producing noisy blocker findings.

## Test rules

- Do not upload or paste workflows that contain real secrets, customer payloads, pinned data, or private credential IDs into public channels.
- Keep raw workflow JSON private unless it is fully sanitized.
- Prefer sharing the exported markdown report plus a redacted workflow shape.
- Record both false positives and missed risks. Both matter.

## Workflow sample mix

Test at least:

- 2 webhook-driven workflows that write to a CRM, database, or external API
- 1 workflow using HubSpot update/search/upsert or Create or Update contact
- 1 schedule-triggered workflow that calls HTTP APIs
- 1 workflow with intentionally disabled draft nodes or Sticky Notes
- 1 workflow you believe is production-safe
- 1 workflow you know has a risk, such as pinned data, missing webhook auth, missing email validation, or missing app-node error handling

## Result log template

Copy one block per tested workflow.

```md
### Workflow test

- Date:
- Tester:
- n8n version, if known:
- Workflow type:
- Redacted workflow shape:
- Scanner verdict:
- Critical/high count:
- Total findings:
- Findings that looked correct:
- False positives:
- Missed risks:
- Confusing copy:
- Parse/import issues:
- Would you fix something because of this report? yes/no
- Notes:
```

## Acceptance signals

Public beta is healthy when:

- Safe real workflows do not produce critical/high findings without a defensible reason.
- Risky real workflows surface at least one concrete, fixable issue.
- Users can understand the first verdict without an explanation call.
- Users can export markdown and send feedback without sharing raw JSON.

Use manual feedback counts only. Do not add analytics for this beta pass.

- How many people received the link
- How many people said they scanned a workflow
- How many markdown reports or notes came back
- How many people said they would fix something because of the report
- Which rule created the most value
- Which rule created the most noise

## Stop or rollback signals

Pause wider distribution if:

- Multiple clean real workflows get critical/high false positives.
- Users cannot understand what to fix from the report.
- A common n8n export shape fails to parse.
- The live app makes any unexpected network request beyond static asset loading.
