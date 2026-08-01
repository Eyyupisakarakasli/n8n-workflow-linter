# Public beta launch checklist

Live beta: https://n8n-workflow-linter.vercel.app

## Done before sharing

- Production deployment is live.
- Default demo shows scanner value immediately.
- README explains usage, privacy, scope, checks, and limits.
- Feedback issue template exists for collaborators.
- CI verifies tests, lint, build, privacy scan, and production dependency audit.
- Clean corpus has zero critical/high findings.

## Manual steps for the founder

1. Open the live URL in a normal browser.
2. Scan the default risky demo and confirm the verdict says `Fix before production use`.
3. Scan one clean sample and confirm the verdict says `All clear`.
4. Test 5-10 real exported workflows using `docs/beta-test-plan.md`.
5. Save only redacted notes or exported markdown reports.
6. Send the short post or direct message from `docs/beta-launch-copy.md`.
7. Track each issue as one of:
   - false positive
   - missed risk
   - confusing copy
   - parser/export format problem
   - UI problem
8. Record manual beta metrics in the founder results note; do not add analytics for this beta pass.

## Where to share first

Start narrow before posting broadly:

- 3-5 n8n users you can message directly
- a small automation/freelancer Discord or Slack group
- n8n community after at least a few real workflow checks
- LinkedIn/X only after the first feedback pass

## Feedback triage rule

Prioritize in this order:

1. Missed critical/high risks in real workflows
2. Critical/high false positives in clean real workflows
3. Parser failures on normal n8n exports
4. Confusing fix steps
5. UI polish

Do not add auth, payment, n8n API connection, team features, marketplace integration, analytics, or server-side workflow storage during this beta pass.

## Deployment maintenance

GitHub auto deploy is connected in Vercel:

- Repository: `Eyyupisakarakasli/n8n-workflow-linter`
- Production branch: `main`
- Pushes to `main` should create production deployments according to the Vercel project settings.

Before pushing beta changes, run:

```bash
npm.cmd run test
npm.cmd run lint
npm.cmd run build
npm.cmd run test:privacy
npm.cmd audit --omit=dev --audit-level=moderate
git push
```

If Git auto deploy is unavailable, use the manual fallback:

```bash
vercel.cmd build --prod
vercel.cmd deploy --prebuilt --prod
```
