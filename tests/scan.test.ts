import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { categorizeNode } from '../src/core/n8n/categories'
import { parseWorkflow } from '../src/core/n8n/parse'
import { buildFixChecklist, buildMarkdownReport } from '../src/core/report/markdown'
import { ScannerInputError, scanWorkflowInput, type ScanResult } from '../src/core/scan'

function fixture(name: string): string {
  const path = fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url))
  return readFileSync(path, 'utf8')
}

function ids(result: ScanResult): Set<string> {
  return new Set(result.findings.map((finding) => finding.ruleId))
}

function findingsFor(result: ScanResult, ruleId: string) {
  return result.findings.filter((finding) => finding.ruleId === ruleId)
}

function highOrCriticalCount(result: ScanResult): number {
  return result.findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high').length
}

describe('scanWorkflowInput', () => {
  it('rejects malformed JSON with a user-facing error', () => {
    expect(() => scanWorkflowInput('{not-json')).toThrow(ScannerInputError)
  })

  it('rejects JSON without n8n nodes', () => {
    expect(() => scanWorkflowInput(JSON.stringify({ name: 'No nodes' }))).toThrow('nodes array')
  })

  it('keeps a clean webhook to validation to HubSpot upsert workflow free of critical/high findings', () => {
    const result = scanWorkflowInput(fixture('clean-webhook-hubspot-upsert.json'), 'clean')

    expect(result.summary.totalNodes).toBe(5)
    expect(result.summary.activeNodes).toBe(5)
    expect(result.summary.crmWriteNodes).toBe(1)
    expect(highOrCriticalCount(result)).toBe(0)
    expect(ids(result).has('duplicate-write-path')).toBe(false)
  })

  it('flags the public webhook to HubSpot create blocker path', () => {
    const result = scanWorkflowInput(fixture('risky-webhook-hubspot-create.json'), 'risk')
    const ruleIds = ids(result)

    expect(ruleIds.has('webhook-missing-secret-check')).toBe(true)
    expect(ruleIds.has('webhook-direct-write')).toBe(true)
    expect(ruleIds.has('webhook-missing-validation')).toBe(true)
    expect(ruleIds.has('hubspot-create-without-dedupe')).toBe(true)
  })

  it('detects real n8n minutesInterval schedules and missing HTTP hardening', () => {
    const result = scanWorkflowInput(fixture('schedule-minutes-interval-risk.json'), 'schedule')
    const ruleIds = ids(result)

    expect(ruleIds.has('frequent-schedule-trigger')).toBe(true)
    expect(ruleIds.has('http-missing-timeout')).toBe(true)
    expect(ruleIds.has('http-missing-retry')).toBe(true)
    expect(ruleIds.has('http-missing-error-branch')).toBe(true)
  })

  it('does not flag timeout, retry, error handling, or pagination on hardened HTTP requests', () => {
    const result = scanWorkflowInput(fixture('hardened-http.json'), 'hardened')
    const ruleIds = ids(result)

    expect(ruleIds.has('http-missing-timeout')).toBe(false)
    expect(ruleIds.has('http-missing-retry')).toBe(false)
    expect(ruleIds.has('http-missing-error-branch')).toBe(false)
    expect(ruleIds.has('http-pagination-suspect')).toBe(false)
  })

  it('skips sticky notes and disabled nodes from active production risk checks', () => {
    const raw = JSON.parse(fixture('sticky-disabled.json'))
    const parsed = parseWorkflow(raw)
    const sticky = parsed.nodes.find((node) => node.type.endsWith('stickyNote'))
    const disabledHttp = parsed.nodes.find((node) => node.name === 'Disabled HTTP Request Draft')
    const result = scanWorkflowInput(JSON.stringify(raw), 'sticky-disabled')

    expect(sticky ? categorizeNode(sticky) : ['missing']).toEqual([])
    expect(disabledHttp ? categorizeNode(disabledHttp) : ['missing']).toEqual([])
    expect(result.summary.disabledNodes).toBe(2)
    expect(result.summary.skippedNodes).toBe(1)
    expect(result.summary.activeNodes).toBe(0)
    expect(result.findings.every((finding) => finding.severity === 'info')).toBe(true)
    expect(ids(result).has('disconnected-critical-node')).toBe(false)
  })

  it('does not treat x-api-key header names or credential expressions as hardcoded secrets', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Safe credential expression',
        nodes: [
          {
            id: 'http-safe',
            name: 'Fetch With Credential Expression',
            type: 'n8n-nodes-base.httpRequest',
            parameters: {
              method: 'GET',
              url: 'https://api.example.com/status',
              headerParameters: {
                parameters: [
                  {
                    name: 'x-api-key',
                    value: '={{ $credentials.apiKey }}',
                  },
                ],
              },
              options: {
                timeout: 10000,
              },
            },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueErrorOutput',
          },
        ],
        connections: {},
      }),
      'safe expression',
    )

    expect(ids(result).has('hardcoded-secret')).toBe(false)
    expect(ids(result).has('embedded-secret')).toBe(false)
    expect(ids(result).has('credential-in-url')).toBe(false)
  })

  it('does not flag authenticated webhooks as unauthenticated', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Authenticated webhook',
        nodes: [
          {
            id: 'webhook-auth',
            name: 'Receive Partner Event',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'partner-event',
              authentication: 'headerAuth',
            },
          },
        ],
        connections: {},
      }),
      'auth webhook',
    )

    expect(ids(result).has('webhook-missing-secret-check')).toBe(false)
  })

  it('does not let an unconnected HubSpot search suppress create-without-dedupe', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Disconnected HubSpot search',
        nodes: [
          {
            id: 'webhook',
            name: 'Receive Lead',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'lead',
              authentication: 'headerAuth',
            },
          },
          {
            id: 'search',
            name: 'Search HubSpot Contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              operation: 'search',
            },
          },
          {
            id: 'create',
            name: 'Create HubSpot Contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              operation: 'create',
              email: '={{ $json.email }}',
            },
          },
        ],
        connections: {
          'Receive Lead': {
            main: [
              [
                {
                  node: 'Create HubSpot Contact',
                  type: 'main',
                  index: 0,
                },
              ],
            ],
          },
        },
      }),
      'disconnected search',
    )

    expect(ids(result).has('hubspot-create-without-dedupe')).toBe(true)
  })

  it('counts HTTP POST as a write path after a webhook', () => {
    const result = scanWorkflowInput(fixture('http-post-write.json'), 'http post')

    expect(result.summary.httpNodes).toBe(1)
    expect(ids(result).has('webhook-direct-write')).toBe(true)
    expect(ids(result).has('webhook-missing-validation')).toBe(true)
  })

  it('flags credential IDs, pinned data, known secrets, embedded secrets, URL credentials, and default names', () => {
    const leaky = scanWorkflowInput(fixture('leaky-workflow.json'), 'leaky')
    const defaults = scanWorkflowInput(fixture('default-node-names.json'), 'defaults')
    const leakyRuleIds = ids(leaky)

    expect(leakyRuleIds.has('real-credential-id')).toBe(true)
    expect(leakyRuleIds.has('pinned-data')).toBe(true)
    expect(leakyRuleIds.has('hardcoded-secret')).toBe(true)
    expect(leakyRuleIds.has('embedded-secret')).toBe(true)
    expect(leakyRuleIds.has('credential-in-url')).toBe(true)
    expect(findingsFor(leaky, 'credential-in-url').every((finding) => !finding.nodeNames.includes('Fetch Safely'))).toBe(true)
    expect(ids(defaults).has('default-node-names')).toBe(true)
  })

  it('exports markdown with verdict and fix steps', () => {
    const result = scanWorkflowInput(fixture('risky-webhook-hubspot-create.json'), 'risk')
    const markdown = buildMarkdownReport(result)
    const checklist = buildFixChecklist(result)

    expect(markdown).toContain('Verdict: Do not share this workflow yet')
    expect(markdown).toContain('Fix steps')
    expect(checklist).toContain('- [ ]')
  })
})
