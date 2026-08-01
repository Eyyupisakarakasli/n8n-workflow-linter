import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { categorizeNode } from '../src/core/n8n/categories'
import { parseWorkflow } from '../src/core/n8n/parse'
import { buildFixChecklist, buildMarkdownReport } from '../src/core/report/markdown'
import { ScannerInputError, scanWorkflowInput, type ScanResult } from '../src/core/scan'
import { demoWorkflows } from '../src/data/demoWorkflows'

const fixturesDir = fileURLToPath(new URL('./fixtures/', import.meta.url))

function fixture(name: string): string {
  const path = fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url))
  return readFileSync(path, 'utf8')
}

function fixtureNames(prefix = ''): string[] {
  return readdirSync(fixturesDir)
    .filter((name) => name.startsWith(prefix) && name.endsWith('.json'))
    .sort()
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

function nonInfoCount(result: ScanResult): number {
  return result.findings.filter((finding) => finding.severity !== 'info').length
}

function buildDeepHttpPostWorkflow({ includeValidation, mappingCount }: { includeValidation: boolean; mappingCount: number }) {
  const nodes = [
    {
      id: 'deep-webhook',
      name: 'Receive Deep Webhook',
      type: 'n8n-nodes-base.webhook',
      typeVersion: 2,
      position: [0, 0],
      parameters: {
        path: 'deep-webhook',
        httpMethod: 'POST',
        authentication: 'headerAuth',
      },
    },
  ]
  const connections: Record<string, { main: Array<Array<{ node: string; type: string; index: number }>> }> = {}
  let previousName = 'Receive Deep Webhook'

  for (let index = 1; index <= mappingCount; index += 1) {
    const nodeName = `Prepare Payload Stage ${index}`
    nodes.push({
      id: `map-${index}`,
      name: nodeName,
      type: 'n8n-nodes-base.set',
      typeVersion: 3,
      position: [index * 180, 0],
      parameters: {
        assignments: {
          assignments: [
            {
              name: `field${index}`,
              value: `={{ $json.field${index} }}`,
            },
          ],
        },
      },
    })
    connections[previousName] = { main: [[{ node: nodeName, type: 'main', index: 0 }]] }
    previousName = nodeName
  }

  if (includeValidation) {
    const validationName = 'Validate Deep Payload'
    nodes.push({
      id: 'deep-validation',
      name: validationName,
      type: 'n8n-nodes-base.if',
      typeVersion: 2,
      position: [(mappingCount + 1) * 180, 0],
      parameters: {
        conditions: {
          string: [
            {
              value1: '={{ $json.email }}',
              operation: 'isNotEmpty',
            },
          ],
        },
      },
    })
    connections[previousName] = { main: [[{ node: validationName, type: 'main', index: 0 }]] }
    previousName = validationName
  }

  nodes.push({
    id: 'deep-http-post',
    name: 'Create External Record',
    type: 'n8n-nodes-base.httpRequest',
    typeVersion: 4,
    position: [(mappingCount + 2) * 180, 0],
    parameters: {
      method: 'POST',
      url: 'https://api.example.com/records',
      options: {
        timeout: 10000,
      },
    },
    retryOnFail: true,
    maxTries: 3,
    onError: 'continueErrorOutput',
  })
  connections[previousName] = { main: [[{ node: 'Create External Record', type: 'main', index: 0 }]] }

  return JSON.stringify({
    name: includeValidation ? 'Deep Validated HTTP POST' : 'Deep Missing Validation HTTP POST',
    nodes,
    connections,
  })
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
    const result = scanWorkflowInput(fixture('risky-schedule-minutes-interval.json'), 'schedule')
    const ruleIds = ids(result)

    expect(ruleIds.has('frequent-schedule-trigger')).toBe(true)
    expect(ruleIds.has('http-missing-timeout')).toBe(true)
    expect(ruleIds.has('http-missing-retry')).toBe(true)
    expect(ruleIds.has('http-missing-error-branch')).toBe(true)
  })

  it('does not flag timeout, retry, error handling, or pagination on hardened HTTP requests', () => {
    const result = scanWorkflowInput(fixture('clean-hardened-http.json'), 'hardened')
    const ruleIds = ids(result)

    expect(ruleIds.has('http-missing-timeout')).toBe(false)
    expect(ruleIds.has('http-missing-retry')).toBe(false)
    expect(ruleIds.has('http-missing-error-branch')).toBe(false)
    expect(ruleIds.has('http-pagination-suspect')).toBe(false)
  })

  it('skips sticky notes and disabled nodes from active production risk checks', () => {
    const raw = JSON.parse(fixture('clean-sticky-disabled.json'))
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
    expect(findingsFor(result, 'disabled-node')).toHaveLength(1)
    expect(findingsFor(result, 'disabled-node')[0].nodeNames).toHaveLength(2)
    expect(ids(result).has('disconnected-critical-node')).toBe(false)
  })

  it('keeps the clean corpus free of critical/high findings within the non-info noise budget', () => {
    const cleanFixtureNames = fixtureNames('clean-')
    const results = cleanFixtureNames.map((name) => scanWorkflowInput(fixture(name), name))
    const totalNodes = results.reduce((sum, result) => sum + result.summary.totalNodes, 0)
    const totalHighCritical = results.reduce((sum, result) => sum + highOrCriticalCount(result), 0)
    const totalNonInfo = results.reduce((sum, result) => sum + nonInfoCount(result), 0)
    const totalFindings = results.reduce((sum, result) => sum + result.findings.length, 0)

    expect(cleanFixtureNames.length).toBeGreaterThanOrEqual(6)
    expect(totalNodes).toBeGreaterThan(0)
    expect(totalHighCritical).toBe(0)
    expect(totalNonInfo / totalNodes).toBeLessThanOrEqual(0.15)
    expect(totalFindings).toBeGreaterThan(totalNonInfo)
  })

  it('preserves the node summary invariant for every fixture', () => {
    for (const name of fixtureNames()) {
      const result = scanWorkflowInput(fixture(name), name)
      expect(result.summary.activeNodes + result.summary.disabledNodes + result.summary.skippedNodes).toBe(
        result.summary.totalNodes,
      )
    }
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

  it('does not flag canonical HubSpot search to IF to update/create as duplicate writes or missing dedupe', () => {
    const result = scanWorkflowInput(fixture('clean-canonical-hubspot-dedupe.json'), 'canonical dedupe')
    const ruleIds = ids(result)

    expect(ruleIds.has('duplicate-write-path')).toBe(false)
    expect(ruleIds.has('hubspot-create-without-dedupe')).toBe(false)
  })

  it('keeps deep validation before a write path from becoming a webhook validation false positive', () => {
    const result = scanWorkflowInput(fixture('clean-deep-validation.json'), 'deep validation')

    expect(ids(result).has('webhook-missing-validation')).toBe(false)
    expect(highOrCriticalCount(result)).toBe(0)
  })

  it('finds write paths beyond 25 hops and still flags missing validation', () => {
    const result = scanWorkflowInput(buildDeepHttpPostWorkflow({ includeValidation: false, mappingCount: 28 }))

    expect(result.summary.totalNodes).toBeGreaterThan(25)
    expect(ids(result).has('webhook-missing-validation')).toBe(true)
  })

  it('does not flag a 25+ hop write path when validation exists before the write', () => {
    const result = scanWorkflowInput(buildDeepHttpPostWorkflow({ includeValidation: true, mappingCount: 28 }))

    expect(result.summary.totalNodes).toBeGreaterThan(25)
    expect(ids(result).has('webhook-missing-validation')).toBe(false)
  })

  it('does not flag a validated and hardened HTTP POST write path as a production blocker', () => {
    const result = scanWorkflowInput(fixture('clean-validated-http-post-write.json'), 'validated http post')

    expect(ids(result).has('webhook-missing-validation')).toBe(false)
    expect(highOrCriticalCount(result)).toBe(0)
  })

  it('flags duplicate writes that can run in the same branch', () => {
    const result = scanWorkflowInput(fixture('risky-same-branch-duplicate-write.json'), 'same branch duplicate')

    expect(ids(result).has('duplicate-write-path')).toBe(true)
  })

  it('counts HTTP POST as a write path after a webhook', () => {
    const result = scanWorkflowInput(fixture('risky-http-post-write.json'), 'http post')

    expect(result.summary.httpNodes).toBe(1)
    expect(ids(result).has('webhook-direct-write')).toBe(true)
    expect(ids(result).has('webhook-missing-validation')).toBe(true)
  })

  it('flags credential IDs, pinned data, known secrets, embedded secrets, URL credentials, and default names', () => {
    const leaky = scanWorkflowInput(fixture('risky-leaky-workflow.json'), 'leaky')
    const defaults = scanWorkflowInput(fixture('risky-default-node-names.json'), 'defaults')
    const leakyRuleIds = ids(leaky)

    expect(leakyRuleIds.has('real-credential-id')).toBe(true)
    expect(leakyRuleIds.has('pinned-data')).toBe(true)
    expect(leakyRuleIds.has('hardcoded-secret')).toBe(true)
    expect(leakyRuleIds.has('embedded-secret')).toBe(true)
    expect(leakyRuleIds.has('credential-in-url')).toBe(true)
    expect(findingsFor(leaky, 'credential-in-url').every((finding) => !finding.nodeNames.includes('Fetch Safely'))).toBe(true)
    expect(ids(defaults).has('default-node-names')).toBe(true)
    expect(findingsFor(defaults, 'default-node-names')).toHaveLength(1)
  })

  it('keeps demo workflows separate from test fixtures and verifies their main findings', () => {
    const demoSourcePath = fileURLToPath(new URL('../src/data/demoWorkflows.ts', import.meta.url))
    const demoSource = readFileSync(demoSourcePath, 'utf8')

    expect(demoSource).not.toContain('../../tests')
    expect(demoWorkflows[0]?.id).toBe('webhook-hubspot-risk')

    const expectedRulesByDemoId: Record<string, string[]> = {
      'webhook-hubspot-risk': ['webhook-missing-secret-check', 'hubspot-create-without-dedupe'],
      'clean-webhook-hubspot-upsert': [],
      'schedule-minutes-interval-risk': ['frequent-schedule-trigger'],
      'leaky-workflow': [
        'real-credential-id',
        'pinned-data',
        'hardcoded-secret',
        'embedded-secret',
        'credential-in-url',
      ],
    }

    for (const demo of demoWorkflows) {
      const result = scanWorkflowInput(demo.json, demo.name)
      const ruleIds = ids(result)

      for (const expectedRule of expectedRulesByDemoId[demo.id] ?? []) {
        expect(ruleIds.has(expectedRule)).toBe(true)
      }

      if (demo.id === 'clean-webhook-hubspot-upsert') {
        expect(highOrCriticalCount(result)).toBe(0)
      }
    }
  })

  it('exports markdown with verdict and fix steps', () => {
    const result = scanWorkflowInput(fixture('risky-webhook-hubspot-create.json'), 'risk')
    const markdown = buildMarkdownReport(result)
    const checklist = buildFixChecklist(result)

    expect(markdown).toContain('Verdict: Fix before production use')
    expect(markdown).toContain('Fix steps')
    expect(checklist).toContain('- [ ]')
  })

  it('keeps privacy scan coupled to a fresh production build', () => {
    const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url))
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { scripts?: Record<string, string> }

    expect(packageJson.scripts?.['test:privacy']).toContain('npm run build')
    expect(packageJson.scripts?.['test:privacy']).toContain('scripts/privacy-scan.mjs')
  })
})
