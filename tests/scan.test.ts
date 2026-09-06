import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { categorizeNode, isReadOperation, isWriteOperation, legacyHubSpotNameLooksWrite } from '../src/core/n8n/categories'
import { parseWorkflow } from '../src/core/n8n/parse'
import { buildFixChecklist, buildMarkdownReport, getReportVerdict } from '../src/core/report/markdown'
import { ScannerInputError, scanWorkflowInput, type ScanResult } from '../src/core/scan'
import { hasPaginationSignal, looksLikeListEndpoint } from '../src/core/rules/helpers'
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

function emailGuardConditions(operation = 'notEmpty') {
  return {
    options: {
      caseSensitive: true,
      leftValue: '',
      typeValidation: 'strict',
      version: 2,
    },
    conditions: [
      {
        id: `email-${operation}`,
        leftValue: '={{ $json.email }}',
        rightValue: '',
        operator: {
          type: 'string',
          operation,
          singleValue: true,
        },
      },
    ],
    combinator: 'and',
  }
}

function fieldGuardCondition(field: string, operation: string) {
  return {
    id: `${field}-${operation}`,
    leftValue: `={{ $json.${field} }}`,
    rightValue: '',
    operator: {
      type: 'string',
      operation,
      singleValue: true,
    },
  }
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
        conditions: emailGuardConditions(),
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

function buildHttpHeavyWorkflow(count: number, method = 'GET') {
  const nodes = Array.from({ length: count }, (_, index) => ({
    id: `http-${index + 1}`,
    name: `Fetch Market Data ${index + 1}`,
    type: 'n8n-nodes-base.httpRequest',
    typeVersion: 4,
    position: [index * 140, 0],
    parameters: {
      method,
      url: `https://api.example.com/market/${index + 1}`,
    },
  }))

  return JSON.stringify({
    name: `${method} HTTP hardening stress`,
    nodes,
    connections: {},
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

  it('groups the public webhook to HubSpot blocker path while keeping the real HubSpot risks', () => {
    const result = scanWorkflowInput(fixture('risky-webhook-hubspot-upsert.json'), 'risk')
    const ruleIds = ids(result)
    const webhookGroup = findingsFor(result, 'webhook-production-exposure')[0]

    expect(ruleIds.has('webhook-production-exposure')).toBe(true)
    expect(webhookGroup.groupedRuleIds?.sort()).toEqual([
      'webhook-direct-write',
      'webhook-missing-secret-check',
      'webhook-missing-validation',
    ])
    expect(ruleIds.has('webhook-missing-secret-check')).toBe(false)
    expect(ruleIds.has('webhook-direct-write')).toBe(false)
    expect(ruleIds.has('webhook-missing-validation')).toBe(false)
    expect(ruleIds.has('hubspot-contact-email-not-required')).toBe(true)
    expect(ruleIds.has('external-action-missing-error-handling')).toBe(true)
    expect(ruleIds.has('external-action-missing-retry')).toBe(true)
    expect(ruleIds.has('workflow-missing-error-workflow')).toBe(true)
    expect(findingsFor(result, 'webhook-test-prod-confusion')[0].severity).toBe('low')
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

  it('counts disabled sticky notes as skipped non-operational nodes, not disabled findings', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Disabled sticky note',
        nodes: [
          {
            id: 'sticky',
            name: 'Sticky Note',
            type: 'n8n-nodes-base.stickyNote',
            disabled: true,
            parameters: {
              content: 'Draft note',
            },
          },
          {
            id: 'disabled-http',
            name: 'Disabled HTTP Draft',
            type: 'n8n-nodes-base.httpRequest',
            disabled: true,
            parameters: {
              method: 'POST',
              url: 'https://api.example.com/orders',
            },
          },
        ],
        connections: {},
      }),
      'disabled sticky',
    )

    expect(result.summary.totalNodes).toBe(2)
    expect(result.summary.activeNodes).toBe(0)
    expect(result.summary.disabledNodes).toBe(1)
    expect(result.summary.skippedNodes).toBe(1)
    expect(findingsFor(result, 'disabled-node')).toHaveLength(1)
    expect(findingsFor(result, 'disabled-node')[0].nodeNames).toEqual(['Disabled HTTP Draft'])
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
    // Recalibrated after finding rollup. Grouping cut the raw finding count, so the old
    // 0.05 budget stopped constraining anything (measured ratio is 0). Keep it scaled to
    // corpus size rather than a flat zero so a genuinely noisy new rule still trips it.
    expect(totalNonInfo / totalNodes).toBeLessThanOrEqual(0.01)
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

  it('does not let outbound HTTP credentials suppress missing webhook authentication', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Unauthenticated webhook to credentialed HTTP read',
        nodes: [
          {
            id: 'webhook',
            name: 'Receive Partner Payload',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'partner-payload',
              authentication: 'none',
            },
          },
          {
            id: 'http',
            name: 'Fetch Account Details',
            type: 'n8n-nodes-base.httpRequest',
            parameters: {
              method: 'GET',
              url: 'https://api.example.com/account',
              authentication: 'predefinedCredentialType',
              options: {
                timeout: 10000,
              },
            },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueErrorOutput',
          },
        ],
        connections: {
          'Receive Partner Payload': {
            main: [[{ node: 'Fetch Account Details', type: 'main', index: 0 }]],
          },
        },
      }),
      'webhook to credentialed http',
    )

    expect(ids(result).has('webhook-missing-secret-check')).toBe(true)
  })

  it('does not treat a generic verify node name as webhook signature verification', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Verify address is not auth',
        nodes: [
          {
            id: 'webhook',
            name: 'Receive Shipping Payload',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'shipping',
              authentication: 'none',
            },
          },
          {
            id: 'code',
            name: 'Verify shipping address',
            type: 'n8n-nodes-base.code',
            parameters: {
              jsCode: 'return items;',
            },
          },
        ],
        connections: {
          'Receive Shipping Payload': {
            main: [[{ node: 'Verify shipping address', type: 'main', index: 0 }]],
          },
        },
      }),
      'generic verify name',
    )

    expect(ids(result).has('webhook-missing-secret-check')).toBe(true)
  })

  it('allows reachable inbound signature verification to satisfy webhook auth checks', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Signed webhook',
        nodes: [
          {
            id: 'webhook',
            name: 'Receive Signed Payload',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'signed-payload',
              authentication: 'none',
            },
          },
          {
            id: 'code',
            name: 'Validate webhook signature',
            type: 'n8n-nodes-base.code',
            parameters: {
              jsCode:
                "const signature = $json.headers['x-hub-signature']; const digest = crypto.createHmac('sha256', $env.WEBHOOK_SECRET).update($json.body).digest('hex'); if (signature !== digest) throw new Error('bad signature'); return items;",
            },
          },
        ],
        connections: {
          'Receive Signed Payload': {
            main: [[{ node: 'Validate webhook signature', type: 'main', index: 0 }]],
          },
        },
      }),
      'signed webhook',
    )

    expect(ids(result).has('webhook-missing-secret-check')).toBe(false)
  })

  it('does not let an unconnected HubSpot search suppress missing email validation', () => {
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

    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
  })

  it('detects legacy HubSpot contact writes without required email validation', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Legacy Typeform to HubSpot contact write',
        nodes: [
          {
            name: 'Typeform Trigger',
            type: 'n8n-nodes-base.typeformTrigger',
            parameters: {
              formId: 'sample-form',
            },
          },
          {
            name: 'Set values',
            type: 'n8n-nodes-base.set',
            parameters: {
              values: {
                string: [
                  {
                    name: 'form_email',
                    value: '={{ $json.email }}',
                  },
                ],
              },
            },
          },
          {
            name: 'create new contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              email: '={{ $json.form_email }}',
              additionalFields: {},
            },
            credentials: {
              hubspotApi: 'hubspot_nodeqa',
            },
            typeVersion: 1,
          },
        ],
        connections: {
          'Typeform Trigger': {
            main: [[{ node: 'Set values', type: 'main', index: 0 }]],
          },
          'Set values': {
            main: [[{ node: 'create new contact', type: 'main', index: 0 }]],
          },
        },
      }),
      'legacy hubspot create',
    )

    expect(result.summary.crmWriteNodes).toBe(1)
    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
  })

  it('detects real-export HubSpot contact upserts when operation is omitted', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Real export default HubSpot upsert',
        nodes: [
          {
            id: 'webhook',
            name: 'Lead Intake',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'lead',
              authentication: 'headerAuth',
            },
          },
          {
            id: 'hubspot',
            name: 'HubSpot2',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              email: '={{ $json.email }}',
            },
            credentials: {
              hubspotApi: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'HubSpot account',
              },
            },
          },
        ],
        connections: {
          'Lead Intake': {
            main: [[{ node: 'HubSpot2', type: 'main', index: 0 }]],
          },
        },
        settings: {
          executionOrder: 'v1',
        },
      }),
      'real hubspot default upsert',
    )

    expect(result.summary.crmWriteNodes).toBe(1)
    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
    expect(findingsFor(result, 'hubspot-contact-email-not-required')[0].problem).toContain(
      'requires email before this HubSpot contact write',
    )
  })

  it('accepts notEmpty as an upstream HubSpot email guard', () => {
    for (const operation of ['notEmpty', 'isNotEmpty']) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: `HubSpot upsert guarded by ${operation}`,
          nodes: [
            {
              id: 'webhook',
              name: 'Lead Intake',
              type: 'n8n-nodes-base.webhook',
              parameters: {
                path: 'lead',
                authentication: 'headerAuth',
              },
            },
            {
              id: 'validate',
              name: 'Validate Lead Email',
              type: 'n8n-nodes-base.if',
              typeVersion: 2.3,
              parameters: {
                conditions: emailGuardConditions(operation),
              },
            },
            {
              id: 'hubspot',
              name: 'HubSpot2',
              type: 'n8n-nodes-base.hubspot',
              parameters: {
                resource: 'contact',
                email: '={{ $json.email }}',
              },
              retryOnFail: true,
              maxTries: 3,
              onError: 'continueErrorOutput',
              credentials: {
                hubspotApi: {
                  id: 'REPLACE_WITH_CREDENTIAL_ID',
                  name: 'HubSpot account',
                },
              },
            },
          ],
          connections: {
            'Lead Intake': {
              main: [[{ node: 'Validate Lead Email', type: 'main', index: 0 }]],
            },
            'Validate Lead Email': {
              main: [[{ node: 'HubSpot2', type: 'main', index: 0 }]],
            },
          },
          settings: {
            executionOrder: 'v1',
            errorWorkflow: 'REPLACE_WITH_ERROR_WORKFLOW_ID',
          },
        }),
        `if filter ${operation}`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
      expect(highOrCriticalCount(result)).toBe(0)
    }
  })

  it('requires HubSpot writes to use the safe IF branch for email guards', () => {
    for (const [operation, writeOutputIndex] of [
      ['notEmpty', 1],
      ['exists', 1],
      ['empty', 0],
      ['notExists', 0],
    ] as const) {
      const outputs: Array<Array<{ node: string; type: string; index: number }>> = [[], []]
      outputs[writeOutputIndex] = [{ node: 'HubSpot Write', type: 'main', index: 0 }]

      const result = scanWorkflowInput(
        JSON.stringify({
          name: `Inverted ${operation} email guard`,
          nodes: [
            {
              id: 'validate',
              name: 'Validate Lead Email',
              type: 'n8n-nodes-base.if',
              parameters: { conditions: emailGuardConditions(operation) },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: {
            'Validate Lead Email': { main: outputs },
          },
        }),
        `inverted ${operation} branch`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
    }
  })

  it('accepts empty email guards only on their false branch', () => {
    for (const operation of ['empty']) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: `${operation} email guard on safe branch`,
          nodes: [
            {
              id: 'validate',
              name: 'Validate Lead Email',
              type: 'n8n-nodes-base.if',
              parameters: { conditions: emailGuardConditions(operation) },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: {
            'Validate Lead Email': { main: [[], [{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
          },
        }),
        `${operation} safe branch`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
    }
  })

  it('does not treat exists or notExists as proof of a nonblank email', () => {
    for (const operation of ['exists', 'notExists']) {
      for (const outputIndex of [0, 1]) {
        const outputs: Array<Array<{ node: string; type: string; index: number }>> = [[], []]
        outputs[outputIndex] = [{ node: 'HubSpot Write', type: 'main', index: 0 }]
        const result = scanWorkflowInput(
          JSON.stringify({
            name: `${operation} is not nonblank proof`,
            nodes: [
              {
                id: 'validate',
                name: 'Check Lead Email',
                type: 'n8n-nodes-base.if',
                parameters: { conditions: emailGuardConditions(operation) },
              },
              {
                id: 'hubspot',
                name: 'HubSpot Write',
                type: 'n8n-nodes-base.hubspot',
                parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
              },
            ],
            connections: { 'Check Lead Email': { main: outputs } },
          }),
          `${operation} output ${outputIndex}`,
        )

        expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
      }
    }
  })

  it('requires an exact current-item email operand on the unary guard', () => {
    for (const [leftValue, rightValue, expectedFinding] of [
      ['={{ $json.email }}', '', false],
      ['{{ $json.email }}', '', false],
      ['$json.email', '', true],
      ["={{ $json['email'] }}", '', false],
      ['={{ $json["email"] }}', '', false],
      ['={{ $json.customerEmail }}', '={{ $json.email }}', true],
      ['={{ $json.emailVerified }}', '', true],
      ['={{ $json.email', '', true],
      ['$json.email }}', '', true],
      ['{{ $json.email', '', true],
      ['={{ $json.email }', '', true],
    ] as const) {
      const conditions = emailGuardConditions('notEmpty')
      conditions.conditions[0].leftValue = leftValue
      conditions.conditions[0].rightValue = rightValue
      const result = scanWorkflowInput(
        JSON.stringify({
          name: 'Exact email operand',
          nodes: [
            {
              id: 'validate',
              name: 'Check Lead Field',
              type: 'n8n-nodes-base.if',
              parameters: { conditions },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: { 'Check Lead Field': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] } },
        }),
        'exact email operand',
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(expectedFinding)
    }
  })

  it('does not apply a current-item email guard to a different HubSpot email mapping', () => {
    for (const email of ['={{ $json.customerEmail }}', '={{ $json.email', '$json.email }}']) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: 'Mismatched HubSpot email mapping',
          nodes: [
            {
              id: 'validate',
              name: 'Check Lead Email',
              type: 'n8n-nodes-base.if',
              parameters: { conditions: emailGuardConditions('notEmpty') },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email },
            },
          ],
          connections: { 'Check Lead Email': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] } },
        }),
        'mismatched HubSpot email mapping',
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
    }
  })

  it('accepts a clearly non-empty literal HubSpot email without an upstream guard', () => {
    for (const [email, expectedFinding] of [
      ['fixed@example.com', false],
      ['   ', true],
      ['={{ $json.customerEmail }}', true],
      ["={{ 'fixed@example.com' }}", true],
      ['={{ $json.email', true],
      ['$json.email }}', true],
    ] as const) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: 'Literal HubSpot email mapping',
          nodes: [
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email },
            },
          ],
          connections: {},
        }),
        'literal HubSpot email mapping',
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(expectedFinding)
    }
  })

  it('does not treat non-main IF outputs as safe guard branches', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'IF error output is not validation',
        nodes: [
          {
            id: 'validate',
            name: 'Check Lead Email',
            type: 'n8n-nodes-base.if',
            parameters: { conditions: emailGuardConditions('notEmpty') },
          },
          {
            id: 'hubspot',
            name: 'HubSpot Write',
            type: 'n8n-nodes-base.hubspot',
            parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
          },
        ],
        connections: { 'Check Lead Email': { error: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] } },
      }),
      'IF error output',
    )

    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
  })

  it('only accepts Filter output when its email condition keeps non-empty items', () => {
    for (const [operation, expectedFinding] of [
      ['notEmpty', false],
      ['empty', true],
    ] as const) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: `Filter with ${operation} email condition`,
          nodes: [
            {
              id: 'filter',
              name: 'Filter Lead Email',
              type: 'n8n-nodes-base.filter',
              parameters: { conditions: emailGuardConditions(operation) },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: {
            'Filter Lead Email': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
          },
        }),
        `filter ${operation}`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(expectedFinding)
    }
  })

  it('requires every incoming path to a HubSpot write to have an email guard', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Merge bypasses email guard',
        nodes: [
          {
            id: 'guarded-source',
            name: 'Guarded Source',
            type: 'n8n-nodes-base.webhook',
            parameters: {},
          },
          {
            id: 'unguarded-source',
            name: 'Unguarded Source',
            type: 'n8n-nodes-base.webhook',
            parameters: {},
          },
          {
            id: 'validate',
            name: 'Validate Lead Email',
            type: 'n8n-nodes-base.if',
            parameters: { conditions: emailGuardConditions('notEmpty') },
          },
          {
            id: 'merge',
            name: 'Merge Leads',
            type: 'n8n-nodes-base.merge',
            parameters: {},
          },
          {
            id: 'hubspot',
            name: 'HubSpot Write',
            type: 'n8n-nodes-base.hubspot',
            parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
          },
        ],
        connections: {
          'Guarded Source': { main: [[{ node: 'Validate Lead Email', type: 'main', index: 0 }]] },
          'Validate Lead Email': { main: [[{ node: 'Merge Leads', type: 'main', index: 0 }]] },
          'Unguarded Source': { main: [[{ node: 'Merge Leads', type: 'main', index: 1 }]] },
          'Merge Leads': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
        },
      }),
      'merge bypass',
    )

    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
  })

  it('preserves email proof through Merge append when every incoming path is guarded', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'All Merge append inputs guarded',
        nodes: [
          { id: 'source-a', name: 'Source A', type: 'n8n-nodes-base.webhook', parameters: {} },
          { id: 'source-b', name: 'Source B', type: 'n8n-nodes-base.webhook', parameters: {} },
          { id: 'guard-a', name: 'Guard A Email', type: 'n8n-nodes-base.if', parameters: { conditions: emailGuardConditions() } },
          { id: 'guard-b', name: 'Guard B Email', type: 'n8n-nodes-base.if', parameters: { conditions: emailGuardConditions() } },
          { id: 'merge', name: 'Append Leads', type: 'n8n-nodes-base.merge', parameters: { mode: 'append' } },
          {
            id: 'hubspot',
            name: 'HubSpot Write',
            type: 'n8n-nodes-base.hubspot',
            parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
          },
        ],
        connections: {
          'Source A': { main: [[{ node: 'Guard A Email', type: 'main', index: 0 }]] },
          'Source B': { main: [[{ node: 'Guard B Email', type: 'main', index: 0 }]] },
          'Guard A Email': { main: [[{ node: 'Append Leads', type: 'main', index: 0 }]] },
          'Guard B Email': { main: [[{ node: 'Append Leads', type: 'main', index: 1 }]] },
          'Append Leads': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
        },
      }),
      'guarded Merge append',
    )

    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
  })

  it('invalidates a guard when Set assigns email before the HubSpot write', () => {
    for (const value of ['', '={{ $json.email.trim().toLowerCase() }}']) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: 'Email changes after validation',
          nodes: [
            {
              id: 'validate',
              name: 'Check Lead Email',
              type: 'n8n-nodes-base.if',
              parameters: { conditions: emailGuardConditions('notEmpty') },
            },
            {
              id: 'set',
              name: 'Change Lead Email',
              type: 'n8n-nodes-base.set',
              parameters: { assignments: { assignments: [{ name: 'email', value }] } },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: {
            'Check Lead Email': { main: [[{ node: 'Change Lead Email', type: 'main', index: 0 }]] },
            'Change Lead Email': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
          },
        }),
        'email changes after validation',
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
    }
  })

  it('accepts normalization followed by a fresh nonblank email guard', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Normalize then validate email',
        nodes: [
          {
            id: 'set',
            name: 'Normalize Lead Email',
            type: 'n8n-nodes-base.set',
            parameters: {
              assignments: {
                assignments: [{ name: 'email', value: '={{ $json.email.trim().toLowerCase() }}' }],
              },
            },
          },
          {
            id: 'validate',
            name: 'Check Normalized Email',
            type: 'n8n-nodes-base.if',
            parameters: { conditions: emailGuardConditions('notEmpty') },
          },
          {
            id: 'hubspot',
            name: 'HubSpot Write',
            type: 'n8n-nodes-base.hubspot',
            parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
          },
        ],
        connections: {
          'Normalize Lead Email': { main: [[{ node: 'Check Normalized Email', type: 'main', index: 0 }]] },
          'Check Normalized Email': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
        },
      }),
      'normalize then validate email',
    )

    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
  })

  it('handles current and legacy Set email mutation and field-retention shapes conservatively', () => {
    const cases: Array<[string, Record<string, unknown>, boolean]> = [
      [
        'current email assignment',
        { assignments: { assignments: [{ name: 'email', value: 'changed@example.com' }] }, includeOtherFields: true },
        true,
      ],
      [
        'legacy email assignment',
        { values: { string: [{ name: 'email', value: 'changed@example.com' }] }, keepOnlySet: false },
        true,
      ],
      [
        'raw JSON output can blank email',
        { mode: 'raw', jsonOutput: '{"email":""}', includeOtherFields: true },
        true,
      ],
      [
        'current drops unassigned email',
        { assignments: { assignments: [{ name: 'status', value: 'ready' }] }, includeOtherFields: false },
        true,
      ],
      [
        'legacy drops unassigned email',
        { values: { string: [{ name: 'status', value: 'ready' }] }, keepOnlySet: true },
        true,
      ],
      [
        'current preserves unassigned email',
        { assignments: { assignments: [{ name: 'status', value: 'ready' }] }, includeOtherFields: true },
        false,
      ],
      [
        'legacy preserves unassigned email',
        { values: { string: [{ name: 'status', value: 'ready' }] }, keepOnlySet: false },
        false,
      ],
    ]

    for (const [name, parameters, expectedFinding] of cases) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name,
          nodes: [
            {
              id: 'validate',
              name: 'Validate Lead Email',
              type: 'n8n-nodes-base.if',
              parameters: { conditions: emailGuardConditions('notEmpty') },
            },
            {
              id: 'set',
              name: 'Edit Lead Fields',
              type: 'n8n-nodes-base.set',
              parameters,
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: {
            'Validate Lead Email': { main: [[{ node: 'Edit Lead Fields', type: 'main', index: 0 }]] },
            'Edit Lead Fields': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
          },
        }),
        name,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(expectedFinding)
    }
  })

  it('handles guarded and unguarded cycles without recursive traversal', () => {
    const build = (guarded: boolean) => {
      const nodes = [
        { id: 'source', name: 'Source', type: 'n8n-nodes-base.webhook', parameters: {} },
        { id: 'a', name: 'Loop A', type: 'n8n-nodes-base.noOp', parameters: {} },
        { id: 'b', name: 'Loop B', type: 'n8n-nodes-base.noOp', parameters: {} },
        {
          id: 'hubspot',
          name: 'HubSpot Write',
          type: 'n8n-nodes-base.hubspot',
          parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
        },
      ]
      const connections: Record<string, { main: Array<Array<{ node: string; type: string; index: number }>> }> = {
        'Loop A': { main: [[{ node: 'Loop B', type: 'main', index: 0 }]] },
        'Loop B': {
          main: [[
            { node: 'Loop A', type: 'main', index: 0 },
            { node: 'HubSpot Write', type: 'main', index: 0 },
          ]],
        },
      }

      if (guarded) {
        nodes.push({
          id: 'validate',
          name: 'Check Lead Email',
          type: 'n8n-nodes-base.if',
          parameters: { conditions: emailGuardConditions('notEmpty') },
        } as never)
        connections.Source = { main: [[{ node: 'Check Lead Email', type: 'main', index: 0 }]] }
        connections['Check Lead Email'] = { main: [[{ node: 'Loop A', type: 'main', index: 0 }]] }
      } else {
        connections.Source = { main: [[{ node: 'Loop A', type: 'main', index: 0 }]] }
      }

      return JSON.stringify({ name: guarded ? 'Guarded cycle' : 'Unguarded cycle', nodes, connections })
    }

    expect(ids(scanWorkflowInput(build(true), 'guarded cycle')).has('hubspot-contact-email-not-required')).toBe(false)
    expect(ids(scanWorkflowInput(build(false), 'unguarded cycle')).has('hubspot-contact-email-not-required')).toBe(true)
  })

  it('handles a deep guarded path iteratively', () => {
    const nodes: Array<Record<string, unknown>> = [
      {
        id: 'validate',
        name: 'Check Lead Email',
        type: 'n8n-nodes-base.if',
        parameters: { conditions: emailGuardConditions('notEmpty') },
      },
    ]
    const connections: Record<string, { main: Array<Array<{ node: string; type: string; index: number }>> }> = {}
    let previous = 'Check Lead Email'

    for (let index = 0; index < 1500; index += 1) {
      const name = `Pass Through ${index}`
      nodes.push({ id: `noop-${index}`, name, type: 'n8n-nodes-base.noOp', parameters: {} })
      connections[previous] = { main: [[{ node: name, type: 'main', index: 0 }]] }
      previous = name
    }

    nodes.push({
      id: 'hubspot',
      name: 'HubSpot Write',
      type: 'n8n-nodes-base.hubspot',
      parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
    })
    connections[previous] = { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] }

    const result = scanWorkflowInput(JSON.stringify({ name: 'Deep guarded path', nodes, connections }), 'deep guard')
    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
  })

  it('does not overclaim email guarantees from multi-condition branches', () => {
    for (const [combinator, emailOperation, outputIndex] of [
      ['or', 'notEmpty', 0],
      ['and', 'empty', 1],
    ] as const) {
      const outputs: Array<Array<{ node: string; type: string; index: number }>> = [[], []]
      outputs[outputIndex] = [{ node: 'HubSpot Write', type: 'main', index: 0 }]

      const result = scanWorkflowInput(
        JSON.stringify({
          name: `${combinator} condition counterexample`,
          nodes: [
            {
              id: 'validate',
              name: 'Validate Lead Email',
              type: 'n8n-nodes-base.if',
              parameters: {
                conditions: {
                  conditions: [
                    fieldGuardCondition('email', emailOperation),
                    fieldGuardCondition('status', 'exists'),
                  ],
                  combinator,
                },
              },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: { 'Validate Lead Email': { main: outputs } },
        }),
        `${combinator} email condition counterexample`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
    }
  })

  it('accepts multi-condition branches only when their formula guarantees email', () => {
    for (const [combinator, emailOperation, outputIndex] of [
      ['and', 'notEmpty', 0],
      ['or', 'empty', 1],
    ] as const) {
      const outputs: Array<Array<{ node: string; type: string; index: number }>> = [[], []]
      outputs[outputIndex] = [{ node: 'HubSpot Write', type: 'main', index: 0 }]

      const result = scanWorkflowInput(
        JSON.stringify({
          name: `${combinator} condition guarantee`,
          nodes: [
            {
              id: 'validate',
              name: 'Validate Lead Email',
              type: 'n8n-nodes-base.if',
              parameters: {
                conditions: {
                  conditions: [
                    fieldGuardCondition('email', emailOperation),
                    fieldGuardCondition('status', 'exists'),
                  ],
                  combinator,
                },
              },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: { 'Validate Lead Email': { main: outputs } },
        }),
        `${combinator} email condition guarantee`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
    }
  })

  it('does not use Switch or branch-node wording as proof of email validation', () => {
    for (const type of ['if', 'filter', 'switch']) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: `${type} wording is not proof`,
          nodes: [
            {
              id: 'branch',
              name: 'Validate required email',
              type: `n8n-nodes-base.${type}`,
              parameters: {
                conditions: {
                  conditions: [
                    {
                      ...fieldGuardCondition('email', 'equals'),
                      rightValue: 'valid',
                    },
                  ],
                  combinator: 'and',
                },
              },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: {
            'Validate required email': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
          },
        }),
        `${type} wording`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
    }

    const switchResult = scanWorkflowInput(
      JSON.stringify({
        name: 'Structured Switch email condition',
        nodes: [
          {
            id: 'switch',
            name: 'Route By Email',
            type: 'n8n-nodes-base.switch',
            parameters: { conditions: emailGuardConditions('notEmpty') },
          },
          {
            id: 'hubspot',
            name: 'HubSpot Write',
            type: 'n8n-nodes-base.hubspot',
            parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
          },
        ],
        connections: { 'Route By Email': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] } },
      }),
      'structured Switch condition',
    )

    expect(ids(switchResult).has('hubspot-contact-email-not-required')).toBe(true)
  })

  it('does not use Code or Function nodes as email-validation proof', () => {
    for (const [name, jsCode] of [
      ['Validate required email', 'return items;'],
      ['Process lead', "if (!$json.email) throw new Error('email is required'); return items;"],
      ['Commented check', "// if (!$json.email) throw new Error('email is required');\nreturn items;"],
    ] as const) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: `${name} code guard`,
          nodes: [
            {
              id: 'code',
              name,
              type: 'n8n-nodes-base.code',
              parameters: { jsCode },
            },
            {
              id: 'hubspot',
              name: 'HubSpot Write',
              type: 'n8n-nodes-base.hubspot',
              parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            },
          ],
          connections: { [name]: { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] } },
        }),
        `${name} code guard`,
      )

      expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
    }
  })

  it('invalidates an earlier email guard across an unknown data-changing node', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Unknown transform after email guard',
        nodes: [
          {
            id: 'validate',
            name: 'Validate Lead Email',
            type: 'n8n-nodes-base.if',
            parameters: { conditions: emailGuardConditions('notEmpty') },
          },
          {
            id: 'code',
            name: 'Transform Lead',
            type: 'n8n-nodes-base.code',
            parameters: { jsCode: 'return items;' },
          },
          {
            id: 'hubspot',
            name: 'HubSpot Write',
            type: 'n8n-nodes-base.hubspot',
            parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
          },
        ],
        connections: {
          'Validate Lead Email': { main: [[{ node: 'Transform Lead', type: 'main', index: 0 }]] },
          'Transform Lead': { main: [[{ node: 'HubSpot Write', type: 'main', index: 0 }]] },
        },
      }),
      'unknown transform after guard',
    )

    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(true)
  })

  it('reports missing HubSpot email input distinctly from missing validation', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'HubSpot contact upsert without email mapping',
        nodes: [
          {
            id: 'hubspot',
            name: 'Update HubSpot',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
            },
            credentials: {
              hubspotApi: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'HubSpot account',
              },
            },
          },
        ],
        settings: {
          executionOrder: 'v1',
        },
      }),
      'hubspot missing email input',
    )

    expect(result.summary.crmWriteNodes).toBe(1)
    expect(findingsFor(result, 'hubspot-contact-email-not-required')[0].problem).toContain('no email input')
  })

  it('treats HubSpot resources with omitted default operations as writes', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Real export default HubSpot deal create',
        nodes: [
          {
            id: 'deal',
            name: 'HubSpot Deal',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'deal',
            },
            credentials: {
              hubspotApi: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'HubSpot account',
              },
            },
          },
        ],
        settings: {
          executionOrder: 'v1',
        },
      }),
      'default hubspot deal',
    )

    expect(result.summary.crmWriteNodes).toBe(1)
    expect(findingsFor(result, 'external-action-missing-error-handling')[0].severity).toBe('high')
  })

  it('treats HubSpot contact list add and remove operations as writes', () => {
    for (const operation of ['add', 'remove']) {
      const result = scanWorkflowInput(
        JSON.stringify({
          name: `HubSpot contact list ${operation}`,
          nodes: [
            {
              id: 'list',
              name: `HubSpot Contact List ${operation}`,
              type: 'n8n-nodes-base.hubspot',
              parameters: {
                resource: 'contactList',
                operation,
              },
              credentials: {
                hubspotApi: {
                  id: 'REPLACE_WITH_CREDENTIAL_ID',
                  name: 'HubSpot account',
                },
              },
            },
          ],
          settings: {
            executionOrder: 'v1',
          },
        }),
        `contact list ${operation}`,
      )

      expect(result.summary.crmWriteNodes).toBe(1)
    }
  })

  it('does not treat default HubSpot contact list writes as contact email upserts', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Real export default HubSpot contact list add',
        nodes: [
          {
            id: 'list',
            name: 'Add Contact To HubSpot List',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contactList',
              by: 'id',
              id: '={{ $json.contactId }}',
              listId: '123',
            },
            credentials: {
              hubspotApi: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'HubSpot account',
              },
            },
          },
        ],
        settings: {
          executionOrder: 'v1',
        },
      }),
      'default contact list add',
    )

    expect(result.summary.crmWriteNodes).toBe(1)
    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
    expect(ids(result).has('email-not-normalized-before-hubspot')).toBe(false)
    expect(ids(result).has('phone-not-normalized-before-hubspot')).toBe(false)
  })

  it('classifies HubSpot form defaults as reads and form submit as a write', () => {
    const defaultFormCategories = categorizeNode({
      id: 'form-default',
      name: 'Get HubSpot Form Fields',
      type: 'n8n-nodes-base.hubspot',
      parameters: {
        resource: 'form',
      },
    })
    const submitFormCategories = categorizeNode({
      id: 'form-submit',
      name: 'Submit HubSpot Form',
      type: 'n8n-nodes-base.hubspot',
      parameters: {
        resource: 'form',
        operation: 'submit',
      },
    })

    expect(defaultFormCategories).not.toContain('write')
    expect(submitFormCategories).toContain('write')
  })

  it('allows upstream email validation to satisfy legacy HubSpot contact writes', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Legacy HubSpot validate then create',
        nodes: [
          {
            name: 'Receive Lead',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'lead',
              authentication: 'headerAuth',
            },
          },
          {
            name: 'Validate Lead Email',
            type: 'n8n-nodes-base.if',
            parameters: {
              conditions: emailGuardConditions('isNotEmpty'),
            },
          },
          {
            name: 'Find HubSpot Contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              operation: 'search',
              email: '={{ $json.email }}',
            },
            alwaysOutputData: true,
            typeVersion: 1,
          },
          {
            name: 'Validate Returned Email',
            type: 'n8n-nodes-base.if',
            parameters: {
              conditions: emailGuardConditions('isNotEmpty'),
            },
          },
          {
            name: 'create new contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              email: '={{ $json.email }}',
            },
            typeVersion: 1,
          },
        ],
        connections: {
          'Receive Lead': {
            main: [[{ node: 'Validate Lead Email', type: 'main', index: 0 }]],
          },
          'Validate Lead Email': {
            main: [[{ node: 'Find HubSpot Contact', type: 'main', index: 0 }]],
          },
          'Find HubSpot Contact': {
            main: [[{ node: 'Validate Returned Email', type: 'main', index: 0 }]],
          },
          'Validate Returned Email': {
            main: [[{ node: 'create new contact', type: 'main', index: 0 }]],
          },
        },
      }),
      'legacy hubspot validate',
    )

    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
  })

  it('does not flag canonical HubSpot search to IF to update/upsert as duplicate writes or missing email validation', () => {
    const result = scanWorkflowInput(fixture('clean-canonical-hubspot-dedupe.json'), 'canonical dedupe')
    const ruleIds = ids(result)

    expect(ruleIds.has('duplicate-write-path')).toBe(false)
    expect(ruleIds.has('hubspot-contact-email-not-required')).toBe(false)
    expect(ruleIds.has('external-action-missing-error-handling')).toBe(false)
    expect(ruleIds.has('external-action-missing-retry')).toBe(false)
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

  it('reads the email guard from the filter structure when no wording can be matched', () => {
    // `empty` on the false output can only clear through the structured, branch-aware
    // reader. Shape copied from a real n8n export (If typeVersion 2.2).
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Structured email guard only',
        nodes: [
          {
            id: 'wh',
            name: 'Receive Lead Webhook',
            type: 'n8n-nodes-base.webhook',
            typeVersion: 2,
            position: [0, 0],
            parameters: { path: 'lead-intake', httpMethod: 'POST', authentication: 'headerAuth' },
          },
          {
            id: 'gate',
            name: 'Email presence gate',
            type: 'n8n-nodes-base.if',
            typeVersion: 2.2,
            position: [240, 0],
            parameters: {
              options: {},
              conditions: {
                options: { version: 2, leftValue: '', caseSensitive: true, typeValidation: 'strict' },
                combinator: 'and',
                conditions: [
                  {
                    id: 'a1f0c9d2-77b4-4e51-9c3a-6b2d8e0f4a15',
                    operator: { type: 'string', operation: 'empty', singleValue: true },
                    leftValue: '={{ $json.email }}',
                    rightValue: '',
                  },
                ],
              },
            },
          },
          {
            id: 'stop',
            name: 'Drop incomplete lead',
            type: 'n8n-nodes-base.noOp',
            typeVersion: 1,
            position: [480, -80],
            parameters: {},
          },
          {
            id: 'hs',
            name: 'Upsert HubSpot Contact By Email',
            type: 'n8n-nodes-base.hubspot',
            typeVersion: 2,
            position: [480, 80],
            parameters: { resource: 'contact', operation: 'upsert', email: '={{ $json.email }}' },
            credentials: { hubspotApi: { id: 'REPLACE_WITH_CREDENTIAL_ID', name: 'HubSpot account' } },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueErrorOutput',
          },
        ],
        connections: {
          'Receive Lead Webhook': { main: [[{ node: 'Email presence gate', type: 'main', index: 0 }]] },
          'Email presence gate': {
            main: [
              [{ node: 'Drop incomplete lead', type: 'main', index: 0 }],
              [{ node: 'Upsert HubSpot Contact By Email', type: 'main', index: 0 }],
            ],
          },
        },
        settings: { executionOrder: 'v1', errorWorkflow: 'REPLACE_WITH_ERROR_WORKFLOW_ID' },
      }),
      'structured-guard-only',
    )

    expect(findingsFor(result, 'hubspot-contact-email-not-required')).toHaveLength(0)
    expect(highOrCriticalCount(result)).toBe(0)
  })

  it('flags duplicate writes that can run in the same branch', () => {
    const result = scanWorkflowInput(fixture('risky-same-branch-duplicate-write.json'), 'same branch duplicate')

    expect(ids(result).has('duplicate-write-path')).toBe(true)
  })

  it('does not treat sequential enrichment HTTP POST calls as duplicate persistent writes', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'AI lead enrichment pipeline',
        nodes: [
          {
            id: 'schedule',
            name: 'Every morning at 8',
            type: 'n8n-nodes-base.scheduleTrigger',
            typeVersion: 1,
            parameters: {
              rule: {
                interval: [
                  {
                    field: 'hours',
                    hoursInterval: 24,
                  },
                ],
              },
            },
          },
          {
            id: 'apify',
            name: 'Fetch fresh leads (Apify)',
            type: 'n8n-nodes-base.httpRequest',
            typeVersion: 4,
            parameters: {
              method: 'POST',
              url: 'https://api.apify.com/v2/acts/example/run-sync-get-dataset-items',
            },
            onError: 'continueRegularOutput',
          },
          {
            id: 'openai',
            name: 'AI: score this lead',
            type: 'n8n-nodes-base.httpRequest',
            typeVersion: 4,
            parameters: {
              method: 'POST',
              url: 'https://api.openai.com/v1/chat/completions',
            },
            onError: 'continueRegularOutput',
          },
          {
            id: 'sheets',
            name: 'Append qualified lead to Google Sheets',
            type: 'n8n-nodes-base.googleSheets',
            typeVersion: 4,
            parameters: {
              resource: 'sheet',
              operation: 'append',
            },
          },
        ],
        connections: {
          'Every morning at 8': {
            main: [[{ node: 'Fetch fresh leads (Apify)', type: 'main', index: 0 }]],
          },
          'Fetch fresh leads (Apify)': {
            main: [[{ node: 'AI: score this lead', type: 'main', index: 0 }]],
          },
          'AI: score this lead': {
            main: [[{ node: 'Append qualified lead to Google Sheets', type: 'main', index: 0 }]],
          },
        },
      }),
      'ai lead enrichment pipeline',
    )

    expect(ids(result).has('duplicate-write-path')).toBe(false)
    expect(findingsFor(result, 'http-missing-retry')).toHaveLength(1)
    expect(findingsFor(result, 'http-missing-retry')[0].nodeNames).toHaveLength(2)
    expect(findingsFor(result, 'http-silent-error-continue')).toHaveLength(2)
  })

  it('rolls repeated HTTP hardening findings up by rule while preserving affected nodes', () => {
    const result = scanWorkflowInput(buildHttpHeavyWorkflow(25), 'http heavy')

    expect(findingsFor(result, 'http-missing-error-branch')).toHaveLength(1)
    expect(findingsFor(result, 'http-missing-retry')).toHaveLength(1)
    expect(findingsFor(result, 'http-missing-timeout')).toHaveLength(1)
    expect(findingsFor(result, 'http-missing-error-branch')[0].nodeNames).toHaveLength(25)
    expect(findingsFor(result, 'http-missing-retry')[0].nodeNames).toHaveLength(25)
    expect(findingsFor(result, 'http-missing-timeout')[0].nodeNames).toHaveLength(25)
    expect(result.summary.httpNodesMissingErrorHandling).toBe(25)
    expect(result.summary.httpNodesMissingRetry).toBe(25)
    expect(result.summary.httpNodesMissingTimeout).toBe(25)
    // Retry/timeout stay medium no matter the scale; only the missing error route escalates.
    expect(findingsFor(result, 'http-missing-retry')[0].severity).toBe('medium')
    expect(findingsFor(result, 'http-missing-timeout')[0].severity).toBe('medium')
  })

  it('escalates a read-only HTTP path to high when no node has an error route', () => {
    // Per-node these are medium GET calls, but a whole ingestion path with no error
    // route anywhere must not report "No production blockers found".
    const systemic = scanWorkflowInput(buildHttpHeavyWorkflow(25), 'http heavy')
    const small = scanWorkflowInput(buildHttpHeavyWorkflow(4), 'http small')

    expect(findingsFor(systemic, 'http-missing-error-branch')[0].severity).toBe('high')
    expect(highOrCriticalCount(systemic)).toBeGreaterThan(0)
    expect(getReportVerdict(systemic).label).toBe('Fix before production use')

    expect(findingsFor(small, 'http-missing-error-branch')[0].severity).toBe('medium')
    expect(highOrCriticalCount(small)).toBe(0)
  })

  it('keeps missing HTTP error branches high for write methods and medium for read methods', () => {
    const readResult = scanWorkflowInput(buildHttpHeavyWorkflow(1, 'GET'), 'http get')
    const writeResult = scanWorkflowInput(buildHttpHeavyWorkflow(1, 'POST'), 'http post')

    expect(findingsFor(readResult, 'http-missing-error-branch')[0].severity).toBe('medium')
    expect(findingsFor(writeResult, 'http-missing-error-branch')[0].severity).toBe('high')
  })

  it('flags retry, error handling, and workflow error gaps on app nodes, not only HTTP Request nodes', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Validated HubSpot app node without reliability settings',
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
            id: 'validate',
            name: 'Validate Lead Email',
            type: 'n8n-nodes-base.if',
            parameters: {
              conditions: emailGuardConditions(),
            },
          },
          {
            id: 'hubspot',
            name: 'Create or Update HubSpot Contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              operation: 'upsert',
              email: '={{ $json.email }}',
            },
            credentials: {
              hubspotApi: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'HubSpot account',
              },
            },
          },
        ],
        connections: {
          'Receive Lead': {
            main: [[{ node: 'Validate Lead Email', type: 'main', index: 0 }]],
          },
          'Validate Lead Email': {
            main: [[{ node: 'Create or Update HubSpot Contact', type: 'main', index: 0 }]],
          },
        },
        settings: {
          executionOrder: 'v1',
        },
      }),
      'app reliability',
    )

    expect(result.summary.httpNodes).toBe(0)
    expect(result.summary.externalActionNodes).toBe(1)
    expect(result.summary.nodesMissingRetry).toBe(1)
    expect(result.summary.nodesMissingErrorHandling).toBe(1)
    expect(result.summary.workflowHasErrorWorkflow).toBe(false)
    expect(ids(result).has('hubspot-contact-email-not-required')).toBe(false)
    expect(ids(result).has('external-action-missing-retry')).toBe(true)
    expect(ids(result).has('external-action-missing-error-handling')).toBe(true)
    expect(findingsFor(result, 'external-action-missing-error-handling')[0].severity).toBe('high')
    expect(ids(result).has('workflow-missing-error-workflow')).toBe(true)
  })

  it('keeps read-only external app error handling gaps at medium severity', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Read-only Gmail sync without local error route',
        nodes: [
          {
            id: 'schedule',
            name: 'Daily digest',
            type: 'n8n-nodes-base.scheduleTrigger',
            parameters: {},
          },
          {
            id: 'gmail',
            name: 'Get Gmail Messages',
            type: 'n8n-nodes-base.gmail',
            parameters: {
              operation: 'getAll',
            },
            credentials: {
              gmailOAuth2: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'Gmail account',
              },
            },
          },
        ],
        connections: {
          'Daily digest': {
            main: [[{ node: 'Get Gmail Messages', type: 'main', index: 0 }]],
          },
        },
        settings: {
          executionOrder: 'v1',
        },
      }),
      'read-only app reliability',
    )

    const errorFinding = findingsFor(result, 'external-action-missing-error-handling')[0]

    expect(errorFinding.severity).toBe('medium')
    expect(errorFinding.plainMeaning).not.toContain('workflow-level error workflow is the only fallback')
    expect(highOrCriticalCount(result)).toBe(0)
    expect(getReportVerdict(result).label).toBe('No production blockers found')
  })

  it('treats Google Sheets append exports without resource as terminal write risks', () => {
    const sheetsNode = {
      id: 'sheets',
      name: 'Log every lead',
      type: 'n8n-nodes-base.googleSheets',
      typeVersion: 4.5,
      parameters: {
        operation: 'append',
        documentId: {
          __rl: true,
          mode: 'url',
          value: 'PASTE_YOUR_GOOGLE_SHEET_URL_HERE',
        },
        sheetName: {
          __rl: true,
          mode: 'name',
          value: 'Leads',
        },
      },
      credentials: {
        googleSheetsOAuth2Api: {
          id: 'REPLACE_WITH_CREDENTIAL_ID',
          name: 'Google Sheets account',
        },
      },
      onError: 'continueRegularOutput',
    }
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Terminal Google Sheets append',
        nodes: [
          {
            id: 'schedule',
            name: 'Daily leads',
            type: 'n8n-nodes-base.scheduleTrigger',
            parameters: {},
          },
          sheetsNode,
        ],
        connections: {
          'Daily leads': {
            main: [[{ node: 'Log every lead', type: 'main', index: 0 }]],
          },
        },
        settings: {
          executionOrder: 'v1',
        },
      }),
      'terminal sheets append',
    )

    const errorFinding = findingsFor(result, 'external-action-missing-error-handling')[0]

    expect(categorizeNode(sheetsNode)).toContain('write')
    expect(result.summary.externalActionNodes).toBe(1)
    expect(result.summary.nodesMissingErrorHandling).toBe(1)
    expect(errorFinding.severity).toBe('high')
    expect(errorFinding.problem).toContain('terminal external write')
    expect(errorFinding.plainMeaning).toContain('no downstream node')
    expect(errorFinding.whyItMatters).toContain('workflow-level error workflow will not fire')
    expect(getReportVerdict(result).label).toBe('Fix before production use')
  })

  it('does not demote silent terminal app writes just because a workflow error workflow exists', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Terminal Google Sheets append with global error workflow',
        nodes: [
          {
            id: 'sheets',
            name: 'Log every lead',
            type: 'n8n-nodes-base.googleSheets',
            parameters: {
              operation: 'append',
            },
            credentials: {
              googleSheetsOAuth2Api: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'Google Sheets account',
              },
            },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueRegularOutput',
          },
        ],
        settings: {
          executionOrder: 'v1',
          errorWorkflow: '42',
        },
      }),
      'terminal sheets append with global fallback',
    )

    const errorFinding = findingsFor(result, 'external-action-missing-error-handling')[0]

    expect(result.summary.workflowHasErrorWorkflow).toBe(true)
    expect(ids(result).has('workflow-missing-error-workflow')).toBe(false)
    expect(errorFinding.severity).toBe('high')
    expect(errorFinding.shareSafetyImpact).toBe('must-fix')
    expect(errorFinding.whyItMatters).toContain('workflow-level error workflow will not fire')
    expect(getReportVerdict(result).label).toBe('Fix before production use')
  })

  it('demotes external write node local error gaps when a workflow error workflow exists', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Slack write with global error workflow',
        nodes: [
          {
            id: 'schedule',
            name: 'Daily notification',
            type: 'n8n-nodes-base.scheduleTrigger',
            parameters: {},
          },
          {
            id: 'slack',
            name: 'Notify Team',
            type: 'n8n-nodes-base.slack',
            parameters: {
              operation: 'send',
              text: '={{ $json.summary }}',
            },
            retryOnFail: true,
            maxTries: 3,
            credentials: {
              slackApi: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'Slack account',
              },
            },
          },
        ],
        connections: {
          'Daily notification': {
            main: [[{ node: 'Notify Team', type: 'main', index: 0 }]],
          },
        },
        settings: {
          executionOrder: 'v1',
          errorWorkflow: '42',
        },
      }),
      'global error workflow fallback',
    )

    const errorFinding = findingsFor(result, 'external-action-missing-error-handling')[0]

    expect(result.summary.workflowHasErrorWorkflow).toBe(true)
    expect(ids(result).has('workflow-missing-error-workflow')).toBe(false)
    expect(errorFinding.severity).toBe('medium')
    expect(errorFinding.shareSafetyImpact).toBe('worth-fixing')
    expect(errorFinding.plainMeaning).toContain('workflow-level error workflow is the only fallback')
    expect(errorFinding.problem).toContain('settings.errorWorkflow is configured')
    expect(highOrCriticalCount(result)).toBe(0)
    expect(getReportVerdict(result).label).toBe('No production blockers found')
  })

  it('flags zero-row search branches and legacy execution order separately', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Search branch without always output data',
        nodes: [
          {
            id: 'schedule',
            name: 'Daily sync',
            type: 'n8n-nodes-base.scheduleTrigger',
            parameters: {},
          },
          {
            id: 'search',
            name: 'Search HubSpot Contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: {
              resource: 'contact',
              operation: 'search',
            },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueErrorOutput',
            credentials: {
              hubspotApi: {
                id: 'REPLACE_WITH_CREDENTIAL_ID',
                name: 'HubSpot account',
              },
            },
          },
          {
            id: 'branch',
            name: 'Contact Found',
            type: 'n8n-nodes-base.if',
            parameters: {},
          },
        ],
        connections: {
          'Daily sync': {
            main: [[{ node: 'Search HubSpot Contact', type: 'main', index: 0 }]],
          },
          'Search HubSpot Contact': {
            main: [[{ node: 'Contact Found', type: 'main', index: 0 }]],
          },
        },
      }),
      'zero-row branch',
    )

    expect(ids(result).has('zero-row-node-may-stop-branch')).toBe(true)
    expect(ids(result).has('legacy-execution-order')).toBe(true)
  })

  it('still flags duplicate persistent HTTP record writes in the same branch', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Duplicate HTTP record writes',
        nodes: [
          {
            id: 'schedule',
            name: 'Every morning',
            type: 'n8n-nodes-base.scheduleTrigger',
            typeVersion: 1,
            parameters: {},
          },
          {
            id: 'order',
            name: 'Create Order In External API',
            type: 'n8n-nodes-base.httpRequest',
            typeVersion: 4,
            parameters: {
              method: 'POST',
              url: 'https://api.example.com/orders',
              options: {
                timeout: 10000,
              },
            },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueErrorOutput',
          },
          {
            id: 'invoice',
            name: 'Create Invoice In External API',
            type: 'n8n-nodes-base.httpRequest',
            typeVersion: 4,
            parameters: {
              method: 'POST',
              url: 'https://api.example.com/invoices',
              options: {
                timeout: 10000,
              },
            },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueErrorOutput',
          },
        ],
        connections: {
          'Every morning': {
            main: [[{ node: 'Create Order In External API', type: 'main', index: 0 }]],
          },
          'Create Order In External API': {
            main: [[{ node: 'Create Invoice In External API', type: 'main', index: 0 }]],
          },
        },
      }),
      'duplicate http record writes',
    )

    expect(ids(result).has('duplicate-write-path')).toBe(true)
  })

  it('counts HTTP POST as a write path after a webhook', () => {
    const result = scanWorkflowInput(fixture('risky-http-post-write.json'), 'http post')
    const webhookGroup = findingsFor(result, 'webhook-production-exposure')[0]

    expect(result.summary.httpNodes).toBe(1)
    expect(ids(result).has('webhook-production-exposure')).toBe(true)
    expect(webhookGroup.groupedRuleIds).toEqual(['webhook-missing-validation', 'webhook-direct-write'])
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

  it('flags known secrets inside pinned workflow data as critical hardcoded secrets', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Pinned secret',
        nodes: [
          {
            id: 'webhook',
            name: 'Receive Payload',
            type: 'n8n-nodes-base.webhook',
            parameters: {
              path: 'payload',
              authentication: 'headerAuth',
            },
          },
        ],
        connections: {},
        pinData: {
          'Receive Payload': [
            {
              json: {
                email: 'customer@example.com',
                apiKey: 'sk-proj-abcdefghijklmnopqrstuvwxyz123456',
              },
            },
          ],
        },
      }),
      'pinned secret',
    )

    expect(ids(result).has('pinned-data')).toBe(true)
    expect(findingsFor(result, 'hardcoded-secret').some((finding) => finding.nodeNames.length === 0)).toBe(true)
    expect(getReportVerdict(result).label).toBe('Fix before production use')
  })

  it('flags known secrets inside workflow staticData and settings', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Envelope secret',
        nodes: [
          {
            id: 'manual',
            name: 'Manual Trigger',
            type: 'n8n-nodes-base.manualTrigger',
            parameters: {},
          },
        ],
        connections: {},
        staticData: {
          cachedAccessKey: 'AKIAABCDEFGHIJKLMNOP',
        },
        settings: {
          deploymentToken: 'ghp_123456789012345678901234567890123456',
        },
      }),
      'envelope secret',
    )

    const hardcoded = findingsFor(result, 'hardcoded-secret')

    expect(hardcoded).toHaveLength(2)
    expect(hardcoded.every((finding) => finding.nodeNames.length === 0)).toBe(true)
    expect(getReportVerdict(result).label).toBe('Fix before production use')
  })

  it('groups repeated real credential IDs by credential type and id', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Repeated credential IDs',
        nodes: [
          {
            id: 'slack-1',
            name: 'Send Slack 1',
            type: 'n8n-nodes-base.slack',
            parameters: {
              operation: 'post',
            },
            credentials: {
              slackOAuth2Api: {
                id: 'slack_credential_real_id',
                name: 'Slack workspace',
              },
            },
          },
          {
            id: 'slack-2',
            name: 'Send Slack 2',
            type: 'n8n-nodes-base.slack',
            parameters: {
              operation: 'post',
            },
            credentials: {
              slackOAuth2Api: {
                id: 'slack_credential_real_id',
                name: 'Slack workspace',
              },
            },
          },
          {
            id: 'slack-3',
            name: 'Send Slack 3',
            type: 'n8n-nodes-base.slack',
            parameters: {
              operation: 'post',
            },
            credentials: {
              slackOAuth2Api: {
                id: 'slack_credential_real_id',
                name: 'Slack workspace',
              },
            },
          },
          {
            id: 'sheets',
            name: 'Append Sheet',
            type: 'n8n-nodes-base.googleSheets',
            parameters: {
              operation: 'append',
            },
            credentials: {
              googleSheetsOAuth2Api: {
                id: 'sheets_credential_real_id',
                name: 'Google Sheets',
              },
            },
          },
        ],
        connections: {},
      }),
      'repeated credentials',
    )

    const credentialFindings = findingsFor(result, 'real-credential-id')

    expect(credentialFindings).toHaveLength(2)
    expect(credentialFindings.find((finding) => finding.nodeNames.includes('Send Slack 1'))?.nodeNames).toHaveLength(3)
    expect(result.summary.uniqueCredentialLeaks).toBe(2)
  })

  it('flags switch nodes with missing fallback outputs', () => {
    const clean = scanWorkflowInput(fixture('clean-switch-all-outputs.json'), 'clean-switch')
    const risky = scanWorkflowInput(fixture('risky-switch-missing-fallback.json'), 'risky-switch')

    expect(findingsFor(clean, 'switch-missing-default')).toHaveLength(0)
    expect(findingsFor(risky, 'switch-missing-default')).toHaveLength(1)
    expect(findingsFor(risky, 'switch-missing-default')[0]?.severity).toBe('medium')
  })

  it('flags IF nodes with no false branch', () => {
    const clean = scanWorkflowInput(fixture('clean-if-both-branches.json'), 'clean-if')
    const risky = scanWorkflowInput(fixture('risky-if-no-false-branch.json'), 'risky-if')

    expect(findingsFor(clean, 'if-missing-false-branch')).toHaveLength(0)
    expect(findingsFor(risky, 'if-missing-false-branch')).toHaveLength(1)
  })

  it('keeps a validation gate before a write out of the verdict', () => {
    // webhook-missing-validation requires a validation step before a production write,
    // and that shape has an empty false branch by design. The IF notice must stay info
    // so the scanner never penalises the pattern it asks for elsewhere.
    const result = scanWorkflowInput(fixture('clean-webhook-hubspot-upsert.json'), 'clean-validation-gate')
    const ifNotices = findingsFor(result, 'if-missing-false-branch')

    expect(ifNotices).toHaveLength(1)
    expect(ifNotices[0]?.severity).toBe('info')
    expect(result.findings.filter((finding) => finding.severity !== 'info')).toHaveLength(0)
    expect(highOrCriticalCount(result)).toBe(0)
  })

  it('does not report a missing timezone when nothing is schedule driven', () => {
    const result = scanWorkflowInput(fixture('clean-webhook-hubspot-upsert.json'), 'clean-no-schedule')

    expect(findingsFor(result, 'default-timezone')).toHaveLength(0)
  })

  it('rejects word salad but accepts 5 and 6 field cron expressions', () => {
    const wordSalad = scanWorkflowInput(
      JSON.stringify({
        name: 'Word salad cron',
        nodes: [
          {
            id: 'sched',
            name: 'Bad schedule',
            type: 'n8n-nodes-base.scheduleTrigger',
            typeVersion: 1,
            position: [0, 0],
            parameters: { rule: { interval: [{ field: 'cronExpression', expression: 'every day at nine am' }] } },
          },
        ],
        connections: {},
        settings: { executionOrder: 'v1', timezone: 'Europe/Istanbul' },
      }),
      'word-salad',
    )
    const withSeconds = scanWorkflowInput(
      JSON.stringify({
        name: 'Six field cron',
        nodes: [
          {
            id: 'sched',
            name: 'Good schedule',
            type: 'n8n-nodes-base.scheduleTrigger',
            typeVersion: 1,
            position: [0, 0],
            parameters: { rule: { interval: [{ field: 'cronExpression', expression: '0 0 9 * * 1-5' }] } },
          },
        ],
        connections: {},
        settings: { executionOrder: 'v1', timezone: 'Europe/Istanbul' },
      }),
      'six-field',
    )

    expect(findingsFor(wordSalad, 'invalid-cron-expression')).toHaveLength(1)
    expect(findingsFor(withSeconds, 'invalid-cron-expression')).toHaveLength(0)
  })

  it('flags invalid cron expressions', () => {
    const risky = scanWorkflowInput(fixture('risky-invalid-cron.json'), 'risky-cron')

    expect(findingsFor(risky, 'invalid-cron-expression')).toHaveLength(1)
  })

  it('flags missing timezone in workflow settings', () => {
    const clean = scanWorkflowInput(fixture('clean-timezone-set.json'), 'clean-tz')
    const risky = scanWorkflowInput(fixture('clean-schedule-without-timezone.json'), 'schedule-no-tz')

    expect(findingsFor(clean, 'default-timezone')).toHaveLength(0)
    expect(findingsFor(risky, 'default-timezone')).toHaveLength(1)
  })

  it('flags monolithic workflows with 50+ active nodes', () => {
    const large = scanWorkflowInput(fixture('clean-monolithic-workflow.json'), 'monolithic')
    const small = scanWorkflowInput(fixture('risky-invalid-cron.json'), 'small')

    expect(findingsFor(large, 'monolithic-workflow')).toHaveLength(1)
    expect(large.findings[0]?.problem).toContain('55')
    expect(findingsFor(small, 'monolithic-workflow')).toHaveLength(0)
  })

  it('keeps demo workflows separate from test fixtures and verifies their main findings', () => {
    const demoSourcePath = fileURLToPath(new URL('../src/data/demoWorkflows.ts', import.meta.url))
    const demoSource = readFileSync(demoSourcePath, 'utf8')

    expect(demoSource).not.toContain('../../tests')
    expect(demoWorkflows[0]?.id).toBe('webhook-hubspot-risk')

    const expectedRulesByDemoId: Record<string, string[]> = {
      'webhook-hubspot-risk': [
        'webhook-production-exposure',
        'hubspot-contact-email-not-required',
        'external-action-missing-error-handling',
      ],
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
    const result = scanWorkflowInput(fixture('risky-webhook-hubspot-upsert.json'), 'risk')
    const markdown = buildMarkdownReport(result)
    const singleBlockingMarkdown = buildMarkdownReport({
      ...result,
      findings: result.findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high').slice(0, 1),
    })
    const checklist = buildFixChecklist(result)

    expect(markdown).toContain('Verdict: Fix before production use')
    expect(markdown).toContain('Scanned locally in the browser with n8n Workflow Linter')
    expect(markdown).toContain('https://n8n-workflow-linter.vercel.app')
    expect(markdown).toContain('critical/high findings affect')
    expect(singleBlockingMarkdown).toContain('1 critical/high finding affects')
    expect(markdown).toContain('Affected nodes')
    expect(markdown).toContain('Fix steps')
    expect(checklist).toContain('- [ ]')
  })

  it('keeps privacy scan coupled to a fresh production build', () => {
    const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url))
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { scripts?: Record<string, string> }

    expect(packageJson.scripts?.['test:privacy']).toContain('npm run build')
    expect(packageJson.scripts?.['test:privacy']).toContain('scripts/privacy-scan.mjs')
  })

  it('flags pagination-less list endpoints but not paginated ones', () => {
    const listNode = { id: 'n1', name: 'List Users', type: 'n8n-nodes-base.httpRequest', parameters: { method: 'GET', url: 'https://api.example.com/users' }, credentials: {} } as any
    const paginatedNode = { ...listNode, id: 'n2', name: 'Paginated List', parameters: { ...listNode.parameters, returnAll: true } }

    expect(looksLikeListEndpoint(listNode)).toBe(true)
    expect(hasPaginationSignal(listNode)).toBe(false)
    expect(looksLikeListEndpoint(paginatedNode)).toBe(true)
    expect(hasPaginationSignal(paginatedNode)).toBe(true)
  })

  it('recognises legacy HubSpot create-contact exports via name heuristic', () => {
    expect(legacyHubSpotNameLooksWrite('create new contact')).toBe(true)
    expect(legacyHubSpotNameLooksWrite('add contact')).toBe(true)
    expect(legacyHubSpotNameLooksWrite('search existing contacts')).toBe(false)
    expect(legacyHubSpotNameLooksWrite('get contact')).toBe(false)
  })

  it('distinguishes read from write HubSpot operations', () => {
    expect(isReadOperation('search')).toBe(true)
    expect(isReadOperation('getAll')).toBe(true)
    expect(isReadOperation('create')).toBe(false)
    expect(isWriteOperation('create')).toBe(true)
    expect(isWriteOperation('upsert')).toBe(true)
  })

  it('drops the normalization findings only when a normalizer really sits upstream', () => {
    // Guards hasNormalizerUpstream. Both workflows are identical apart from the Set node
    // between the webhook and the HubSpot write, so the only thing that can change the
    // normalization findings is whether that node is recognised as a normalizer.
    const build = (normalizes: boolean) =>
      JSON.stringify({
        name: normalizes ? 'Normalized lead' : 'Raw lead',
        nodes: [
          {
            id: 'wh',
            name: 'Receive Lead Webhook',
            type: 'n8n-nodes-base.webhook',
            typeVersion: 2,
            position: [0, 0],
            parameters: { path: 'lead-intake', httpMethod: 'POST', authentication: 'headerAuth' },
          },
          {
            id: 'prep',
            name: 'Prepare lead fields',
            type: 'n8n-nodes-base.set',
            typeVersion: 3,
            position: [240, 0],
            parameters: {
              assignments: {
                assignments: normalizes
                  ? [
                      { name: 'email', value: '={{ $json.email.trim().toLowerCase() }}' },
                      { name: 'phone', value: "={{ String($json.phone || '').replace(/[^0-9+]/g, '') }}" },
                    ]
                  : [{ name: 'stage', value: 'new' }],
              },
            },
          },
          {
            id: 'hs',
            name: 'Upsert HubSpot Contact By Email',
            type: 'n8n-nodes-base.hubspot',
            typeVersion: 2,
            position: [480, 0],
            parameters: {
              resource: 'contact',
              operation: 'upsert',
              email: '={{ $json.email }}',
              additionalFields: { phone: '={{ $json.phone }}' },
            },
            credentials: { hubspotApi: { id: 'REPLACE_WITH_CREDENTIAL_ID', name: 'HubSpot account' } },
            retryOnFail: true,
            maxTries: 3,
            onError: 'continueErrorOutput',
          },
        ],
        connections: {
          'Receive Lead Webhook': { main: [[{ node: 'Prepare lead fields', type: 'main', index: 0 }]] },
          'Prepare lead fields': { main: [[{ node: 'Upsert HubSpot Contact By Email', type: 'main', index: 0 }]] },
        },
        settings: { executionOrder: 'v1', errorWorkflow: 'REPLACE_WITH_ERROR_WORKFLOW_ID' },
      })

    const normalized = scanWorkflowInput(build(true), 'normalized')
    const raw = scanWorkflowInput(build(false), 'raw')

    expect(findingsFor(normalized, 'email-not-normalized-before-hubspot')).toHaveLength(0)
    expect(findingsFor(normalized, 'phone-not-normalized-before-hubspot')).toHaveLength(0)
    expect(findingsFor(raw, 'email-not-normalized-before-hubspot')).toHaveLength(1)
    expect(findingsFor(raw, 'phone-not-normalized-before-hubspot')).toHaveLength(1)
  })

  it('trusts validation wording only on code-like nodes', () => {
    // nodeSearchText serialises parameters, so wording signals must not let an unrelated
    // node claim the validation category. A Postgres node ships a standard `schema`
    // parameter; a Code node that throws on a missing field is real validation.
    const postgres = categorizeNode({
      id: 'pg',
      name: 'Load lookup rows',
      type: 'n8n-nodes-base.postgres',
      typeVersion: 2,
      position: [0, 0],
      parameters: { operation: 'select', schema: 'public', table: 'leads' },
      credentials: {},
    } as never)
    const codeGuard = categorizeNode({
      id: 'code',
      name: 'Validate payload',
      type: 'n8n-nodes-base.code',
      typeVersion: 2,
      position: [0, 0],
      parameters: { jsCode: "if (!$json.email) { throw new Error('email is required'); }" },
      credentials: {},
    } as never)

    expect(postgres).not.toContain('validation')
    expect(codeGuard).toContain('validation')
  })
})
