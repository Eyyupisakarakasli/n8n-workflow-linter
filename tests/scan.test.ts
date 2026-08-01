import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { ScannerInputError, scanWorkflowInput } from '../src/core/scan'

function fixture(name: string): string {
  const path = fileURLToPath(new URL(`../src/data/demo-workflows/${name}`, import.meta.url))
  return readFileSync(path, 'utf8')
}

describe('scanWorkflowInput', () => {
  it('rejects malformed JSON with a user-facing error', () => {
    expect(() => scanWorkflowInput('{not-json')).toThrow(ScannerInputError)
  })

  it('rejects JSON without n8n nodes', () => {
    expect(() => scanWorkflowInput(JSON.stringify({ name: 'No nodes' }))).toThrow('nodes array')
  })

  it('scans the webhook HubSpot demo and reports production risks', () => {
    const result = scanWorkflowInput(fixture('webhook-hubspot-risk.json'), 'demo')

    expect(result.summary.totalNodes).toBe(2)
    expect(result.summary.crmWriteNodes).toBe(1)
    expect(result.findings.some((finding) => finding.ruleId === 'webhook-direct-write')).toBe(true)
    expect(result.findings.some((finding) => finding.ruleId === 'hubspot-create-without-dedupe')).toBe(true)
  })

  it('flags missing API handling and query-string secrets', () => {
    const result = scanWorkflowInput(fixture('api-no-error-handling.json'), 'demo')

    expect(result.findings.some((finding) => finding.ruleId === 'http-missing-timeout')).toBe(true)
    expect(result.findings.some((finding) => finding.ruleId === 'http-missing-error-branch')).toBe(true)
    expect(result.findings.some((finding) => finding.ruleId === 'query-param-secret')).toBe(true)
    expect(result.findings.some((finding) => finding.ruleId === 'frequent-schedule-trigger')).toBe(true)
  })

  it('keeps scanning when connections are missing', () => {
    const result = scanWorkflowInput(
      JSON.stringify({
        name: 'Disconnected test',
        nodes: [
          {
            id: '1',
            name: 'Create HubSpot Contact',
            type: 'n8n-nodes-base.hubspot',
            parameters: { resource: 'contact', operation: 'create' },
          },
        ],
      }),
      'test',
    )

    expect(result.parserWarnings.length).toBeGreaterThan(0)
    expect(result.summary.totalNodes).toBe(1)
  })
})
