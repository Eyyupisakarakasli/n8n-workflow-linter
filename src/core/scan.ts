import { categorizeNode, isNonOperationalNode, type NodeCategory } from './n8n/categories'
import { buildGraph, getDisconnectedNodes } from './n8n/graph'
import { parseWorkflow } from './n8n/parse'
import type { N8nNode, NormalizedWorkflow, WorkflowSummary } from './n8n/types'
import { runRules } from './rules'
import type { RiskFinding, Severity, ShareSafetyImpact } from './rules/types'

export interface ScanResult {
  sourceLabel: string
  workflowName: string
  summary: WorkflowSummary
  findings: RiskFinding[]
  parserWarnings: string[]
  scannedAt: string
  durationMs: number
}

export interface ScanError {
  code: 'empty_input' | 'invalid_json' | 'invalid_workflow'
  title: string
  detail: string
}

export class ScannerInputError extends Error {
  code: ScanError['code']
  title: string
  detail: string

  constructor(error: ScanError) {
    super(error.detail)
    this.name = 'ScannerInputError'
    this.code = error.code
    this.title = error.title
    this.detail = error.detail
  }
}

export function scanWorkflowInput(input: string, sourceLabel = 'Workflow JSON'): ScanResult {
  const startedAt = performance.now()
  const trimmed = input.trim()

  if (!trimmed) {
    throw new ScannerInputError({
      code: 'empty_input',
      title: 'No workflow JSON provided',
      detail: 'Upload a JSON file, paste workflow JSON, or choose a demo workflow.',
    })
  }

  let raw: unknown
  try {
    raw = JSON.parse(trimmed)
  } catch {
    throw new ScannerInputError({
      code: 'invalid_json',
      title: 'Invalid JSON',
      detail: 'The input could not be parsed as JSON. Export the workflow from n8n and try again.',
    })
  }

  const originalWorkflow = parseWorkflow(raw)

  if (originalWorkflow.nodes.length === 0) {
    throw new ScannerInputError({
      code: 'invalid_workflow',
      title: 'No n8n nodes found',
      detail: 'The JSON parsed successfully, but it does not contain a usable n8n nodes array.',
    })
  }

  const skippedNodes = originalWorkflow.nodes.filter(isNonOperationalNode)
  const disabledNodes = originalWorkflow.nodes.filter((node) => node.disabled && !isNonOperationalNode(node))
  const workflow = buildActiveWorkflow(originalWorkflow, disabledNodes, skippedNodes)
  const graph = buildGraph(workflow)
  const categoriesByNodeId = Object.fromEntries(
    workflow.nodes.map((node) => [node.id, categorizeNode(node)]),
  ) as Record<string, NodeCategory[]>
  const summary = summarizeWorkflow(originalWorkflow, workflow, graph, categoriesByNodeId)
  const maxGraphDepth = Math.max(25, workflow.nodes.length + 1)
  const rawFindings = runRules({
    workflow,
    originalWorkflow,
    disabledNodes,
    skippedNodes,
    graph,
    categoriesByNodeId,
    summary,
    maxGraphDepth,
  })
  const findings = groupFindings(rawFindings)
  const enrichedSummary = enrichSummary(summary, findings)

  return {
    sourceLabel,
    workflowName: originalWorkflow.name,
    summary: enrichedSummary,
    findings,
    parserWarnings: originalWorkflow.warnings.map((warning) => warning.message),
    scannedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - startedAt),
  }
}

function buildActiveWorkflow(
  workflow: NormalizedWorkflow,
  disabledNodes: N8nNode[],
  skippedNodes: N8nNode[],
): NormalizedWorkflow {
  const excludedIds = new Set([...disabledNodes, ...skippedNodes].map((node) => node.id))
  const nodes = workflow.nodes.filter((node) => !excludedIds.has(node.id))
  const activeIds = new Set(nodes.map((node) => node.id))
  const nodeById = Object.fromEntries(nodes.map((node) => [node.id, node]))
  const nodeIdByName = Object.fromEntries(nodes.map((node) => [node.name, node.id]))

  return {
    ...workflow,
    nodes,
    nodeById,
    nodeIdByName,
    edges: workflow.edges.filter((edge) => activeIds.has(edge.sourceId) && activeIds.has(edge.targetId)),
  }
}

function summarizeWorkflow(
  originalWorkflow: ReturnType<typeof parseWorkflow>,
  workflow: NormalizedWorkflow,
  graph: ReturnType<typeof buildGraph>,
  categoriesByNodeId: Record<string, NodeCategory[]>,
): WorkflowSummary {
  const categoryMatches = (category: NodeCategory) =>
    workflow.nodes.filter((node) => categoriesByNodeId[node.id]?.includes(category))

  return {
    workflowName: originalWorkflow.name,
    totalNodes: originalWorkflow.nodes.length,
    activeNodes: workflow.nodes.length,
    disabledNodes: originalWorkflow.nodes.filter((node) => node.disabled && !isNonOperationalNode(node)).length,
    skippedNodes: originalWorkflow.nodes.filter(isNonOperationalNode).length,
    totalEdges: workflow.edges.length,
    triggerNodes: workflow.nodes.filter(
      (node) =>
        categoriesByNodeId[node.id]?.includes('webhook') ||
        categoriesByNodeId[node.id]?.includes('schedule') ||
        node.type.toLowerCase().includes('trigger'),
    ).length,
    httpNodes: categoryMatches('http').length,
    crmWriteNodes: workflow.nodes.filter(
      (node) =>
        categoriesByNodeId[node.id]?.includes('write') &&
        (categoriesByNodeId[node.id]?.includes('hubspot') || categoriesByNodeId[node.id]?.includes('crm')),
    ).length,
    disconnectedNodes: getDisconnectedNodes(workflow, graph).length,
    parserWarnings: originalWorkflow.warnings.length,
    affectedNodes: 0,
    httpNodesMissingTimeout: 0,
    httpNodesMissingRetry: 0,
    httpNodesMissingErrorHandling: 0,
    uniqueCredentialLeaks: 0,
  }
}

const httpRollupRuleIds = new Set(['http-missing-error-branch', 'http-missing-retry', 'http-missing-timeout'])

function groupFindings(findings: RiskFinding[]): RiskFinding[] {
  const grouped: RiskFinding[] = []
  const httpCandidates = new Map<string, RiskFinding[]>()

  for (const finding of findings) {
    if (httpRollupRuleIds.has(finding.ruleId)) {
      const key = `${finding.ruleId}:${finding.severity}`
      const group = httpCandidates.get(key) ?? []
      group.push(finding)
      httpCandidates.set(key, group)
      continue
    }

    grouped.push(finding)
  }

  for (const group of httpCandidates.values()) {
    grouped.push(groupHttpFindings(group))
  }

  return grouped.sort(compareFindings)
}

function groupHttpFindings(findings: RiskFinding[]): RiskFinding {
  const representative = findings[0]
  const nodeIds = unique(findings.flatMap((finding) => finding.nodeIds))
  const nodeNames = unique(findings.flatMap((finding) => finding.nodeNames))
  const count = nodeIds.length
  const severity = escalateHttpGroupSeverity(representative.ruleId, representative.severity, count)
  const copy = httpRollupCopy(representative.ruleId, count, severity !== representative.severity)

  return {
    ...representative,
    id: `${representative.ruleId}:group:${representative.severity}:${nodeIds.join(',')}`,
    severity,
    title: copy.title,
    plainTitle: copy.plainTitle,
    plainMeaning: copy.plainMeaning,
    fixSteps: copy.fixSteps,
    shareSafetyImpact: shareImpactForSeverity(severity),
    nodeIds,
    nodeNames,
    problem: copy.problem,
    whyItMatters: copy.whyItMatters,
    suggestedFix: copy.fixSteps[0],
    affectedNodeCount: count,
    groupedRuleIds: [representative.ruleId],
    groupKind: 'http-hardening',
  }
}

function enrichSummary(summary: WorkflowSummary, findings: RiskFinding[]): WorkflowSummary {
  return {
    ...summary,
    affectedNodes: unique(findings.flatMap((finding) => finding.nodeIds)).length,
    httpNodesMissingTimeout: affectedNodeCountForRule(findings, 'http-missing-timeout'),
    httpNodesMissingRetry: affectedNodeCountForRule(findings, 'http-missing-retry'),
    httpNodesMissingErrorHandling: affectedNodeCountForRules(findings, [
      'http-missing-error-branch',
      'http-silent-error-continue',
    ]),
    uniqueCredentialLeaks: findings.filter((finding) => finding.ruleId === 'real-credential-id').length,
  }
}

function affectedNodeCountForRule(findings: RiskFinding[], ruleId: string): number {
  return affectedNodeCountForRules(findings, [ruleId])
}

function affectedNodeCountForRules(findings: RiskFinding[], ruleIds: string[]): number {
  const wanted = new Set(ruleIds)
  return unique(findings.filter((finding) => wanted.has(finding.ruleId)).flatMap((finding) => finding.nodeIds)).length
}

// A single unguarded read call is a medium reliability note. A whole pipeline with no
// error route anywhere is a production blocker: one failed fetch silently produces a
// partial run, and nothing in the workflow reports it.
const systemicHttpNodeThreshold = 5

function escalateHttpGroupSeverity(ruleId: string, severity: Severity, count: number): Severity {
  if (ruleId !== 'http-missing-error-branch') return severity
  if (severity !== 'medium') return severity
  return count >= systemicHttpNodeThreshold ? 'high' : severity
}

function httpRollupCopy(ruleId: string, count: number, escalated = false) {
  if (ruleId === 'http-missing-error-branch') {
    return {
      title: 'HTTP Request nodes have no error branch',
      plainTitle: `${count} HTTP ${pluralize(count, 'node')} have no error branch`,
      plainMeaning: escalated
        ? `None of these ${count} HTTP Request nodes have an error output branch. Each call is a read, so any single failure looks minor, but with no error route anywhere in the path a failed fetch produces a partial run that nothing reports.`
        : 'These HTTP Request nodes do not show an error output branch or equivalent recovery route. A failed API call can stop or distort the workflow without a clear alert path.',
      fixSteps: [
        'Add an error output branch or shared alert/dead-letter route for each listed HTTP Request node.',
        'Prioritize write/action calls first; for read-only feeds, use one shared notification or logging branch.',
        'Re-run the scan after wiring the error paths.',
      ],
      problem: `${count} HTTP Request ${pluralize(count, 'node')} do not show an error branch or continue-on-fail handling.`,
      whyItMatters: escalated
        ? 'At this scale the gap is systemic, not incidental. A scheduled ingestion path with no error route anywhere can keep reporting success while returning incomplete data.'
        : 'API outages and bad responses are common. A shared error path keeps scheduled ingestion and production actions observable when a call fails.',
    }
  }

  if (ruleId === 'http-missing-retry') {
    return {
      title: 'HTTP Request nodes have no retry policy',
      plainTitle: `${count} HTTP ${pluralize(count, 'node')} have no retry policy`,
      plainMeaning:
        'These HTTP Request nodes have no explicit retry settings. Temporary network failures, 429s, or 5xx responses can break runs that would succeed on a later attempt.',
      fixSteps: [
        'Enable Retry On Fail for each listed HTTP Request node.',
        'Use conservative retry counts and spacing, for example 3 tries with a short wait.',
        'Send repeated failures to an alert or dead-letter path.',
      ],
      problem: `${count} HTTP Request ${pluralize(count, 'node')} have no retryOnFail/maxTries policy.`,
      whyItMatters:
        'External APIs often fail transiently. A consistent retry policy reduces avoidable workflow failures and manual reruns.',
    }
  }

  return {
    title: 'HTTP Request nodes have no timeout setting',
    plainTitle: `${count} HTTP ${pluralize(count, 'node')} have no timeout`,
    plainMeaning:
      'These HTTP Request nodes do not expose an explicit timeout setting. Slow third-party APIs can stall workflow execution and let queued retries pile up.',
    fixSteps: [
      'Set an explicit timeout on each listed HTTP Request node.',
      'Use a normal API timeout such as 10-30 seconds unless the endpoint is known to be slow.',
      'Route timeout failures into an error or alert branch.',
    ],
    problem: `${count} HTTP Request ${pluralize(count, 'node')} do not expose a timeout setting in their parameters.`,
    whyItMatters:
      'Timeouts keep slow upstream services from blocking workflow execution longer than expected.',
  }
}

function shareImpactForSeverity(severity: Severity): ShareSafetyImpact {
  return severity === 'critical' || severity === 'high' ? 'must-fix' : 'worth-fixing'
}

function unique(values: string[]): string[] {
  return [...new Set(values)]
}

const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

function compareFindings(a: RiskFinding, b: RiskFinding): number {
  const severityDelta = severityRank[a.severity] - severityRank[b.severity]
  if (severityDelta !== 0) return severityDelta
  return a.title.localeCompare(b.title)
}

function pluralize(count: number, singular: string): string {
  return count === 1 ? singular : `${singular}s`
}
