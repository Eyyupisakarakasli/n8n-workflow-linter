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
    externalActionNodes: workflow.nodes.filter((node) => localExternalActionCategories(categoriesByNodeId[node.id] ?? [], node)).length,
    nodesMissingRetry: 0,
    nodesMissingErrorHandling: 0,
    workflowHasErrorWorkflow: localWorkflowHasErrorWorkflow(originalWorkflow),
  }
}

const httpRollupRuleIds = new Set(['http-missing-error-branch', 'http-missing-retry', 'http-missing-timeout'])
const appRollupRuleIds = new Set(['external-action-missing-error-handling', 'external-action-missing-retry'])
const webhookExposureRuleIds = new Set([
  'webhook-missing-secret-check',
  'webhook-missing-validation',
  'webhook-direct-write',
])

function groupFindings(findings: RiskFinding[]): RiskFinding[] {
  const grouped: RiskFinding[] = []
  const httpCandidates = new Map<string, RiskFinding[]>()
  const appCandidates = new Map<string, RiskFinding[]>()
  const webhookCandidates = new Map<string, RiskFinding[]>()

  for (const finding of findings) {
    if (webhookExposureRuleIds.has(finding.ruleId) && finding.nodeIds.length === 1) {
      const key = finding.nodeIds[0]
      const group = webhookCandidates.get(key) ?? []
      group.push(finding)
      webhookCandidates.set(key, group)
      continue
    }

    if (httpRollupRuleIds.has(finding.ruleId)) {
      const key = `${finding.ruleId}:${finding.severity}`
      const group = httpCandidates.get(key) ?? []
      group.push(finding)
      httpCandidates.set(key, group)
      continue
    }

    if (appRollupRuleIds.has(finding.ruleId)) {
      const key = `${finding.ruleId}:${finding.severity}:${appRollupFlavor(finding)}`
      const group = appCandidates.get(key) ?? []
      group.push(finding)
      appCandidates.set(key, group)
      continue
    }

    grouped.push(finding)
  }

  for (const group of webhookCandidates.values()) {
    grouped.push(group.length > 1 ? groupWebhookExposureFindings(group) : group[0])
  }

  for (const group of httpCandidates.values()) {
    grouped.push(groupHttpFindings(group))
  }

  for (const group of appCandidates.values()) {
    grouped.push(groupAppFindings(group))
  }

  return grouped.sort(compareFindings)
}

function groupWebhookExposureFindings(findings: RiskFinding[]): RiskFinding {
  const representative = findings[0]
  const nodeIds = unique(findings.flatMap((finding) => finding.nodeIds))
  const nodeNames = unique(findings.flatMap((finding) => finding.nodeNames))
  const ruleIds = unique(findings.map((finding) => finding.ruleId))

  return {
    ...representative,
    id: `webhook-production-exposure:group:${nodeIds.join(',')}`,
    ruleId: 'webhook-production-exposure',
    title: 'Public webhook reaches production actions without enough protection',
    plainTitle: 'Public webhook can trigger a production write before checks',
    plainMeaning:
      'This is one root problem: an incoming webhook can reach a CRM/database/API action before clear authentication and payload validation. The individual checks are grouped so the report shows one issue with multiple fixes.',
    fixSteps: [
      'Add Webhook authentication or a signature/HMAC verification step.',
      'Validate required payload fields before any production write or action.',
      'Insert transform/dedupe/idempotency logic before the first CRM, database, or API write.',
    ],
    shareSafetyImpact: 'must-fix',
    severity: 'high',
    category: 'Webhook',
    nodeIds,
    nodeNames,
    problem: `Grouped ${ruleIds.length} webhook exposure checks for this trigger: ${ruleIds.join(', ')}.`,
    whyItMatters:
      'Separately listing auth, validation, and direct-write symptoms overstates the count. Operationally they describe one unsafe webhook-to-action path that should be fixed as a unit.',
    suggestedFix: 'Add authentication/signature verification and validate payload fields before the first production write.',
    confidence: findings.some((finding) => finding.confidence === 'high') ? 'high' : 'medium',
    affectedNodeCount: nodeIds.length,
    groupedRuleIds: ruleIds,
    groupKind: 'webhook-exposure',
  }
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

function groupAppFindings(findings: RiskFinding[]): RiskFinding {
  const representative = findings[0]
  const nodeIds = unique(findings.flatMap((finding) => finding.nodeIds))
  const nodeNames = unique(findings.flatMap((finding) => finding.nodeNames))
  const count = nodeIds.length
  const copy = appRollupCopy(representative.ruleId, count, representative.severity, representative.problem)

  return {
    ...representative,
    id: `${representative.ruleId}:group:${representative.severity}:${nodeIds.join(',')}`,
    title: copy.title,
    plainTitle: copy.plainTitle,
    plainMeaning: copy.plainMeaning,
    fixSteps: copy.fixSteps,
    nodeIds,
    nodeNames,
    problem: copy.problem,
    whyItMatters: copy.whyItMatters,
    suggestedFix: copy.fixSteps[0],
    affectedNodeCount: count,
    groupedRuleIds: [representative.ruleId],
    groupKind: 'app-hardening',
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
    nodesMissingRetry: affectedNodeCountForRules(findings, ['http-missing-retry', 'external-action-missing-retry']),
    nodesMissingErrorHandling: affectedNodeCountForRules(findings, [
      'http-missing-error-branch',
      'http-silent-error-continue',
      'external-action-missing-error-handling',
    ]),
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
      plainTitle: `${count} HTTP ${pluralize(count, 'node')} ${hasOrHave(count)} no error branch`,
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
      plainTitle: `${count} HTTP ${pluralize(count, 'node')} ${hasOrHave(count)} no retry policy`,
      plainMeaning:
        'These HTTP Request nodes have no explicit retry settings. Temporary network failures, 429s, or 5xx responses can break runs that would succeed on a later attempt.',
      fixSteps: [
        'Enable Retry On Fail for each listed HTTP Request node.',
        'Use conservative retry counts and spacing, for example 3 tries with a short wait.',
        'Send repeated failures to an alert or dead-letter path.',
      ],
      problem: `${count} HTTP Request ${pluralize(count, 'node')} ${hasOrHave(count)} no retryOnFail/maxTries policy.`,
      whyItMatters:
        'External APIs often fail transiently. A consistent retry policy reduces avoidable workflow failures and manual reruns.',
    }
  }

  return {
    title: 'HTTP Request nodes have no timeout setting',
    plainTitle: `${count} HTTP ${pluralize(count, 'node')} ${hasOrHave(count)} no timeout`,
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

function appRollupCopy(ruleId: string, count: number, severity: Severity, representativeProblem: string) {
  if (ruleId === 'external-action-missing-error-handling') {
    const isBlocking = severity === 'critical' || severity === 'high'
    const hasWorkflowFallback = representativeProblem.includes('settings.errorWorkflow is configured')

    return {
      title: 'External app nodes have no error handling',
      plainTitle: isBlocking
        ? `${count} external app ${pluralize(count, 'node')} can fail without a recovery path`
        : `${count} external app ${pluralize(count, 'node')} ${hasOrHave(count)} no local error route`,
      plainMeaning: isBlocking
        ? 'These non-HTTP app nodes call services such as HubSpot, Slack, or databases, but do not show an error output branch or equivalent onError routing.'
        : 'These non-HTTP app nodes call external systems and have no local error output branch or onError routing. Review them, especially when the workflow-level error workflow is the only fallback.',
      fixSteps: [
        'Add error output or onError recovery for each listed app node.',
        'Route failures to Slack, email, a log, or a dead-letter path.',
        'Use a workflow-level error workflow as the fallback for failures not handled locally.',
      ],
      problem: hasWorkflowFallback
        ? `${count} external app ${pluralize(count, 'node')} ${hasOrHave(count)} no local error output branch or onError recovery setting; settings.errorWorkflow is configured as the fallback.`
        : `${count} external app ${pluralize(count, 'node')} ${hasOrHave(count)} no local error output branch or onError recovery setting.`,
      whyItMatters: isBlocking
        ? 'App nodes are API calls too. HubSpot, Slack, Postgres, and similar services can fail, rate-limit, or reject data during production runs.'
        : hasWorkflowFallback
          ? 'A workflow-level error workflow is a useful fallback, but local error branches still make expected API failures easier to route, retry, or ignore intentionally.'
        : 'For read-only calls or workflows with a global error workflow, this is still useful hardening but should not dominate the production verdict by itself.',
    }
  }

  return {
    title: 'External app nodes have no retry policy',
    plainTitle: `${count} external app ${pluralize(count, 'node')} ${hasOrHave(count)} no retry policy`,
    plainMeaning:
      'These non-HTTP app nodes call external services but do not enable retryOnFail/maxTries. Transient API failures can break runs that would recover on a retry.',
    fixSteps: [
      'Enable Retry On Fail for each listed app node.',
      'Use conservative retry counts and spacing, for example 3 tries with a short wait.',
      'Pair retries with an error route or workflow-level error workflow.',
    ],
    problem: `${count} external app ${pluralize(count, 'node')} ${hasOrHave(count)} no retryOnFail/maxTries policy.`,
    whyItMatters:
      'External services commonly fail transiently. A consistent retry policy reduces avoidable failed executions and manual reruns.',
  }
}

function appRollupFlavor(finding: RiskFinding): string {
  if (finding.ruleId !== 'external-action-missing-error-handling') return 'default'
  return finding.problem.includes('settings.errorWorkflow is configured') ? 'workflow-fallback' : 'default'
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

function hasOrHave(count: number): 'has' | 'have' {
  return count === 1 ? 'has' : 'have'
}

function localExternalActionCategories(categories: NodeCategory[], node: N8nNode): boolean {
  if (categories.includes('http')) return true
  if (
    categories.includes('hubspot') ||
    categories.includes('crm') ||
    categories.includes('database') ||
    categories.includes('notification')
  ) {
    return true
  }

  return categories.includes('write') && Object.keys(node.credentials).length > 0
}

function localWorkflowHasErrorWorkflow(workflow: NormalizedWorkflow): boolean {
  const settings = workflow.raw.settings
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) return false

  const errorWorkflow = settings.errorWorkflow
  if (typeof errorWorkflow === 'string') return errorWorkflow.trim().length > 0
  if (typeof errorWorkflow === 'number') return Number.isFinite(errorWorkflow)
  if (!errorWorkflow || typeof errorWorkflow !== 'object' || Array.isArray(errorWorkflow)) return false

  return Object.values(errorWorkflow).some((value) => {
    if (typeof value === 'string') return value.trim().length > 0
    if (typeof value === 'number') return Number.isFinite(value)
    return false
  })
}
