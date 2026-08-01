import { categorizeNode } from './n8n/categories'
import { buildGraph, getDisconnectedNodes } from './n8n/graph'
import { parseWorkflow } from './n8n/parse'
import type { WorkflowSummary } from './n8n/types'
import { runRules } from './rules'
import type { RiskFinding } from './rules/types'

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

  const workflow = parseWorkflow(raw)

  if (workflow.nodes.length === 0) {
    throw new ScannerInputError({
      code: 'invalid_workflow',
      title: 'No n8n nodes found',
      detail: 'The JSON parsed successfully, but it does not contain a usable n8n nodes array.',
    })
  }

  const graph = buildGraph(workflow)
  const categoriesByNodeId = Object.fromEntries(
    workflow.nodes.map((node) => [node.id, categorizeNode(node)]),
  )
  const summary = summarizeWorkflow(workflow, graph, categoriesByNodeId)
  const findings = runRules({ workflow, graph, categoriesByNodeId, summary })

  return {
    sourceLabel,
    workflowName: workflow.name,
    summary,
    findings,
    parserWarnings: workflow.warnings.map((warning) => warning.message),
    scannedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - startedAt),
  }
}

function summarizeWorkflow(
  workflow: ReturnType<typeof parseWorkflow>,
  graph: ReturnType<typeof buildGraph>,
  categoriesByNodeId: Record<string, string[]>,
): WorkflowSummary {
  const categoryMatches = (category: string) =>
    workflow.nodes.filter((node) => categoriesByNodeId[node.id]?.includes(category))

  return {
    workflowName: workflow.name,
    totalNodes: workflow.nodes.length,
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
    parserWarnings: workflow.warnings.length,
  }
}
