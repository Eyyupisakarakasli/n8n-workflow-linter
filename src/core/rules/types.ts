import type { NodeCategory } from '../n8n/categories'
import type { WorkflowGraph } from '../n8n/graph'
import type { N8nNode, NormalizedWorkflow, WorkflowSummary } from '../n8n/types'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'

export interface RuleContext {
  workflow: NormalizedWorkflow
  graph: WorkflowGraph
  categoriesByNodeId: Record<string, NodeCategory[]>
  summary: WorkflowSummary
}

export interface RiskFinding {
  id: string
  ruleId: string
  title: string
  severity: Severity
  category: string
  nodeIds: string[]
  nodeNames: string[]
  problem: string
  whyItMatters: string
  suggestedFix: string
  confidence: Confidence
}

export interface RuleDefinition {
  id: string
  title: string
  category: string
  severity: Severity
  run: (context: RuleContext) => RiskFinding[]
}

export interface FindingInput {
  rule: RuleDefinition
  node: N8nNode
  severity?: Severity
  confidence?: Confidence
  problem: string
  whyItMatters: string
  suggestedFix: string
}
