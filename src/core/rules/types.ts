import type { NodeCategory } from '../n8n/categories'
import type { WorkflowGraph } from '../n8n/graph'
import type { N8nNode, NormalizedWorkflow, WorkflowSummary } from '../n8n/types'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'

export interface RuleContext {
  workflow: NormalizedWorkflow
  originalWorkflow: NormalizedWorkflow
  disabledNodes: N8nNode[]
  skippedNodes: N8nNode[]
  graph: WorkflowGraph
  categoriesByNodeId: Record<string, NodeCategory[]>
  summary: WorkflowSummary
}

export type ShareSafetyImpact = 'must-fix' | 'worth-fixing' | 'minor'

export interface RiskFinding {
  id: string
  ruleId: string
  title: string
  plainTitle: string
  plainMeaning: string
  fixSteps: string[]
  shareSafetyImpact: ShareSafetyImpact
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
  plainTitle: string
  plainMeaning: string
  fixSteps: string[]
  shareSafetyImpact: ShareSafetyImpact
  category: string
  defaultSeverity: Severity
  run: (context: RuleContext) => RiskFinding[]
}

export interface FindingInput {
  rule: RuleDefinition
  node?: N8nNode
  nodes?: N8nNode[]
  severity?: Severity
  confidence?: Confidence
  problem: string
  whyItMatters: string
  suggestedFix?: string
  plainTitle?: string
  plainMeaning?: string
  fixSteps?: string[]
  shareSafetyImpact?: ShareSafetyImpact
}
