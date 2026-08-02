export type JsonObject = Record<string, unknown>

export interface RawN8nNode extends JsonObject {
  id?: string
  name?: string
  type?: string
  typeVersion?: number
  position?: [number, number]
  parameters?: JsonObject
  credentials?: JsonObject
  disabled?: boolean
  retryOnFail?: boolean
  maxTries?: number
  waitBetweenTries?: number
  continueOnFail?: boolean
  onError?: string
  alwaysOutputData?: boolean
  notes?: string
}

export interface RawN8nWorkflow extends JsonObject {
  id?: string
  name?: string
  nodes?: RawN8nNode[]
  connections?: RawN8nConnections
  pinData?: JsonObject
  settings?: JsonObject
}

export interface RawN8nConnectionTarget extends JsonObject {
  node?: string
  type?: string
  index?: number
}

export type RawN8nConnectionGroup = RawN8nConnectionTarget[]
export type RawN8nConnectionOutput = RawN8nConnectionGroup[]
export type RawN8nConnections = Record<string, Record<string, RawN8nConnectionOutput>>

export interface N8nNode {
  id: string
  name: string
  type: string
  typeVersion?: number
  parameters: JsonObject
  credentials: JsonObject
  disabled: boolean
  retryOnFail: boolean
  maxTries?: number
  waitBetweenTries?: number
  continueOnFail: boolean
  onError?: string
  alwaysOutputData: boolean
  notes?: string
  raw: RawN8nNode
}

export interface ConnectionEdge {
  sourceId: string
  sourceName: string
  targetId: string
  targetName: string
  outputType: string
  outputIndex: number
  inputIndex: number
}

export type ParserWarningCode =
  | 'invalid_shape'
  | 'missing_nodes'
  | 'empty_nodes'
  | 'missing_connections'
  | 'missing_node_name'
  | 'missing_node_type'
  | 'duplicate_node_name'
  | 'missing_connection_source'
  | 'missing_connection_target'
  | 'unsupported_connection_shape'

export interface ParserWarning {
  code: ParserWarningCode
  message: string
  nodeName?: string
}

export interface NormalizedWorkflow {
  id?: string
  name: string
  nodes: N8nNode[]
  nodeById: Record<string, N8nNode>
  nodeIdByName: Record<string, string>
  edges: ConnectionEdge[]
  warnings: ParserWarning[]
  raw: RawN8nWorkflow
  rawText?: string
}

export interface WorkflowSummary {
  workflowName: string
  totalNodes: number
  activeNodes: number
  disabledNodes: number
  skippedNodes: number
  totalEdges: number
  triggerNodes: number
  httpNodes: number
  crmWriteNodes: number
  disconnectedNodes: number
  parserWarnings: number
  affectedNodes: number
  httpNodesMissingTimeout: number
  httpNodesMissingRetry: number
  httpNodesMissingErrorHandling: number
  uniqueCredentialLeaks: number
  externalActionNodes: number
  nodesMissingRetry: number
  nodesMissingErrorHandling: number
  workflowHasErrorWorkflow: boolean
}
