import type { ConnectionEdge, N8nNode, NormalizedWorkflow } from './types'

export interface WorkflowGraph {
  outgoingById: Record<string, ConnectionEdge[]>
  incomingById: Record<string, ConnectionEdge[]>
}

export function buildGraph(workflow: NormalizedWorkflow): WorkflowGraph {
  const outgoingById: Record<string, ConnectionEdge[]> = {}
  const incomingById: Record<string, ConnectionEdge[]> = {}

  for (const node of workflow.nodes) {
    outgoingById[node.id] = []
    incomingById[node.id] = []
  }

  for (const edge of workflow.edges) {
    outgoingById[edge.sourceId]?.push(edge)
    incomingById[edge.targetId]?.push(edge)
  }

  return { outgoingById, incomingById }
}

export function getDownstreamNodes(
  workflow: NormalizedWorkflow,
  graph: WorkflowGraph,
  nodeId: string,
): N8nNode[] {
  return (graph.outgoingById[nodeId] ?? [])
    .map((edge) => workflow.nodeById[edge.targetId])
    .filter((node): node is N8nNode => Boolean(node))
}

export function getUpstreamNodes(
  workflow: NormalizedWorkflow,
  graph: WorkflowGraph,
  nodeId: string,
): N8nNode[] {
  return (graph.incomingById[nodeId] ?? [])
    .map((edge) => workflow.nodeById[edge.sourceId])
    .filter((node): node is N8nNode => Boolean(node))
}

export function getReachableNodeIds(graph: WorkflowGraph, startNodeId: string, maxDepth = 25): Set<string> {
  const seen = new Set<string>()
  const queue: Array<{ nodeId: string; depth: number }> = [{ nodeId: startNodeId, depth: 0 }]

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current || current.depth >= maxDepth) continue

    for (const edge of graph.outgoingById[current.nodeId] ?? []) {
      if (seen.has(edge.targetId)) continue
      seen.add(edge.targetId)
      queue.push({ nodeId: edge.targetId, depth: current.depth + 1 })
    }
  }

  return seen
}

export function getReachableNodes(
  workflow: NormalizedWorkflow,
  graph: WorkflowGraph,
  startNodeId: string,
  maxDepth = 25,
): N8nNode[] {
  return [...getReachableNodeIds(graph, startNodeId, maxDepth)]
    .map((nodeId) => workflow.nodeById[nodeId])
    .filter((node): node is N8nNode => Boolean(node))
}

export function hasReachableNode(
  workflow: NormalizedWorkflow,
  graph: WorkflowGraph,
  startNodeId: string,
  predicate: (node: N8nNode) => boolean,
  maxDepth = 25,
): boolean {
  return getReachableNodes(workflow, graph, startNodeId, maxDepth).some(predicate)
}

export function hasUpstreamNode(
  workflow: NormalizedWorkflow,
  graph: WorkflowGraph,
  startNodeId: string,
  predicate: (node: N8nNode) => boolean,
  maxDepth = 25,
): boolean {
  const seen = new Set<string>()
  const queue: Array<{ nodeId: string; depth: number }> = [{ nodeId: startNodeId, depth: 0 }]

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current || current.depth >= maxDepth) continue

    for (const edge of graph.incomingById[current.nodeId] ?? []) {
      if (seen.has(edge.sourceId)) continue
      seen.add(edge.sourceId)

      const upstreamNode = workflow.nodeById[edge.sourceId]
      if (upstreamNode && predicate(upstreamNode)) return true

      queue.push({ nodeId: edge.sourceId, depth: current.depth + 1 })
    }
  }

  return false
}

export function getDisconnectedNodes(workflow: NormalizedWorkflow, graph: WorkflowGraph): N8nNode[] {
  if (workflow.nodes.length <= 1) return []

  return workflow.nodes.filter((node) => {
    const incoming = graph.incomingById[node.id]?.length ?? 0
    const outgoing = graph.outgoingById[node.id]?.length ?? 0
    return incoming === 0 && outgoing === 0
  })
}
