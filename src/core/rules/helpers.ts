import { categorizeNode, nodeSearchText, type NodeCategory } from '../n8n/categories'
import { getDownstreamNodes, getReachableNodes, hasReachableNode, hasUpstreamNode } from '../n8n/graph'
import type { N8nNode } from '../n8n/types'
import type { FindingInput, RiskFinding, RuleContext } from './types'

export function makeFinding(input: FindingInput): RiskFinding {
  return {
    id: `${input.rule.id}:${input.node.id}`,
    ruleId: input.rule.id,
    title: input.rule.title,
    severity: input.severity ?? input.rule.severity,
    category: input.rule.category,
    nodeIds: [input.node.id],
    nodeNames: [input.node.name],
    problem: input.problem,
    whyItMatters: input.whyItMatters,
    suggestedFix: input.suggestedFix,
    confidence: input.confidence ?? 'medium',
  }
}

export function nodesInCategory(context: RuleContext, category: NodeCategory): N8nNode[] {
  return context.workflow.nodes.filter((node) => context.categoriesByNodeId[node.id]?.includes(category))
}

export function nodeHasCategory(node: N8nNode, category: NodeCategory): boolean {
  return categorizeNode(node).includes(category)
}

export function textIncludesAny(text: string, needles: string[]): boolean {
  return needles.some((needle) => text.includes(needle))
}

export function nodeTextIncludesAny(node: N8nNode, needles: string[]): boolean {
  return textIncludesAny(nodeSearchText(node), needles)
}

export function nodeHasDownstreamCategory(
  context: RuleContext,
  node: N8nNode,
  category: NodeCategory,
  maxDepth = 25,
): boolean {
  return hasReachableNode(
    context.workflow,
    context.graph,
    node.id,
    (candidate) => context.categoriesByNodeId[candidate.id]?.includes(category) ?? false,
    maxDepth,
  )
}

export function nodeHasUpstreamCategory(
  context: RuleContext,
  node: N8nNode,
  category: NodeCategory,
  maxDepth = 25,
): boolean {
  return hasUpstreamNode(
    context.workflow,
    context.graph,
    node.id,
    (candidate) => context.categoriesByNodeId[candidate.id]?.includes(category) ?? false,
    maxDepth,
  )
}

export function immediateDownstreamHasCategory(
  context: RuleContext,
  node: N8nNode,
  category: NodeCategory,
): boolean {
  return getDownstreamNodes(context.workflow, context.graph, node.id).some((candidate) =>
    context.categoriesByNodeId[candidate.id]?.includes(category),
  )
}

export function reachableWriteNodes(context: RuleContext, node: N8nNode): N8nNode[] {
  return getReachableNodes(context.workflow, context.graph, node.id).filter((candidate) =>
    context.categoriesByNodeId[candidate.id]?.includes('write'),
  )
}

export function hasErrorHandling(context: RuleContext, node: N8nNode): boolean {
  if (node.continueOnFail) return true
  if (node.onError && !node.onError.toLowerCase().includes('stop')) return true

  const outgoing = context.graph.outgoingById[node.id] ?? []
  return outgoing.some((edge) => edge.outputIndex > 0 || edge.outputType.toLowerCase().includes('error'))
}

export function hasRetry(node: N8nNode): boolean {
  if (node.retryOnFail) return true
  if (typeof node.maxTries === 'number' && node.maxTries > 1) return true
  return nodeSearchText(node).includes('retry')
}

export function hasTimeout(node: N8nNode): boolean {
  const text = nodeSearchText(node)
  return text.includes('timeout') && !text.includes('"timeout":0') && !text.includes('"timeout":""')
}

export function hasPaginationSignal(node: N8nNode): boolean {
  return nodeTextIncludesAny(node, [
    'pagination',
    'page size',
    'next page',
    'returnall',
    'return all',
    'offset',
    'cursor',
    'limit',
  ])
}

export function looksLikeListEndpoint(node: N8nNode): boolean {
  return nodeTextIncludesAny(node, [
    '/contacts',
    '/companies',
    '/deals',
    '/orders',
    '/customers',
    '/users',
    '/items',
    '/events',
    'list',
    'search',
    'getall',
    'get all',
  ])
}

export function looksLikeCreateContact(node: N8nNode): boolean {
  const text = nodeSearchText(node)
  return (
    text.includes('hubspot') &&
    (text.includes('contact') || text.includes('contacts')) &&
    (text.includes('create') || text.includes('"operation":"create"'))
  )
}

export function looksLikeSearchUpdateOrUpsert(node: N8nNode): boolean {
  const text = nodeSearchText(node)
  return textIncludesAny(text, ['search', 'lookup', 'find', 'update', 'upsert', 'dedupe', 'duplicate'])
}

export function hasHardcodedSecret(node: N8nNode): boolean {
  const text = nodeSearchText(node)
  const secretPatterns = [
    /bearer\s+[a-z0-9._-]{16,}/i,
    /sk-[a-z0-9]{16,}/i,
    /pat-[a-z0-9]{16,}/i,
    /x-api-key/i,
    /api[_-]?key["':=\s]+[a-z0-9._-]{16,}/i,
    /access[_-]?token["':=\s]+[a-z0-9._-]{16,}/i,
  ]

  return secretPatterns.some((pattern) => pattern.test(text))
}

export function hasSecretInQueryParam(node: N8nNode): boolean {
  const text = nodeSearchText(node)
  return /[?&](api_key|apikey|token|access_token|secret)=/i.test(text)
}

export function scheduleLooksFrequent(node: N8nNode): boolean {
  const text = nodeSearchText(node)

  if (text.includes('every minute') || text.includes('every 1 minute')) return true
  if (/cron(expression)?["':\s]+(\*|\*\/1)\s+\*/i.test(text)) return true
  if (/unit["':\s]+(minute|minutes)/i.test(text) && /interval["':\s]+[1-4][,\s}]/i.test(text)) return true
  if (/field["':\s]+(minute|minutes)/i.test(text) && /value["':\s]+[1-4][,\s}]/i.test(text)) return true

  return false
}

export function hasNormalizerUpstream(context: RuleContext, node: N8nNode, field: 'email' | 'phone'): boolean {
  const signals =
    field === 'email'
      ? ['email', 'lowercase', 'lower case', 'toLowerCase', 'trim', 'normalize']
      : ['phone', 'e164', 'e.164', 'digits', 'normalize', 'trim']

  return hasUpstreamNode(
    context.workflow,
    context.graph,
    node.id,
    (candidate) =>
      (context.categoriesByNodeId[candidate.id]?.includes('transform') ||
        context.categoriesByNodeId[candidate.id]?.includes('validation')) &&
      nodeTextIncludesAny(candidate, signals.map((signal) => signal.toLowerCase())),
    8,
  )
}
