import type { JsonObject, N8nNode } from './types'

export type NodeCategory =
  | 'webhook'
  | 'schedule'
  | 'http'
  | 'hubspot'
  | 'crm'
  | 'database'
  | 'notification'
  | 'logging'
  | 'transform'
  | 'validation'
  | 'security'
  | 'write'
  | 'unknown'

const writeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const writeOperations = new Set(['add', 'append', 'create', 'delete', 'insert', 'post', 'remove', 'send', 'update', 'upsert'])
const readOperations = new Set([
  'find',
  'get',
  'getall',
  'get all',
  'getrecentlycreatedupdated',
  'list',
  'lookup',
  'read',
  'search',
  'searchbydomain',
])
const nonOperationalSuffixes = new Set(['stickyNote', 'noOp', 'noop'])

export function getNodeTypeSuffix(node: N8nNode): string {
  return node.type.split('.').pop() ?? node.type
}

export function nodeTypeIs(node: N8nNode, ...suffixes: string[]): boolean {
  const suffix = getNodeTypeSuffix(node).toLowerCase()
  return suffixes.some((candidate) => suffix === candidate.toLowerCase())
}

export function isNonOperationalNode(node: N8nNode): boolean {
  const suffix = getNodeTypeSuffix(node)
  return nonOperationalSuffixes.has(suffix) || suffix.toLowerCase() === 'noop'
}

function lowerText(value: unknown): string {
  try {
    return JSON.stringify(value)?.toLowerCase() ?? ''
  } catch {
    return ''
  }
}

export function nodeSearchText(node: N8nNode): string {
  if (isNonOperationalNode(node)) {
    return [node.name, node.type].join(' ').toLowerCase()
  }

  return [
    node.name,
    node.type,
    node.notes ?? '',
    lowerText(withoutStickyContent(node.parameters)),
    lowerText(node.credentials),
  ]
    .join(' ')
    .toLowerCase()
}

function withoutStickyContent(parameters: JsonObject): JsonObject {
  const { content: _content, ...rest } = parameters
  return rest
}

export function categorizeNode(node: N8nNode): NodeCategory[] {
  if (node.disabled || isNonOperationalNode(node)) return []

  const suffix = getNodeTypeSuffix(node).toLowerCase()
  const text = nodeSearchText(node)
  const categories = new Set<NodeCategory>()
  const operation = getParameterString(node, 'operation').toLowerCase()
  const resource = getParameterString(node, 'resource').toLowerCase()

  if (suffix === 'webhook') categories.add('webhook')
  if (suffix === 'scheduletrigger' || suffix === 'cron' || suffix === 'interval') categories.add('schedule')
  if (suffix === 'httprequest') categories.add('http')
  if (suffix === 'hubspot') {
    categories.add('hubspot')
    categories.add('crm')
  }
  if (['salesforce', 'pipedrive', 'zohoCrm'].some((candidate) => suffix === candidate.toLowerCase())) {
    categories.add('crm')
  }
  if (['postgres', 'mysql', 'mongoDb', 'supabase'].some((candidate) => suffix === candidate.toLowerCase())) {
    categories.add('database')
  }
  if (['slack', 'emailSend', 'gmail', 'telegram'].some((candidate) => suffix === candidate.toLowerCase())) {
    categories.add('notification')
  }
  if (suffix.includes('log') || text.includes('logging') || text.includes('audit')) categories.add('logging')
  if (
    ['set', 'code', 'function', 'functionitem', 'itemlists', 'editfields'].includes(suffix) ||
    text.includes('normalize') ||
    text.includes('lowercase') ||
    text.includes('trim')
  ) {
    categories.add('transform')
  }
  if (
    ['if', 'switch', 'filter'].includes(suffix) ||
    text.includes('validate') ||
    text.includes('validation') ||
    text.includes('required') ||
    text.includes('schema')
  ) {
    categories.add('validation')
  }
  if (
    getWebhookAuthentication(node) !== 'none' ||
    text.includes('signature') ||
    text.includes('secret') ||
    text.includes('token check') ||
    text.includes('verify') ||
    text.includes('authorization')
  ) {
    categories.add('security')
  }

  if (suffix === 'httprequest' && writeMethods.has(getHttpMethod(node))) {
    categories.add('write')
  }

  if ((categories.has('hubspot') || categories.has('crm') || categories.has('database')) && isWriteOperation(operation)) {
    categories.add('write')
  }

  if (categories.has('notification') && isWriteOperation(operation)) {
    categories.add('write')
  }

  if (suffix === 'hubspot' && hubSpotLooksWrite(node)) {
    categories.add('write')
  }

  if (!categories.has('write') && resource && isWriteOperation(operation)) {
    categories.add('write')
  }

  if (categories.size === 0) categories.add('unknown')
  return [...categories]
}

export function getParameterString(node: N8nNode, key: string): string {
  const value = node.parameters[key]
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (isRecord(value) && typeof value.value === 'string') return value.value
  return ''
}

export function getHttpMethod(node: N8nNode): string {
  return (getParameterString(node, 'method') || 'GET').toUpperCase()
}

export function getWebhookAuthentication(node: N8nNode): string {
  const auth = getParameterString(node, 'authentication').toLowerCase()
  return auth && auth !== 'none' ? auth : 'none'
}

export function isWriteOperation(operation: string): boolean {
  const normalized = operation.toLowerCase().replace(/\s+/g, '')
  return writeOperations.has(normalized)
}

export function isReadOperation(operation: string): boolean {
  const normalized = operation.toLowerCase().replace(/\s+/g, '')
  return readOperations.has(normalized)
}

export function legacyHubSpotNameLooksWrite(name: string): boolean {
  return /\b(create|add|update|upsert|insert|delete|remove)\b/i.test(name)
}

export function hubSpotLooksWrite(node: N8nNode): boolean {
  if (!nodeTypeIs(node, 'hubspot')) return false

  const operation = getParameterString(node, 'operation').toLowerCase()
  if (operation) return isWriteOperation(operation)

  return true
}

export function hasCategory(node: N8nNode, category: NodeCategory): boolean {
  return categorizeNode(node).includes(category)
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
