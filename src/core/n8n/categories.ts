import type { N8nNode } from './types'

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

function lowerText(value: unknown): string {
  try {
    return JSON.stringify(value)?.toLowerCase() ?? ''
  } catch {
    return ''
  }
}

export function nodeSearchText(node: N8nNode): string {
  return [
    node.name,
    node.type,
    node.notes ?? '',
    lowerText(node.parameters),
    lowerText(node.credentials),
  ]
    .join(' ')
    .toLowerCase()
}

export function categorizeNode(node: N8nNode): NodeCategory[] {
  const text = nodeSearchText(node)
  const type = node.type.toLowerCase()
  const categories = new Set<NodeCategory>()

  if (type.includes('webhook')) categories.add('webhook')
  if (type.includes('schedule') || type.includes('cron') || type.includes('interval')) categories.add('schedule')
  if (type.includes('httprequest') || type.includes('http request') || type.includes('http')) categories.add('http')
  if (type.includes('hubspot') || text.includes('hubspot')) {
    categories.add('hubspot')
    categories.add('crm')
  }
  if (text.includes('salesforce') || text.includes('pipedrive') || text.includes('zoho')) categories.add('crm')
  if (
    type.includes('postgres') ||
    type.includes('mysql') ||
    type.includes('mongodb') ||
    type.includes('supabase') ||
    type.includes('database')
  ) {
    categories.add('database')
  }
  if (type.includes('slack') || type.includes('email') || type.includes('gmail') || type.includes('telegram')) {
    categories.add('notification')
  }
  if (type.includes('log') || text.includes('logging') || text.includes('audit')) categories.add('logging')
  if (
    type.includes('set') ||
    type.includes('code') ||
    type.includes('function') ||
    type.includes('itemlists') ||
    text.includes('normalize') ||
    text.includes('lowercase') ||
    text.includes('trim')
  ) {
    categories.add('transform')
  }
  if (
    type.includes('if') ||
    type.includes('switch') ||
    text.includes('validate') ||
    text.includes('validation') ||
    text.includes('required') ||
    text.includes('schema')
  ) {
    categories.add('validation')
  }
  if (
    text.includes('signature') ||
    text.includes('secret') ||
    text.includes('token check') ||
    text.includes('verify') ||
    text.includes('authorization')
  ) {
    categories.add('security')
  }

  const writeSignals = ['create', 'update', 'upsert', 'insert', 'append', 'delete', 'send', 'post']
  if (
    categories.has('hubspot') ||
    categories.has('database') ||
    categories.has('notification') ||
    writeSignals.some((signal) => text.includes(`"operation":"${signal}`) || text.includes(`operation ${signal}`))
  ) {
    categories.add('write')
  }

  if (categories.size === 0) categories.add('unknown')
  return [...categories]
}

export function hasCategory(node: N8nNode, category: NodeCategory): boolean {
  return categorizeNode(node).includes(category)
}
