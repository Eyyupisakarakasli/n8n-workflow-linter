import {
  categorizeNode,
  getHttpMethod,
  getParameterString,
  nodeTypeIs,
  nodeSearchText,
  type NodeCategory,
} from '../n8n/categories'
import { getDownstreamNodes, getReachableNodes, hasReachableNode, hasUpstreamNode } from '../n8n/graph'
import type { ConnectionEdge, JsonObject, N8nNode } from '../n8n/types'
import type { FindingInput, RiskFinding, RuleContext } from './types'

const codeParameterKeys = new Set(['jsCode', 'pythonCode', 'functionCode', 'code'])
const credentialNamePattern =
  /api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|token|authorization|password|passwd|pwd|private[_-]?key|credential/i
const expressionMarkers = ['{{', '$json', '$node', '$credentials', '$env', '$secrets', '$vars']
const placeholderMarkers = [
  'REPLACE',
  'YOUR',
  'EXAMPLE',
  'PLACEHOLDER',
  'XXXX',
  'DUMMY',
  'TEST_',
  'SAMPLE',
  'CHANGEME',
  '<',
  '...',
]
const credentialQueryParams = new Set([
  'api_key',
  'apikey',
  'api-key',
  'key',
  'token',
  'access_token',
  'accesstoken',
  'auth',
  'auth_token',
  'authorization',
  'password',
  'passwd',
  'pwd',
  'secret',
  'client_secret',
  'app_secret',
  'private_key',
  'signature',
])
const secretPatterns: Array<{ label: string; pattern: RegExp }> = [
  { label: 'Anthropic API key', pattern: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { label: 'Stripe secret key', pattern: /sk_live_[0-9A-Za-z]{20,}/g },
  { label: 'OpenAI API key', pattern: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { label: 'GitHub token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { label: 'AWS access key ID', pattern: /AKIA[0-9A-Z]{16}/g },
  { label: 'Google API key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { label: 'Slack token', pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { label: 'Twilio account SID', pattern: /AC[0-9a-fA-F]{32}/g },
  { label: 'Private key block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { label: 'JWT', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g },
]
const safeCredentialIds = new Set([
  '',
  'REPLACE_WITH_CREDENTIAL_ID',
  'REPLACE_WITH_CREDENTIAL',
  'REPLACE_ME',
  'PLACEHOLDER',
  'YOUR_CREDENTIAL_ID',
])

export interface SecretMatch {
  label: string
  value: string
  redacted: string
}

export interface EmbeddedSecretMatch extends SecretMatch {
  source: string
}

export interface UrlSecretMatch extends SecretMatch {
  paramName: string
}

export interface CredentialIdLeak {
  credentialType: string
  credentialId: string
  redacted: string
}

export interface ReachableWritePath {
  target: N8nNode
  nodeIds: string[]
  edges: ConnectionEdge[]
  branchChoices: BranchChoice[]
}

export interface BranchChoice {
  nodeId: string
  outputIndex: number
}

export function makeFinding(input: FindingInput): RiskFinding {
  const nodes = input.nodes ?? (input.node ? [input.node] : [])

  return {
    id: `${input.rule.id}:${nodes.map((node) => node.id).join(',') || hashText(input.problem)}`,
    ruleId: input.rule.id,
    title: input.rule.title,
    plainTitle: input.plainTitle ?? input.rule.plainTitle,
    plainMeaning: input.plainMeaning ?? input.rule.plainMeaning,
    fixSteps: input.fixSteps ?? input.rule.fixSteps,
    shareSafetyImpact: input.shareSafetyImpact ?? input.rule.shareSafetyImpact,
    severity: input.severity ?? input.rule.defaultSeverity,
    category: input.rule.category,
    nodeIds: nodes.map((node) => node.id),
    nodeNames: nodes.map((node) => node.name),
    problem: input.problem,
    whyItMatters: input.whyItMatters,
    suggestedFix: input.suggestedFix ?? input.fixSteps?.[0] ?? input.rule.fixSteps[0] ?? '',
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
  const normalizedText = text.toLowerCase()
  return needles.some((needle) => normalizedText.includes(needle.toLowerCase()))
}

export function nodeTextIncludesAny(node: N8nNode, needles: string[]): boolean {
  return textIncludesAny(nodeSearchText(node), needles)
}

export function nodeHasDownstreamCategory(
  context: RuleContext,
  node: N8nNode,
  category: NodeCategory,
  maxDepth = context.maxGraphDepth,
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
  maxDepth = context.maxGraphDepth,
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
  return getReachableNodes(context.workflow, context.graph, node.id, context.maxGraphDepth).filter((candidate) =>
    context.categoriesByNodeId[candidate.id]?.includes('write'),
  )
}

export function reachableWritePaths(context: RuleContext, node: N8nNode): ReachableWritePath[] {
  const paths: ReachableWritePath[] = []
  const queue: Array<{ nodeId: string; nodeIds: string[]; edges: ConnectionEdge[]; branchChoices: BranchChoice[] }> = [
    { nodeId: node.id, nodeIds: [node.id], edges: [], branchChoices: [] },
  ]
  const maxPaths = Math.max(250, context.workflow.nodes.length * 20)

  while (queue.length > 0 && paths.length < maxPaths) {
    const current = queue.shift()
    if (!current) continue
    if (current.edges.length >= context.maxGraphDepth) continue

    for (const edge of context.graph.outgoingById[current.nodeId] ?? []) {
      if (current.nodeIds.includes(edge.targetId)) continue

      const target = context.workflow.nodeById[edge.targetId]
      if (!target) continue

      const nextPath = {
        nodeId: edge.targetId,
        nodeIds: [...current.nodeIds, edge.targetId],
        edges: [...current.edges, edge],
        branchChoices: [...current.branchChoices, ...branchChoiceForEdge(context, edge)],
      }

      if (context.categoriesByNodeId[target.id]?.includes('write')) {
        paths.push({
          target,
          nodeIds: nextPath.nodeIds,
          edges: nextPath.edges,
          branchChoices: nextPath.branchChoices,
        })
      }

      queue.push(nextPath)
    }
  }

  return paths
}

export function pathHasCategoryBeforeTarget(
  context: RuleContext,
  path: ReachableWritePath,
  category: NodeCategory,
): boolean {
  return path.nodeIds.slice(1, -1).some((nodeId) => context.categoriesByNodeId[nodeId]?.includes(category))
}

export function pathsAreMutuallyExclusive(left: ReachableWritePath, right: ReachableWritePath): boolean {
  return left.branchChoices.some((leftChoice) =>
    right.branchChoices.some(
      (rightChoice) => leftChoice.nodeId === rightChoice.nodeId && leftChoice.outputIndex !== rightChoice.outputIndex,
    ),
  )
}

export function writeTargetsThatCanRunTogether(paths: ReachableWritePath[]): N8nNode[] {
  const pathsByTargetId = new Map<string, ReachableWritePath[]>()
  const targetById = new Map<string, N8nNode>()

  for (const path of paths) {
    const existing = pathsByTargetId.get(path.target.id) ?? []
    existing.push(path)
    pathsByTargetId.set(path.target.id, existing)
    targetById.set(path.target.id, path.target)
  }

  const targetIds = [...pathsByTargetId.keys()]
  const runnableTogether = new Set<string>()

  for (let leftIndex = 0; leftIndex < targetIds.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < targetIds.length; rightIndex += 1) {
      const leftId = targetIds[leftIndex]
      const rightId = targetIds[rightIndex]
      const leftPaths = pathsByTargetId.get(leftId) ?? []
      const rightPaths = pathsByTargetId.get(rightId) ?? []
      const canRunTogether = leftPaths.some((leftPath) =>
        rightPaths.some((rightPath) => !pathsAreMutuallyExclusive(leftPath, rightPath)),
      )

      if (canRunTogether) {
        runnableTogether.add(leftId)
        runnableTogether.add(rightId)
      }
    }
  }

  return [...runnableTogether]
    .map((targetId) => targetById.get(targetId))
    .filter((node): node is N8nNode => Boolean(node))
}

function branchChoiceForEdge(context: RuleContext, edge: ConnectionEdge): BranchChoice[] {
  const source = context.workflow.nodeById[edge.sourceId]
  if (!source || !nodeTypeIs(source, 'if', 'switch')) return []
  return [{ nodeId: source.id, outputIndex: edge.outputIndex }]
}

export function hasErrorHandling(context: RuleContext, node: N8nNode): boolean {
  if (node.onError === 'continueErrorOutput') return true

  const outgoing = context.graph.outgoingById[node.id] ?? []
  return outgoing.some((edge) => edge.outputIndex > 0 || edge.outputType.toLowerCase().includes('error'))
}

export function hasSilentErrorContinue(node: N8nNode): boolean {
  return node.continueOnFail || node.onError === 'continueRegularOutput'
}

export function hasRetry(node: N8nNode): boolean {
  return node.retryOnFail || (typeof node.maxTries === 'number' && node.maxTries > 1)
}

export function hasTimeout(node: N8nNode): boolean {
  const candidates = [
    getNestedValue(node.parameters, ['options', 'timeout']),
    getNestedValue(node.parameters, ['options', 'requestTimeout']),
    getNestedValue(node.parameters, ['timeout']),
    getNestedValue(node.parameters, ['requestTimeout']),
  ]

  return candidates.some((value) => {
    if (typeof value === 'number') return value > 0
    if (typeof value === 'string') return value.trim().length > 0 && value.trim() !== '0'
    return false
  })
}

export function hasPaginationSignal(node: N8nNode): boolean {
  const text = lowerJson(node.parameters)
  return textIncludesAny(text, [
    'pagination',
    'pageSize',
    'page size',
    'nextPage',
    'next page',
    'returnAll',
    'return all',
    'offset',
    'cursor',
    'limit',
    'page=',
  ])
}

export function looksLikeListEndpoint(node: N8nNode): boolean {
  if (getHttpMethod(node) !== 'GET') return false

  const operation = getParameterString(node, 'operation').toLowerCase()
  if (['getall', 'get all', 'list', 'search'].includes(operation)) return true

  const url = getFirstStringParameter(node.parameters, ['url', 'endpoint', 'path'])
  if (!url || isExpression(url)) return false

  const path = extractPathname(url)
  const lastSegment = path
    .split('/')
    .filter(Boolean)
    .at(-1)
    ?.toLowerCase()

  if (!lastSegment || lastSegment.includes('.')) return false
  if (['contacts', 'companies', 'deals', 'orders', 'customers', 'users', 'items', 'events', 'leads'].includes(lastSegment)) {
    return true
  }

  return lastSegment.endsWith('s') && lastSegment.length > 4
}

export function looksLikeCreateContact(node: N8nNode): boolean {
  const operation = getParameterString(node, 'operation').toLowerCase()
  const resource = getParameterString(node, 'resource').toLowerCase()
  const text = nodeSearchText(node)

  return (
    text.includes('hubspot') &&
    operation === 'create' &&
    (resource.includes('contact') || text.includes('contact') || text.includes('contacts'))
  )
}

export function looksLikeSearchUpdateOrUpsert(node: N8nNode): boolean {
  const operation = getParameterString(node, 'operation').toLowerCase().replace(/\s+/g, '')
  return ['search', 'lookup', 'find', 'getall', 'update', 'upsert'].includes(operation) || nodeTextIncludesAny(node, ['dedupe'])
}

export function hasKnownSecret(node: N8nNode): SecretMatch[] {
  return knownSecretsInText(safeStringify(node.raw))
}

export function knownSecretsInText(text: string): SecretMatch[] {
  const seen = new Set<string>()
  const matches: SecretMatch[] = []

  for (const { label, pattern } of secretPatterns) {
    pattern.lastIndex = 0
    for (const match of text.matchAll(pattern)) {
      const value = match[0]
      if (isPlaceholder(value) || isExpression(value) || seen.has(value)) continue
      seen.add(value)
      matches.push({ label, value, redacted: redact(value) })
    }
  }

  return matches
}

export function embeddedSecretMatches(node: N8nNode): EmbeddedSecretMatch[] {
  const matches: EmbeddedSecretMatch[] = []
  const seen = new Set<string>()

  walkJson(node.parameters, (value, path) => {
    if (typeof value !== 'string') return
    const key = path.at(-1) ?? ''

    if (codeParameterKeys.has(key)) {
      for (const match of secretAssignmentsInCode(value)) {
        const marker = `${match.source}:${match.value}`
        if (seen.has(marker)) continue
        seen.add(marker)
        matches.push(match)
      }
      return
    }

    if (credentialNamePattern.test(key) && looksLikeSecretValue(value)) {
      const marker = `${key}:${value}`
      if (seen.has(marker)) return
      seen.add(marker)
      matches.push({ label: key, source: `"${key}" parameter`, value, redacted: redact(value) })
    }
  })

  walkJson(node.parameters, (value) => {
    if (!isRecord(value)) return
    const name = typeof value.name === 'string' ? value.name : ''
    const fieldValue = typeof value.value === 'string' ? value.value : ''

    if (!name || !fieldValue || !credentialNamePattern.test(name) || !looksLikeSecretValue(fieldValue)) return

    const marker = `${name}:${fieldValue}`
    if (seen.has(marker)) return
    seen.add(marker)
    matches.push({
      label: name,
      source: `"${name}" header/query parameter`,
      value: fieldValue,
      redacted: redact(fieldValue),
    })
  })

  return matches
}

export function urlSecretMatches(node: N8nNode): UrlSecretMatch[] {
  const matches: UrlSecretMatch[] = []
  const urls = getStringParameters(node.parameters, ['url', 'endpoint'])

  for (const url of urls) {
    if (!url.includes('?') || isExpression(url)) continue

    for (const [paramName, value] of queryPairs(url)) {
      const normalizedName = paramName.trim().toLowerCase()
      if (!credentialQueryParams.has(normalizedName)) continue
      if (value.length < 8 || isPlaceholder(value) || isExpression(value)) continue
      matches.push({ label: 'URL credential', paramName, value, redacted: redact(value) })
    }
  }

  return matches
}

export function credentialIdLeaks(node: N8nNode): CredentialIdLeak[] {
  const leaks: CredentialIdLeak[] = []

  for (const [credentialType, credential] of Object.entries(node.credentials)) {
    if (!isRecord(credential)) continue
    const credentialId = credential.id
    if (credentialId === undefined || credentialId === null) continue

    const value = String(credentialId)
    if (safeCredentialIds.has(value) || isPlaceholder(value) || isExpression(value)) continue
    leaks.push({ credentialType, credentialId: value, redacted: redact(value) })
  }

  return leaks
}

export function hasPinnedData(context: RuleContext): string[] {
  const pinData = context.originalWorkflow.raw.pinData
  if (!isRecord(pinData)) return []
  return Object.keys(pinData)
}

export function isDefaultNodeName(node: N8nNode): boolean {
  if (/stickynote/i.test(node.type)) return false
  return /^\s*(HTTP Request|Webhook|Code|Function( Item)?|Set|Edit Fields|If|Switch|Merge|Wait|NoOp|No Operation, do nothing|Filter|Sort|Limit|Aggregate|Summarize|Item Lists|Split In Batches|Loop Over Items|Split Out|Execute Workflow|Date & Time|Crypto|HTML|XML|Compare Datasets|Respond to Webhook|Basic LLM Chain|AI Agent|Edit Image|Convert to File|Extract from File)\s*\d*\s*$/i.test(
    node.name,
  )
}

export function scheduleLooksFrequent(node: N8nNode): boolean {
  const text = lowerJson(node.parameters)
  if (text.includes('every minute') || text.includes('every 1 minute')) return true
  if (/cron(expression)?["':\s]+(\*|\*\/1)\s+\*/i.test(text)) return true

  let frequent = false
  walkJson(node.parameters, (value) => {
    if (frequent || !isRecord(value)) return

    const field = stringField(value, 'field').toLowerCase()
    const unit = stringField(value, 'unit').toLowerCase()
    const intervalUnit = stringField(value, 'intervalUnit').toLowerCase()
    const mode = stringField(value, 'mode').toLowerCase()
    const count = firstFiniteNumber(value, ['minutesInterval', 'value', 'interval', 'every', 'triggerAtMinute'])

    if (field === 'minutes' && count !== undefined && count <= 4) frequent = true
    if ((unit === 'minute' || unit === 'minutes') && count !== undefined && count <= 4) frequent = true
    if ((intervalUnit === 'minute' || intervalUnit === 'minutes') && count !== undefined && count <= 4) frequent = true
    if (mode === 'everyminute') frequent = true
  })

  return frequent
}

export function hasNormalizerUpstream(context: RuleContext, node: N8nNode, field: 'email' | 'phone'): boolean {
  const signals =
    field === 'email'
      ? ['email', 'lowercase', 'lower case', 'tolowercase', 'trim', 'normalize']
      : ['phone', 'e164', 'e.164', 'digits', 'normalize', 'trim']

  return hasUpstreamNode(
    context.workflow,
    context.graph,
    node.id,
    (candidate) => {
      const categoryHit =
        context.categoriesByNodeId[candidate.id]?.includes('transform') ||
        context.categoriesByNodeId[candidate.id]?.includes('validation')
      return Boolean(categoryHit) && textIncludesAny(lowerJson(candidate.parameters), signals)
    },
    context.maxGraphDepth,
  )
}

export function isExpression(value: string): boolean {
  return expressionMarkers.some((marker) => value.includes(marker))
}

export function isPlaceholder(value: string): boolean {
  const upper = value.toUpperCase()
  return placeholderMarkers.some((marker) => upper.includes(marker)) || /^[xX0_-]{8,}$/.test(value)
}

export function looksLikeSecretValue(value: string): boolean {
  if (knownSecretsInText(value).length > 0) return true
  if (value.length < 16 || /\s/.test(value)) return false
  if (isPlaceholder(value) || isExpression(value)) return false
  return shannonEntropy(value) >= 3
}

export function redact(secret: string): string {
  if (secret.length <= 12) return '...'
  return `${secret.slice(0, 6)}...${secret.slice(-4)}`
}

export function shannonEntropy(value: string): number {
  if (!value) return 0
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)

  return [...counts.values()].reduce((entropy, count) => {
    const frequency = count / value.length
    return entropy - frequency * Math.log2(frequency)
  }, 0)
}

function secretAssignmentsInCode(body: string): EmbeddedSecretMatch[] {
  const matches: EmbeddedSecretMatch[] = []
  const assignment =
    /\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|token|password|passwd|pwd|private[_-]?key|credential)\b\s*[:=]\s*['"]([^'"\s]{16,200})['"]/gi
  const bearer = /bearer\s+([A-Za-z0-9_.-]{20,400})/gi

  for (const match of body.matchAll(assignment)) {
    const value = match[2]
    if (looksLikeSecretValue(value)) {
      matches.push({
        label: match[1],
        source: `'${match[1]}' assignment in code`,
        value,
        redacted: redact(value),
      })
    }
  }

  for (const match of body.matchAll(bearer)) {
    const value = match[1]
    if (looksLikeSecretValue(value)) {
      matches.push({ label: 'bearer token', source: 'bearer token in code', value, redacted: redact(value) })
    }
  }

  return matches
}

function walkJson(value: unknown, visitor: (value: unknown, path: string[]) => void, path: string[] = []): void {
  visitor(value, path)

  if (Array.isArray(value)) {
    value.forEach((item, index) => walkJson(item, visitor, [...path, String(index)]))
    return
  }

  if (!isRecord(value)) return

  for (const [key, child] of Object.entries(value)) {
    walkJson(child, visitor, [...path, key])
  }
}

function getStringParameters(parameters: JsonObject, keyNames: string[]): string[] {
  const wanted = new Set(keyNames.map((key) => key.toLowerCase()))
  const values: string[] = []

  walkJson(parameters, (value, path) => {
    if (typeof value !== 'string') return
    const key = path.at(-1)?.toLowerCase()
    if (key && wanted.has(key)) values.push(value)
  })

  return values
}

function getFirstStringParameter(parameters: JsonObject, keyNames: string[]): string | undefined {
  return getStringParameters(parameters, keyNames)[0]
}

function queryPairs(url: string): Array<[string, string]> {
  try {
    const parsed = new URL(url)
    return [...parsed.searchParams.entries()]
  } catch {
    const query = url.split('?')[1]?.split('#')[0] ?? ''
    return query
      .split('&')
      .filter(Boolean)
      .map((pair) => {
        const [rawName, rawValue = ''] = pair.split('=')
        return [decodeURIComponentSafe(rawName), decodeURIComponentSafe(rawValue)] as [string, string]
      })
  }
}

function extractPathname(url: string): string {
  try {
    return new URL(url).pathname
  } catch {
    return url.split('?')[0] ?? ''
  }
}

function getNestedValue(object: JsonObject, path: string[]): unknown {
  let current: unknown = object
  for (const key of path) {
    if (!isRecord(current)) return undefined
    current = current[key]
  }
  return current
}

function lowerJson(value: unknown): string {
  return safeStringify(value).toLowerCase()
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? ''
  } catch {
    return ''
  }
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function stringField(object: JsonObject, key: string): string {
  const value = object[key]
  return typeof value === 'string' ? value : ''
}

function firstFiniteNumber(object: JsonObject, keys: string[]): number | undefined {
  for (const key of keys) {
    const value = object[key]
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string' && value.trim() !== '') {
      const parsed = Number(value)
      if (Number.isFinite(parsed)) return parsed
    }
  }
  return undefined
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '))
  } catch {
    return value
  }
}

function hashText(value: string): string {
  let hash = 0
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0
  }
  return hash.toString(16)
}
