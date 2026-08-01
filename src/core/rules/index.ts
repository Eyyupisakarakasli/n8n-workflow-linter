import { nodeSearchText } from '../n8n/categories'
import type { N8nNode } from '../n8n/types'
import {
  hasErrorHandling,
  hasHardcodedSecret,
  hasNormalizerUpstream,
  hasPaginationSignal,
  hasRetry,
  hasSecretInQueryParam,
  hasTimeout,
  immediateDownstreamHasCategory,
  looksLikeCreateContact,
  looksLikeListEndpoint,
  looksLikeSearchUpdateOrUpsert,
  makeFinding,
  nodeHasDownstreamCategory,
  nodeHasUpstreamCategory,
  nodeTextIncludesAny,
  nodesInCategory,
  reachableWriteNodes,
  scheduleLooksFrequent,
} from './helpers'
import type { RiskFinding, RuleContext, RuleDefinition } from './types'

const webhookValidationRule: RuleDefinition = {
  id: 'webhook-missing-validation',
  title: 'Webhook input reaches actions without validation',
  category: 'Webhook',
  severity: 'high',
  run(context) {
    return nodesInCategory(context, 'webhook')
      .filter((node) => nodeHasDownstreamCategory(context, node, 'write', 8))
      .filter((node) => !nodeHasDownstreamCategory(context, node, 'validation', 3))
      .map((node) =>
        makeFinding({
          rule: webhookValidationRule,
          node,
          confidence: 'medium',
          problem: 'Webhook data can reach write/action nodes before a validation step.',
          whyItMatters:
            'Bad payloads, missing email fields, or unexpected schema changes can create broken records or trigger the wrong downstream action.',
          suggestedFix: 'Add an IF, Switch, Code, or validation node directly after the webhook before any CRM/API write path.',
        }),
      )
  },
}

const webhookDirectWriteRule: RuleDefinition = {
  id: 'webhook-direct-write',
  title: 'Webhook writes directly to a side-effect node',
  category: 'Webhook',
  severity: 'high',
  run(context) {
    return nodesInCategory(context, 'webhook')
      .filter((node) => immediateDownstreamHasCategory(context, node, 'write'))
      .map((node) =>
        makeFinding({
          rule: webhookDirectWriteRule,
          node,
          confidence: 'high',
          problem: 'The webhook is connected directly to a CRM, database, notification, or API action.',
          whyItMatters:
            'Public webhook payloads should usually be checked, normalized, and deduplicated before anything is written.',
          suggestedFix: 'Insert validation and transform nodes between the webhook and the first write/action node.',
        }),
      )
  },
}

const webhookSecretRule: RuleDefinition = {
  id: 'webhook-missing-secret-check',
  title: 'Webhook has no obvious secret or signature check',
  category: 'Security',
  severity: 'high',
  run(context) {
    return nodesInCategory(context, 'webhook')
      .filter((node) => !nodeHasDownstreamCategory(context, node, 'security', 3))
      .filter((node) => !nodeTextIncludesAny(node, ['basic auth', 'header auth', 'jwt', 'signature', 'secret', 'verify']))
      .map((node) =>
        makeFinding({
          rule: webhookSecretRule,
          node,
          confidence: 'medium',
          problem: 'The webhook path does not show an obvious auth, secret, or signature verification step.',
          whyItMatters:
            'Anyone who discovers a public webhook URL may be able to trigger production actions if the request is not verified.',
          suggestedFix: 'Require a shared secret, signed header, or n8n webhook authentication before accepting the payload.',
        }),
      )
  },
}

const webhookTestProdRule: RuleDefinition = {
  id: 'webhook-test-prod-confusion',
  title: 'Webhook name or path suggests test/prod confusion',
  category: 'Webhook',
  severity: 'medium',
  run(context) {
    return nodesInCategory(context, 'webhook')
      .filter((node) =>
        nodeTextIncludesAny(node, ['test webhook', 'dev webhook', 'staging', 'localhost', 'sample', 'temporary']),
      )
      .map((node) =>
        makeFinding({
          rule: webhookTestProdRule,
          node,
          confidence: 'low',
          problem: 'The webhook naming or parameters contain test/dev wording.',
          whyItMatters:
            'Teams often ship workflows with test paths, temporary names, or staging payload assumptions still present.',
          suggestedFix: 'Confirm this workflow uses the production webhook URL, path, and expected payload contract.',
        }),
      )
  },
}

const httpTimeoutRule: RuleDefinition = {
  id: 'http-missing-timeout',
  title: 'HTTP Request has no timeout setting',
  category: 'API',
  severity: 'medium',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => !hasTimeout(node))
      .map((node) =>
        makeFinding({
          rule: httpTimeoutRule,
          node,
          confidence: 'medium',
          problem: 'This HTTP Request node does not expose an obvious timeout setting.',
          whyItMatters: 'Slow third-party APIs can stall workflow execution and make retries pile up.',
          suggestedFix: 'Set a realistic timeout for the API and handle timeout failures explicitly.',
        }),
      )
  },
}

const httpRetryRule: RuleDefinition = {
  id: 'http-missing-retry',
  title: 'HTTP Request has no retry policy',
  category: 'API',
  severity: 'medium',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => !hasRetry(node))
      .map((node) =>
        makeFinding({
          rule: httpRetryRule,
          node,
          confidence: 'medium',
          problem: 'This HTTP Request node has no obvious retry policy.',
          whyItMatters: 'Temporary network failures and rate limits can break the whole workflow without a retry strategy.',
          suggestedFix: 'Enable retry on fail with conservative max tries and spacing, then route repeated failures to an alert path.',
        }),
      )
  },
}

const httpErrorBranchRule: RuleDefinition = {
  id: 'http-missing-error-branch',
  title: 'HTTP Request has no error branch',
  category: 'API',
  severity: 'high',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => !hasErrorHandling(context, node))
      .map((node) =>
        makeFinding({
          rule: httpErrorBranchRule,
          node,
          confidence: 'medium',
          problem: 'This HTTP Request node does not show an error branch or continue-on-fail handling.',
          whyItMatters:
            'An API outage or bad response can stop production workflows without notification or cleanup.',
          suggestedFix: 'Add explicit error output handling, continue-on-fail routing, or a notification path for failed requests.',
        }),
      )
  },
}

const paginationRule: RuleDefinition = {
  id: 'http-pagination-suspect',
  title: 'List-style API call may be missing pagination',
  category: 'API',
  severity: 'low',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => looksLikeListEndpoint(node))
      .filter((node) => !hasPaginationSignal(node))
      .map((node) =>
        makeFinding({
          rule: paginationRule,
          node,
          confidence: 'low',
          problem: 'This request looks like it reads a collection but no pagination signal was found.',
          whyItMatters: 'Production data can silently miss records after the first page.',
          suggestedFix: 'Confirm the API pagination model and loop through next page, cursor, offset, or return-all options.',
        }),
      )
  },
}

const hardcodedSecretRule: RuleDefinition = {
  id: 'hardcoded-secret',
  title: 'Possible hardcoded API key or token',
  category: 'Security',
  severity: 'high',
  run(context) {
    return context.workflow.nodes
      .filter((node) => hasHardcodedSecret(node))
      .map((node) =>
        makeFinding({
          rule: hardcodedSecretRule,
          node,
          confidence: 'medium',
          problem: 'Node parameters appear to contain a hardcoded token, API key, or bearer credential.',
          whyItMatters: 'Secrets in workflow JSON can leak through exports, screenshots, shared templates, or version control.',
          suggestedFix: 'Move the value into n8n credentials or environment variables and rotate the exposed key if needed.',
        }),
      )
  },
}

const querySecretRule: RuleDefinition = {
  id: 'query-param-secret',
  title: 'API secret appears in the URL query string',
  category: 'Security',
  severity: 'high',
  run(context) {
    return context.workflow.nodes
      .filter((node) => hasSecretInQueryParam(node))
      .map((node) =>
        makeFinding({
          rule: querySecretRule,
          node,
          confidence: 'high',
          problem: 'A token, secret, or API key appears in a URL query parameter.',
          whyItMatters: 'Query strings are commonly stored in logs, browser history, proxies, and monitoring tools.',
          suggestedFix: 'Move the secret to an Authorization header or n8n credential field.',
        }),
      )
  },
}

const hubspotCreateRule: RuleDefinition = {
  id: 'hubspot-create-without-dedupe',
  title: 'HubSpot contact create has no upstream dedupe step',
  category: 'HubSpot',
  severity: 'high',
  run(context) {
    return nodesInCategory(context, 'hubspot')
      .filter((node) => looksLikeCreateContact(node))
      .filter((node) => !nodeHasUpstreamCategory(context, node, 'hubspot', 10))
      .filter((node) => !nodeHasUpstreamCategory(context, node, 'validation', 6))
      .filter((node) => !hasUpstreamSearchUpdateOrUpsert(context, node))
      .map((node) =>
        makeFinding({
          rule: hubspotCreateRule,
          node,
          confidence: 'medium',
          problem: 'A HubSpot contact create action exists without an obvious upstream search, update, upsert, or dedupe step.',
          whyItMatters: 'Repeated webhook deliveries and retries can create duplicate contacts in HubSpot.',
          suggestedFix: 'Search by normalized email first, then update the existing contact or create only when no match exists.',
        }),
      )
  },
}

const emailNormalizeRule: RuleDefinition = {
  id: 'email-not-normalized-before-hubspot',
  title: 'Email may not be normalized before HubSpot create',
  category: 'HubSpot',
  severity: 'medium',
  run(context) {
    return nodesInCategory(context, 'hubspot')
      .filter((node) => looksLikeCreateContact(node))
      .filter((node) => !hasNormalizerUpstream(context, node, 'email'))
      .map((node) =>
        makeFinding({
          rule: emailNormalizeRule,
          node,
          confidence: 'low',
          problem: 'No obvious upstream email lowercasing, trimming, or normalization step was found.',
          whyItMatters: 'Case and whitespace differences can weaken dedupe checks and produce inconsistent CRM data.',
          suggestedFix: 'Normalize email before dedupe or create: trim whitespace and compare lowercased values.',
        }),
      )
  },
}

const phoneNormalizeRule: RuleDefinition = {
  id: 'phone-not-normalized-before-hubspot',
  title: 'Phone may not be normalized before HubSpot create',
  category: 'HubSpot',
  severity: 'low',
  run(context) {
    return nodesInCategory(context, 'hubspot')
      .filter((node) => looksLikeCreateContact(node))
      .filter((node) => !hasNormalizerUpstream(context, node, 'phone'))
      .map((node) =>
        makeFinding({
          rule: phoneNormalizeRule,
          node,
          confidence: 'low',
          problem: 'No obvious upstream phone normalization step was found.',
          whyItMatters: 'Different phone formats make matching, reporting, and downstream enrichment less reliable.',
          suggestedFix: 'Normalize phone numbers to a consistent format before writing them to HubSpot.',
        }),
      )
  },
}

const duplicateWritePathRule: RuleDefinition = {
  id: 'duplicate-write-path',
  title: 'Trigger can reach multiple write paths',
  category: 'Reliability',
  severity: 'medium',
  run(context) {
    const triggerNodes = context.workflow.nodes.filter(
      (node) =>
        context.categoriesByNodeId[node.id]?.includes('webhook') ||
        context.categoriesByNodeId[node.id]?.includes('schedule'),
    )

    return triggerNodes
      .map((node) => ({ node, writes: reachableWriteNodes(context, node) }))
      .filter(({ writes }) => writes.length > 1)
      .map(({ node, writes }) =>
        makeFinding({
          rule: duplicateWritePathRule,
          node,
          confidence: 'medium',
          problem: `This trigger can reach ${writes.length} write/action nodes: ${writes
            .map((writeNode) => writeNode.name)
            .join(', ')}.`,
          whyItMatters: 'Parallel or repeated write paths can create duplicate CRM records, duplicate messages, or inconsistent state.',
          suggestedFix: 'Confirm the branches are mutually exclusive, then add dedupe keys or a single shared write path.',
        }),
      )
  },
}

const frequentScheduleRule: RuleDefinition = {
  id: 'frequent-schedule-trigger',
  title: 'Schedule trigger may run too frequently',
  category: 'Reliability',
  severity: 'medium',
  run(context) {
    return nodesInCategory(context, 'schedule')
      .filter((node) => scheduleLooksFrequent(node))
      .map((node) =>
        makeFinding({
          rule: frequentScheduleRule,
          node,
          confidence: 'medium',
          problem: 'The schedule appears to run every few minutes or more often.',
          whyItMatters: 'High-frequency schedules can amplify API failures, rate limits, duplicate writes, and cost.',
          suggestedFix: 'Confirm the interval is intentional and add idempotency checks before any write/action nodes.',
        }),
      )
  },
}

const disconnectedCriticalNodeRule: RuleDefinition = {
  id: 'disconnected-critical-node',
  title: 'Action node is disconnected',
  category: 'Reliability',
  severity: 'low',
  run(context) {
    return context.workflow.nodes
      .filter((node) => context.categoriesByNodeId[node.id]?.includes('write'))
      .filter((node) => {
        const incoming = context.graph.incomingById[node.id]?.length ?? 0
        const outgoing = context.graph.outgoingById[node.id]?.length ?? 0
        return incoming === 0 && outgoing === 0
      })
      .map((node) =>
        makeFinding({
          rule: disconnectedCriticalNodeRule,
          node,
          confidence: 'high',
          problem: 'This write/action node is not connected to the workflow graph.',
          whyItMatters: 'Disconnected nodes often indicate unfinished logic, broken exports, or dead production paths.',
          suggestedFix: 'Connect the node intentionally or remove it before shipping the workflow.',
        }),
      )
  },
}

export const allRules: RuleDefinition[] = [
  webhookValidationRule,
  webhookDirectWriteRule,
  webhookSecretRule,
  webhookTestProdRule,
  httpTimeoutRule,
  httpRetryRule,
  httpErrorBranchRule,
  paginationRule,
  hardcodedSecretRule,
  querySecretRule,
  hubspotCreateRule,
  emailNormalizeRule,
  phoneNormalizeRule,
  duplicateWritePathRule,
  frequentScheduleRule,
  disconnectedCriticalNodeRule,
]

export function runRules(context: RuleContext): RiskFinding[] {
  const findings = allRules.flatMap((rule) => rule.run(context))
  return dedupeFindings(findings).sort(compareFindings)
}

function hasUpstreamSearchUpdateOrUpsert(context: RuleContext, node: N8nNode): boolean {
  return nodeHasUpstreamCategory(context, node, 'hubspot', 12)
    ? context.workflow.nodes
        .filter((candidate) => candidate.id !== node.id)
        .filter((candidate) => nodeSearchText(candidate).includes('hubspot'))
        .some((candidate) => looksLikeSearchUpdateOrUpsert(candidate))
    : context.workflow.nodes
        .filter((candidate) => candidate.id !== node.id)
        .filter((candidate) => nodeSearchText(candidate).includes('hubspot'))
        .some((candidate) => looksLikeSearchUpdateOrUpsert(candidate))
}

function dedupeFindings(findings: RiskFinding[]): RiskFinding[] {
  const seen = new Set<string>()
  return findings.filter((finding) => {
    const key = `${finding.ruleId}:${finding.nodeIds.join(',')}:${finding.problem}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const severityRank: Record<RiskFinding['severity'], number> = {
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
