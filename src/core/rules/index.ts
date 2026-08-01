import { getHttpMethod, getWebhookAuthentication } from '../n8n/categories'
import { hasUpstreamNode } from '../n8n/graph'
import type { N8nNode } from '../n8n/types'
import {
  credentialIdLeaks,
  embeddedSecretMatches,
  hasErrorHandling,
  hasKnownSecret,
  hasNormalizerUpstream,
  hasPaginationSignal,
  hasPinnedData,
  hasRetry,
  hasSilentErrorContinue,
  hasTimeout,
  immediateDownstreamHasCategory,
  isDuplicateWriteTarget,
  isDefaultNodeName,
  looksLikeCreateContact,
  looksLikeListEndpoint,
  looksLikeSearchUpdateOrUpsert,
  makeFinding,
  nodeHasDownstreamCategory,
  nodeTextIncludesAny,
  nodesInCategory,
  pathHasCategoryBeforeTarget,
  reachableWritePaths,
  scheduleLooksFrequent,
  urlSecretMatches,
  writeTargetsThatCanRunTogether,
} from './helpers'
import type { RiskFinding, RuleContext, RuleDefinition } from './types'

const httpWriteMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

const webhookValidationRule: RuleDefinition = {
  id: 'webhook-missing-validation',
  title: 'Webhook input reaches actions without validation',
  plainTitle: 'Webhook data reaches production actions before it is checked',
  plainMeaning:
    'This webhook can pass incoming data to write/action steps without a clear validation gate first. A malformed or unexpected payload can create bad CRM records, send the wrong message, or trigger a production side effect.',
  fixSteps: [
    'Add an IF, Switch, Code, or validation node directly after the webhook.',
    'Check required fields such as email, phone, ids, and event type before any write step.',
    'Route invalid payloads to a stop/notification branch instead of continuing.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'Webhook',
  defaultSeverity: 'high',
  run(context) {
    return nodesInCategory(context, 'webhook')
      .filter((node) =>
        reachableWritePaths(context, node).some((path) => !pathHasCategoryBeforeTarget(context, path, 'validation')),
      )
      .map((node) =>
        makeFinding({
          rule: webhookValidationRule,
          node,
          confidence: 'medium',
          problem: 'Webhook data can reach write/action nodes before a validation step.',
          whyItMatters:
            'Bad payloads, missing fields, or unexpected schema changes can create broken records or trigger the wrong downstream action.',
        }),
      )
  },
}

const webhookDirectWriteRule: RuleDefinition = {
  id: 'webhook-direct-write',
  title: 'Webhook writes directly to a side-effect node',
  plainTitle: 'The webhook is wired straight into a write/action step',
  plainMeaning:
    'A public webhook should usually authenticate, validate, normalize, and dedupe incoming data before it writes to another system. This workflow starts a side effect immediately.',
  fixSteps: [
    'Insert validation and transform nodes between the webhook and the first write/action node.',
    'Add dedupe or idempotency checks before CRM/database/API write steps.',
    'Keep notification-only branches separate from production write paths.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'Webhook',
  defaultSeverity: 'high',
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
        }),
      )
  },
}

const webhookSecretRule: RuleDefinition = {
  id: 'webhook-missing-secret-check',
  title: 'Webhook has no authentication setting',
  plainTitle: 'Anyone with the webhook URL may be able to trigger this workflow',
  plainMeaning:
    'The Webhook node is configured with no n8n authentication and no nearby signature/secret verification step. A leaked webhook URL can become a production trigger.',
  fixSteps: [
    'Open the Webhook node in n8n and set Authentication to Header Auth, Basic Auth, or another intended method.',
    'If the caller signs payloads, add a signature verification step before any action nodes.',
    'Retest the caller so it sends the required header/secret before sharing the workflow.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'Security',
  defaultSeverity: 'high',
  run(context) {
    return nodesInCategory(context, 'webhook')
      .filter((node) => getWebhookAuthentication(node) === 'none')
      .filter((node) => !nodeHasDownstreamCategory(context, node, 'security', 3))
      .map((node) =>
        makeFinding({
          rule: webhookSecretRule,
          node,
          confidence: 'high',
          problem: 'The webhook authentication parameter is empty or set to none.',
          whyItMatters:
            'Anyone who discovers a public webhook URL may be able to trigger production actions if the request is not verified.',
        }),
      )
  },
}

const webhookTestProdRule: RuleDefinition = {
  id: 'webhook-test-prod-confusion',
  title: 'Webhook name or path suggests test/prod confusion',
  plainTitle: 'This webhook still looks like a test or staging endpoint',
  plainMeaning:
    'Test wording in the path, name, or parameters is a common sign that a workflow was exported before production cleanup.',
  fixSteps: [
    'Confirm this is the production workflow, not a copied test export.',
    'Rename the webhook and path to match the production event contract.',
    'Re-run the scan after updating the workflow export.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'Webhook',
  defaultSeverity: 'medium',
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
        }),
      )
  },
}

const httpTimeoutRule: RuleDefinition = {
  id: 'http-missing-timeout',
  title: 'HTTP Request has no timeout setting',
  plainTitle: 'This HTTP call can wait too long before failing',
  plainMeaning:
    'No explicit timeout is set on this HTTP Request node. Slow third-party APIs can stall workflow execution and let queued retries pile up.',
  fixSteps: [
    'Open the HTTP Request node and set a timeout under Options.',
    'Use a normal API timeout such as 10-30 seconds unless this endpoint is known to be slow.',
    'Route timeout failures into an error/alert branch.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'API',
  defaultSeverity: 'medium',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => !hasTimeout(node))
      .map((node) =>
        makeFinding({
          rule: httpTimeoutRule,
          node,
          confidence: 'high',
          problem: 'This HTTP Request node does not expose a timeout setting in its parameters.',
          whyItMatters: 'Slow third-party APIs can stall workflow execution and make retries pile up.',
        }),
      )
  },
}

const httpRetryRule: RuleDefinition = {
  id: 'http-missing-retry',
  title: 'HTTP Request has no retry policy',
  plainTitle: 'This HTTP call does not retry temporary failures',
  plainMeaning:
    'The node has no explicit retry settings. A transient network failure, 429, or 5xx response can break the run even when a second attempt would have succeeded.',
  fixSteps: [
    'Enable Retry On Fail for the HTTP Request node.',
    'Use conservative retry counts and spacing, for example 3 tries with a short wait.',
    'Send repeated failures to an alert or dead-letter path.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'API',
  defaultSeverity: 'medium',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => !hasRetry(node))
      .map((node) =>
        makeFinding({
          rule: httpRetryRule,
          node,
          confidence: 'high',
          problem: 'This HTTP Request node has no retryOnFail/maxTries policy.',
          whyItMatters: 'Temporary network failures and rate limits can break the whole workflow without a retry strategy.',
        }),
      )
  },
}

const httpErrorBranchRule: RuleDefinition = {
  id: 'http-missing-error-branch',
  title: 'HTTP Request has no error branch',
  plainTitle: 'This HTTP call can fail without a recovery path',
  plainMeaning:
    'The HTTP Request node has no error output branch or equivalent error routing. A bad response can stop production without cleanup or notification.',
  fixSteps: [
    'Enable error output handling for the HTTP Request node.',
    'Connect the error output to a notification, log, or retry/dead-letter path.',
    'Avoid silently continuing on the normal output when the call failed.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'API',
  defaultSeverity: 'high',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => !hasErrorHandling(context, node) && !hasSilentErrorContinue(node))
      .map((node) => {
        const isWrite = httpWriteMethods.has(getHttpMethod(node))
        return makeFinding({
          rule: httpErrorBranchRule,
          node,
          severity: isWrite ? 'high' : 'medium',
          confidence: 'medium',
          shareSafetyImpact: isWrite ? 'must-fix' : 'worth-fixing',
          problem: 'This HTTP Request node does not show an error branch or continue-on-fail handling.',
          whyItMatters:
            'An API outage or bad response can stop production workflows without notification or cleanup.',
        })
      })
  },
}

const httpSilentContinueRule: RuleDefinition = {
  id: 'http-silent-error-continue',
  title: 'HTTP Request continues failures on the normal output',
  plainTitle: 'Failed HTTP calls may keep flowing through the success path',
  plainMeaning:
    'This node appears to continue after failure without a separate error output. Downstream nodes may treat an error response as valid data.',
  fixSteps: [
    'Use the error output branch instead of continuing failures on the normal output.',
    'Connect the error branch to alerting or a controlled stop path.',
    'Verify downstream nodes only receive successful API responses.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'API',
  defaultSeverity: 'medium',
  run(context) {
    return nodesInCategory(context, 'http')
      .filter((node) => hasSilentErrorContinue(node))
      .map((node) =>
        makeFinding({
          rule: httpSilentContinueRule,
          node,
          confidence: 'medium',
          problem: 'This HTTP Request node continues failed requests on the regular output.',
          whyItMatters: 'Downstream write steps may process an error body as if it were a successful API response.',
        }),
      )
  },
}

const paginationRule: RuleDefinition = {
  id: 'http-pagination-suspect',
  title: 'List-style API call may be missing pagination',
  plainTitle: 'This list API call may only read the first page',
  plainMeaning:
    'The request looks like it reads a collection, but no pagination, cursor, offset, limit, or return-all signal was found.',
  fixSteps: [
    'Confirm the API pagination model for this endpoint.',
    'Loop through next page, cursor, offset, or page number until no more data remains.',
    'Add a test with more records than one API page.',
  ],
  shareSafetyImpact: 'minor',
  category: 'API',
  defaultSeverity: 'low',
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
        }),
      )
  },
}

const hardcodedSecretRule: RuleDefinition = {
  id: 'hardcoded-secret',
  title: 'Possible hardcoded API key or token',
  plainTitle: 'A password or API key is written inside this file',
  plainMeaning:
    'The workflow export contains a value that matches a known secret format such as OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe, Twilio, JWT, or a private key block.',
  fixSteps: [
    'Regenerate or revoke the exposed key at the provider.',
    'Move the value into n8n Credentials or an environment variable.',
    'Export the workflow again and re-run the scan before sharing.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'Security',
  defaultSeverity: 'critical',
  run(context) {
    return context.originalWorkflow.nodes.flatMap((node) =>
      hasKnownSecret(node).map((match) =>
        makeFinding({
          rule: hardcodedSecretRule,
          node,
          confidence: 'high',
          problem: `${match.label} appears in this node (${match.redacted}).`,
          whyItMatters: 'Secrets in workflow JSON can leak through exports, screenshots, shared templates, or version control.',
        }),
      ),
    )
  },
}

const embeddedSecretRule: RuleDefinition = {
  id: 'embedded-secret',
  title: 'Credential-shaped value is embedded in a node',
  plainTitle: 'A password or key is typed into a step instead of stored safely',
  plainMeaning:
    'This value is sitting in a Code node assignment or a header/query-style parameter where a credential belongs. It may not match a famous provider prefix, but it behaves like a real secret.',
  fixSteps: [
    'Treat the value as exposed and regenerate it if it belongs to a real service.',
    'Move HTTP header/query credentials into the node authentication/credential settings.',
    'Remove credentials from Code nodes and pass runtime values through n8n credentials or environment variables.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'Security',
  defaultSeverity: 'critical',
  run(context) {
    return context.originalWorkflow.nodes.flatMap((node) =>
      embeddedSecretMatches(node).map((match) =>
        makeFinding({
          rule: embeddedSecretRule,
          node,
          confidence: 'high',
          problem: `${match.source} holds a literal credential-like value (${match.redacted}).`,
          whyItMatters:
            'Values typed directly into node parameters are readable in the exported workflow and travel wherever the file goes.',
        }),
      ),
    )
  },
}

const credentialInUrlRule: RuleDefinition = {
  id: 'credential-in-url',
  title: 'API secret appears in the URL query string',
  plainTitle: 'A key is being sent inside the web address itself',
  plainMeaning:
    'The URL contains a credential query parameter such as api_key, token, or secret. URLs are copied into logs by many systems and are hard to clean later.',
  fixSteps: [
    'Regenerate or revoke the key if it is real.',
    'Remove the secret value from the URL.',
    'Use an Authorization/header credential or an n8n credential-backed expression instead.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'Security',
  defaultSeverity: 'critical',
  run(context) {
    return context.originalWorkflow.nodes.flatMap((node) =>
      urlSecretMatches(node).map((match) =>
        makeFinding({
          rule: credentialInUrlRule,
          node,
          confidence: 'high',
          problem: `URL passes "${match.paramName}" as a literal query parameter (${match.redacted}).`,
          whyItMatters: 'Query strings are commonly stored in logs, browser history, proxies, and monitoring tools.',
        }),
      ),
    )
  },
}

const realCredentialIdRule: RuleDefinition = {
  id: 'real-credential-id',
  title: 'Workflow contains a real n8n credential ID',
  plainTitle: 'This file points at a login that only exists in your n8n account',
  plainMeaning:
    'n8n exports can include the private ID of a credential from your instance. It is not the password, but it leaks internal account wiring and breaks imports for other users.',
  fixSteps: [
    'Before sharing, replace the credential id with REPLACE_WITH_CREDENTIAL_ID.',
    'Keep the credential name generic enough for another user to understand what to connect.',
    'Ask the importing user to pick their own n8n credential after import.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'Security',
  defaultSeverity: 'critical',
  run(context) {
    const leaksByCredential = new Map<
      string,
      { credentialType: string; credentialId: string; redacted: string; nodes: N8nNode[] }
    >()

    for (const node of context.originalWorkflow.nodes) {
      for (const leak of credentialIdLeaks(node)) {
        const key = `${leak.credentialType}:${leak.credentialId}`
        const existing = leaksByCredential.get(key) ?? { ...leak, nodes: [] }
        existing.nodes.push(node)
        leaksByCredential.set(key, existing)
      }
    }

    return [...leaksByCredential.values()].map((leak) =>
      makeFinding({
        rule: realCredentialIdRule,
        nodes: leak.nodes,
        confidence: 'high',
        problem: `${leak.credentialType} credential uses a real instance ID (${leak.redacted}) in ${leak.nodes.length} ${leak.nodes.length === 1 ? 'node' : 'nodes'}.`,
        whyItMatters:
          'Credential IDs do not transfer between n8n accounts and reveal details from the private instance that exported the file.',
        affectedNodeCount: leak.nodes.length,
        groupedRuleIds: [realCredentialIdRule.id],
        groupKind: 'credential-leak',
      }),
    )
  },
}

const pinnedDataRule: RuleDefinition = {
  id: 'pinned-data',
  title: 'Workflow export contains pinned data',
  plainTitle: 'Saved test data is stored inside this file',
  plainMeaning:
    'Pinned data is saved into the workflow export. It can include real emails, orders, webhook payloads, or customer records.',
  fixSteps: [
    'Open the named node in n8n and inspect the pinned data.',
    'Unpin the node before publishing or sharing the workflow.',
    'Export the workflow again and re-run the scan.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'Data exposure',
  defaultSeverity: 'medium',
  run(context) {
    const pinnedNodeNames = hasPinnedData(context)
    if (pinnedNodeNames.length === 0) return []

    const pinnedNodes = context.originalWorkflow.nodes.filter((node) => pinnedNodeNames.includes(node.name))

    return [
      makeFinding({
        rule: pinnedDataRule,
        nodes: pinnedNodes,
        confidence: 'high',
        problem: `Workflow ships pinned data for: ${pinnedNodeNames.sort().join(', ')}.`,
        whyItMatters:
          'Pinned records are embedded in the exported JSON and may contain real customer or payload data.',
      }),
    ]
  },
}

const hubspotCreateRule: RuleDefinition = {
  id: 'hubspot-create-without-dedupe',
  title: 'HubSpot contact create has no upstream dedupe step',
  plainTitle: 'HubSpot can create duplicate contacts on repeated runs',
  plainMeaning:
    'This workflow creates HubSpot contacts without a reachable upstream search, update, upsert, or dedupe step. Replayed webhooks and retries can create duplicates.',
  fixSteps: [
    'Normalize the email address before the HubSpot write.',
    'Search HubSpot by normalized email before creating a contact.',
    'Update the existing contact or create only when no match exists.',
  ],
  shareSafetyImpact: 'must-fix',
  category: 'HubSpot',
  defaultSeverity: 'high',
  run(context) {
    return nodesInCategory(context, 'hubspot')
      .filter((node) => looksLikeCreateContact(node))
      .filter((node) => !hasUpstreamHubspotDedupe(context, node))
      .map((node) =>
        makeFinding({
          rule: hubspotCreateRule,
          node,
          confidence: 'high',
          problem: 'A HubSpot contact create action exists without a reachable upstream search, update, upsert, or dedupe step.',
          whyItMatters: 'Repeated webhook deliveries and retries can create duplicate contacts in HubSpot.',
        }),
      )
  },
}

const emailNormalizeRule: RuleDefinition = {
  id: 'email-not-normalized-before-hubspot',
  title: 'Email may not be normalized before HubSpot create',
  plainTitle: 'Email is written to HubSpot without clear normalization first',
  plainMeaning:
    'No upstream step clearly trims and lowercases email before the HubSpot create. This weakens dedupe and reporting.',
  fixSteps: [
    'Trim whitespace from email before HubSpot writes.',
    'Compare and store email in lowercase.',
    'Run the HubSpot search/dedupe step on the normalized value.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'HubSpot',
  defaultSeverity: 'medium',
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
        }),
      )
  },
}

const phoneNormalizeRule: RuleDefinition = {
  id: 'phone-not-normalized-before-hubspot',
  title: 'Phone may not be normalized before HubSpot create',
  plainTitle: 'Phone is written to HubSpot without clear normalization first',
  plainMeaning:
    'No upstream step clearly normalizes phone numbers before HubSpot create. Phone formats vary by market, so treat this as a conservative hygiene warning.',
  fixSteps: [
    'Normalize phone numbers to one expected format before writing them.',
    'Strip obvious formatting noise such as spaces, brackets, and dashes.',
    'Skip the warning if the upstream source already guarantees a normalized phone field.',
  ],
  shareSafetyImpact: 'minor',
  category: 'HubSpot',
  defaultSeverity: 'low',
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
        }),
      )
  },
}

const duplicateWritePathRule: RuleDefinition = {
  id: 'duplicate-write-path',
  title: 'Trigger can reach multiple CRM/database write paths',
  plainTitle: 'One trigger can reach multiple production write paths',
  plainMeaning:
    'The trigger can reach more than one CRM/database/API write node. Notification nodes are ignored, so this points at state-changing production writes.',
  fixSteps: [
    'Confirm the branches are mutually exclusive.',
    'Add idempotency keys or dedupe checks before every write path.',
    'Prefer one shared write path when two branches write the same object.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'Reliability',
  defaultSeverity: 'medium',
  run(context) {
    const triggerNodes = context.workflow.nodes.filter(
      (node) =>
        context.categoriesByNodeId[node.id]?.includes('webhook') ||
        context.categoriesByNodeId[node.id]?.includes('schedule'),
    )

    return triggerNodes
      .map((node) => ({
        node,
        writes: writeTargetsThatCanRunTogether(
          reachableWritePaths(context, node).filter((path) => isDuplicateWriteTarget(context, path.target)),
        ),
      }))
      .filter(({ writes }) => writes.length > 1)
      .map(({ node, writes }) =>
        makeFinding({
          rule: duplicateWritePathRule,
          node,
          confidence: 'medium',
          problem: `This trigger can reach ${writes.length} CRM/database/API write nodes: ${writes
            .map((writeNode) => writeNode.name)
            .join(', ')}.`,
          whyItMatters: 'Parallel or repeated write paths can create duplicate CRM records or inconsistent state.',
        }),
      )
  },
}

const frequentScheduleRule: RuleDefinition = {
  id: 'frequent-schedule-trigger',
  title: 'Schedule trigger may run too frequently',
  plainTitle: 'This schedule can amplify failures quickly',
  plainMeaning:
    'The schedule appears to run every few minutes or more often. High-frequency polling can amplify API outages, rate limits, duplicate writes, and cost.',
  fixSteps: [
    'Confirm the interval is intentional for production.',
    'Add idempotency or dedupe checks before write/action nodes.',
    'Add retry and error routing before sharing the workflow.',
  ],
  shareSafetyImpact: 'worth-fixing',
  category: 'Reliability',
  defaultSeverity: 'medium',
  run(context) {
    return nodesInCategory(context, 'schedule')
      .filter((node) => scheduleLooksFrequent(node))
      .map((node) =>
        makeFinding({
          rule: frequentScheduleRule,
          node,
          confidence: 'high',
          problem: 'The schedule appears to run every few minutes or more often.',
          whyItMatters: 'High-frequency schedules can amplify API failures, rate limits, duplicate writes, and cost.',
        }),
      )
  },
}

const disconnectedCriticalNodeRule: RuleDefinition = {
  id: 'disconnected-critical-node',
  title: 'Action node is disconnected',
  plainTitle: 'A production action step is disconnected from the workflow',
  plainMeaning:
    'This active write/action node is not connected to the workflow graph. It may be unfinished logic or dead production behavior left on the canvas.',
  fixSteps: [
    'Connect the node intentionally if it belongs in the workflow.',
    'Delete the node if it was only a drafting artifact.',
    'Re-export and re-run the scan to confirm the graph is clean.',
  ],
  shareSafetyImpact: 'minor',
  category: 'Reliability',
  defaultSeverity: 'low',
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
        }),
      )
  },
}

const defaultNodeNamesRule: RuleDefinition = {
  id: 'default-node-names',
  title: 'Several nodes still use default names',
  plainTitle: 'Several steps are still called things like HTTP Request1',
  plainMeaning:
    'Default node names make workflows hard to debug and hand off. Error messages such as HTTP Request2 failed do not explain what was being fetched.',
  fixSteps: [
    'Rename each default-named node to describe what it does.',
    'Use names such as Fetch recent leads or Drop leads without email instead of the node type.',
    'Keep the default name only for throwaway local drafts.',
  ],
  shareSafetyImpact: 'minor',
  category: 'Hygiene',
  defaultSeverity: 'info',
  run(context) {
    const defaults = context.workflow.nodes.filter(isDefaultNodeName)
    if (defaults.length < 3) return []

    return [
      makeFinding({
        rule: defaultNodeNamesRule,
        nodes: defaults,
        confidence: 'high',
        problem: `${defaults.length} active nodes still use default n8n names.`,
        whyItMatters: 'Default names make debugging, support, and handoff much harder after the workflow grows.',
      }),
    ]
  },
}

const disabledNodeRule: RuleDefinition = {
  id: 'disabled-node',
  title: 'Disabled node left on the canvas',
  plainTitle: 'A switched-off step is still sitting on the canvas',
  plainMeaning:
    'Disabled nodes do not run and are excluded from active production risk checks. They are still worth documenting so future editors know whether the step is intentionally disabled.',
  fixSteps: [
    'Delete the disabled node if it was only a draft.',
    'Add a nearby Sticky Note explaining why it stays disabled if it is intentional.',
    'Re-run the scan after cleanup.',
  ],
  shareSafetyImpact: 'minor',
  category: 'Hygiene',
  defaultSeverity: 'info',
  run(context) {
    if (context.disabledNodes.length === 0) return []

    return [
      makeFinding({
        rule: disabledNodeRule,
        nodes: context.disabledNodes,
        confidence: 'high',
        problem: `${context.disabledNodes.length} disabled node(s) were skipped by active production risk checks.`,
        whyItMatters: 'Future editors may not know whether disabled nodes are intentional or accidentally left behind.',
      }),
    ]
  },
}

export const allRules: RuleDefinition[] = [
  hardcodedSecretRule,
  embeddedSecretRule,
  credentialInUrlRule,
  realCredentialIdRule,
  pinnedDataRule,
  webhookValidationRule,
  webhookDirectWriteRule,
  webhookSecretRule,
  webhookTestProdRule,
  httpTimeoutRule,
  httpRetryRule,
  httpErrorBranchRule,
  httpSilentContinueRule,
  paginationRule,
  hubspotCreateRule,
  emailNormalizeRule,
  phoneNormalizeRule,
  duplicateWritePathRule,
  frequentScheduleRule,
  disconnectedCriticalNodeRule,
  defaultNodeNamesRule,
  disabledNodeRule,
]

export function runRules(context: RuleContext): RiskFinding[] {
  const findings = allRules.flatMap((rule) => rule.run(context))
  return dedupeFindings(findings).sort(compareFindings)
}

function hasUpstreamHubspotDedupe(context: RuleContext, node: N8nNode): boolean {
  return hasUpstreamNode(
    context.workflow,
    context.graph,
    node.id,
    (candidate) =>
      context.categoriesByNodeId[candidate.id]?.includes('hubspot') === true &&
      looksLikeSearchUpdateOrUpsert(candidate),
    context.maxGraphDepth,
  )
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
