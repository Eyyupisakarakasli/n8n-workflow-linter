import cleanWebhookHubspot from '../../tests/fixtures/clean-webhook-hubspot-upsert.json?raw'
import leakyWorkflow from '../../tests/fixtures/leaky-workflow.json?raw'
import scheduleMinutesIntervalRisk from '../../tests/fixtures/schedule-minutes-interval-risk.json?raw'
import webhookHubspotRisk from '../../tests/fixtures/risky-webhook-hubspot-create.json?raw'

export interface DemoWorkflow {
  id: string
  name: string
  description: string
  json: string
}

export const demoWorkflows: DemoWorkflow[] = [
  {
    id: 'clean-webhook-hubspot-upsert',
    name: 'Clean webhook to HubSpot sample',
    description: 'Authenticated webhook, validation, normalization, HubSpot upsert, and Slack notification.',
    json: cleanWebhookHubspot,
  },
  {
    id: 'webhook-hubspot-risk',
    name: 'Webhook to HubSpot risk',
    description: 'Direct public webhook to HubSpot create, no validation or dedupe.',
    json: webhookHubspotRisk,
  },
  {
    id: 'schedule-minutes-interval-risk',
    name: 'Frequent schedule to CRM risk',
    description: 'Real minutesInterval schedule export, HTTP pull, and CRM write without enough hardening.',
    json: scheduleMinutesIntervalRisk,
  },
  {
    id: 'leaky-workflow',
    name: 'Secrets and pinned data sample',
    description: 'Credential ID, hardcoded key, embedded secret, query-string secret, and pinned data.',
    json: leakyWorkflow,
  },
]
