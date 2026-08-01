import apiNoErrorHandling from './demo-workflows/api-no-error-handling.json?raw'
import scheduleDuplicateRisk from './demo-workflows/schedule-duplicate-risk.json?raw'
import webhookHubspotRisk from './demo-workflows/webhook-hubspot-risk.json?raw'

export interface DemoWorkflow {
  id: string
  name: string
  description: string
  json: string
}

export const demoWorkflows: DemoWorkflow[] = [
  {
    id: 'webhook-hubspot-risk',
    name: 'Webhook to HubSpot risk',
    description: 'Direct public webhook to HubSpot create, no validation or dedupe.',
    json: webhookHubspotRisk,
  },
  {
    id: 'api-no-error-handling',
    name: 'API without error handling',
    description: 'Frequent schedule, list endpoint, no retry/error branch, query token risk.',
    json: apiNoErrorHandling,
  },
  {
    id: 'schedule-duplicate-risk',
    name: 'Duplicate CRM write risk',
    description: 'A scheduled lead sync can reach multiple HubSpot create paths.',
    json: scheduleDuplicateRisk,
  },
]
