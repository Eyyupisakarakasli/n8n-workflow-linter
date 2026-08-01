import type { ScanResult } from '../scan'
import type { RiskFinding, Severity } from '../rules/types'

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export interface ReportVerdict {
  label: 'Do not share this workflow yet' | 'Safe to share, but worth fixing' | 'All clear'
  detail: string
  tone: 'danger' | 'warning' | 'success'
}

export function getReportVerdict(result: ScanResult): ReportVerdict {
  const blockingFindings = result.findings.filter(
    (finding) => finding.severity === 'critical' || finding.severity === 'high',
  )

  if (blockingFindings.length > 0) {
    return {
      label: 'Do not share this workflow yet',
      detail: `${blockingFindings.length} critical/high finding needs attention before public sharing.`,
      tone: 'danger',
    }
  }

  if (result.findings.length > 0 || result.parserWarnings.length > 0) {
    return {
      label: 'Safe to share, but worth fixing',
      detail: 'No critical/high findings were found, but there are cleanup or reliability items.',
      tone: 'warning',
    }
  }

  return {
    label: 'All clear',
    detail: 'No findings or parser warnings were found by the current scanner rules.',
    tone: 'success',
  }
}

export function buildMarkdownReport(result: ScanResult): string {
  const verdict = getReportVerdict(result)
  const summary = [
    `# ${result.workflowName} reliability report`,
    '',
    `Verdict: ${verdict.label}`,
    `${verdict.detail}`,
    '',
    `Source: ${result.sourceLabel}`,
    `Scanned: ${new Date(result.scannedAt).toLocaleString()}`,
    '',
    '## Summary',
    '',
    `- Nodes: ${result.summary.totalNodes}`,
    `- Active nodes: ${result.summary.activeNodes}`,
    `- Disabled nodes: ${result.summary.disabledNodes}`,
    `- Skipped non-operational nodes: ${result.summary.skippedNodes}`,
    `- Connections scanned: ${result.summary.totalEdges}`,
    `- Trigger nodes: ${result.summary.triggerNodes}`,
    `- HTTP nodes: ${result.summary.httpNodes}`,
    `- CRM write nodes: ${result.summary.crmWriteNodes}`,
    `- Disconnected active nodes: ${result.summary.disconnectedNodes}`,
    `- Parser warnings: ${result.summary.parserWarnings}`,
    `- Findings: ${result.findings.length}`,
  ]

  const warnings =
    result.parserWarnings.length > 0
      ? ['', '## Parser warnings', '', ...result.parserWarnings.map((warning) => `- ${warning}`)]
      : []

  const findings =
    result.findings.length > 0
      ? ['', '## Findings', '', ...severityOrder.flatMap((severity) => findingGroupLines(result.findings, severity))]
      : ['', '## Findings', '', 'No risks found by the current scanner rules.']

  return [...summary, ...warnings, ...findings, ...buildChecklistLines(result)].join('\n')
}

export function buildFixChecklist(result: ScanResult): string {
  return buildChecklistLines(result).join('\n')
}

function findingGroupLines(findings: RiskFinding[], severity: Severity): string[] {
  const group = findings.filter((finding) => finding.severity === severity)
  if (group.length === 0) return []

  return [
    `### ${titleCase(severity)}`,
    '',
    ...group.flatMap((finding, index) => [
      `#### ${index + 1}. ${finding.plainTitle}`,
      '',
      `- Rule: ${finding.ruleId}`,
      `- Node: ${finding.nodeNames.join(', ') || 'Workflow level'}`,
      `- Category: ${finding.category}`,
      `- Confidence: ${finding.confidence}`,
      `- Share impact: ${finding.shareSafetyImpact}`,
      `- Problem: ${finding.problem}`,
      `- Meaning: ${finding.plainMeaning}`,
      '- Fix steps:',
      ...finding.fixSteps.map((step, stepIndex) => `  ${stepIndex + 1}. ${step}`),
      '',
    ]),
  ]
}

function buildChecklistLines(result: ScanResult): string[] {
  if (result.findings.length === 0) {
    return ['', '## Fix checklist', '', '- [ ] Re-run the scan after future workflow changes.']
  }

  return [
    '',
    '## Fix checklist',
    '',
    ...result.findings.map((finding) => {
      const nodeLabel = finding.nodeNames.join(', ') || 'Workflow level'
      return `- [ ] ${nodeLabel}: ${finding.fixSteps[0] ?? finding.suggestedFix}`
    }),
  ]
}

function titleCase(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`
}
