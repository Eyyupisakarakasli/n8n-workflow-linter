import type { ScanResult } from '../scan'

export function buildMarkdownReport(result: ScanResult): string {
  const summary = [
    `# ${result.workflowName} reliability report`,
    '',
    `Source: ${result.sourceLabel}`,
    `Scanned: ${new Date(result.scannedAt).toLocaleString()}`,
    '',
    '## Summary',
    '',
    `- Nodes: ${result.summary.totalNodes}`,
    `- Connections: ${result.summary.totalEdges}`,
    `- Trigger nodes: ${result.summary.triggerNodes}`,
    `- HTTP nodes: ${result.summary.httpNodes}`,
    `- CRM write nodes: ${result.summary.crmWriteNodes}`,
    `- Disconnected nodes: ${result.summary.disconnectedNodes}`,
    `- Findings: ${result.findings.length}`,
  ]

  const warnings =
    result.parserWarnings.length > 0
      ? ['', '## Parser warnings', '', ...result.parserWarnings.map((warning) => `- ${warning}`)]
      : []

  const findings =
    result.findings.length > 0
      ? [
          '',
          '## Findings',
          '',
          ...result.findings.flatMap((finding, index) => [
            `### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`,
            '',
            `- Node: ${finding.nodeNames.join(', ')}`,
            `- Category: ${finding.category}`,
            `- Confidence: ${finding.confidence}`,
            `- Problem: ${finding.problem}`,
            `- Why it matters: ${finding.whyItMatters}`,
            `- Suggested fix: ${finding.suggestedFix}`,
            '',
          ]),
        ]
      : ['', '## Findings', '', 'No critical risks found by the current scanner rules.']

  return [...summary, ...warnings, ...findings, ...buildChecklistLines(result)].join('\n')
}

export function buildFixChecklist(result: ScanResult): string {
  return buildChecklistLines(result).join('\n')
}

function buildChecklistLines(result: ScanResult): string[] {
  if (result.findings.length === 0) {
    return ['', '## Fix checklist', '', '- [ ] Re-run the scan after future workflow changes.']
  }

  return [
    '',
    '## Fix checklist',
    '',
    ...result.findings.map(
      (finding) => `- [ ] ${finding.nodeNames.join(', ')}: ${finding.suggestedFix}`,
    ),
  ]
}
