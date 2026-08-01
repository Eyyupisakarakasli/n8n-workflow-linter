import {
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Copy,
  Download,
  FileJson,
  FileText,
  Filter,
  Loader2,
  Mail,
  Play,
  ShieldCheck,
  Upload,
  XCircle,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type DragEvent } from 'react'
import './App.css'
import { buildFixChecklist, buildMarkdownReport, getReportVerdict } from './core/report/markdown'
import { ScannerInputError, scanWorkflowInput, type ScanError, type ScanResult } from './core/scan'
import type { Severity } from './core/rules/types'
import { demoWorkflows } from './data/demoWorkflows'
import type { ScanWorkerRequest, ScanWorkerResponse } from './worker/scanner.worker'

const maxFileBytes = 2 * 1024 * 1024
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const feedbackEmail = 'eyyupisa16@gmail.com'

type ScanStatus = 'idle' | 'scanning' | 'ready' | 'error'
type CopyState = 'idle' | 'copied' | 'failed'

function App() {
  const [rawInput, setRawInput] = useState('')
  const [sourceLabel, setSourceLabel] = useState('Pasted workflow')
  const [selectedDemoId, setSelectedDemoId] = useState(demoWorkflows[0]?.id ?? '')
  const [status, setStatus] = useState<ScanStatus>('idle')
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [scanError, setScanError] = useState<ScanError | null>(null)
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [showInfoFindings, setShowInfoFindings] = useState(false)
  const [reportCopyState, setReportCopyState] = useState<CopyState>('idle')
  const [checklistCopyState, setChecklistCopyState] = useState<CopyState>('idle')
  const [isDragging, setIsDragging] = useState(false)
  const workerRef = useRef<Worker | null>(null)

  useEffect(() => {
    const demo = demoWorkflows.find((item) => item.id === selectedDemoId)
    if (!rawInput && demo) {
      setRawInput(demo.json)
      setSourceLabel(demo.name)
    }
  }, [rawInput, selectedDemoId])

  useEffect(() => {
    return () => {
      workerRef.current?.terminate()
    }
  }, [])

  const visibleFindings = useMemo(() => {
    if (!scanResult) return []

    return scanResult.findings.filter((finding) => {
      const matchesSeverity = severityFilter === 'all' || finding.severity === severityFilter
      const matchesCategory = categoryFilter === 'all' || finding.category === categoryFilter
      const matchesInfoVisibility = severityFilter !== 'all' || showInfoFindings || finding.severity !== 'info'
      return matchesSeverity && matchesCategory && matchesInfoVisibility
    })
  }, [categoryFilter, scanResult, severityFilter, showInfoFindings])

  const categoryOptions = useMemo(() => {
    if (!scanResult) return []
    return [...new Set(scanResult.findings.map((finding) => finding.category))].sort()
  }, [scanResult])

  function setSizeLimitError(source: 'file' | 'paste') {
    setStatus('error')
    setScanResult(null)
    setScanError({
      code: 'invalid_workflow',
      title: source === 'file' ? 'Workflow file is too large' : 'Workflow JSON is too large',
      detail: 'The current public beta accepts workflow JSON up to 2 MB.',
    })
  }

  function runScan(input = rawInput, label = sourceLabel) {
    if (byteSize(input) > maxFileBytes) {
      setSizeLimitError('paste')
      return
    }

    const requestId = createRequestId()
    workerRef.current?.terminate()

    setStatus('scanning')
    setScanError(null)
    setSeverityFilter('all')
    setCategoryFilter('all')
    setShowInfoFindings(false)
    setReportCopyState('idle')
    setChecklistCopyState('idle')

    const completeWithResult = (result: ScanResult) => {
      setScanResult(result)
      setStatus('ready')
    }

    const completeWithError = (error: ScanError) => {
      setScanResult(null)
      setScanError(error)
      setStatus('error')
    }

    const runMainThreadFallback = () => {
      try {
        completeWithResult(scanWorkflowInput(input, label))
      } catch (error) {
        completeWithError(normalizeScanError(error))
      }
    }

    let worker: Worker
    try {
      worker = new Worker(new URL('./worker/scanner.worker.ts', import.meta.url), { type: 'module' })
      workerRef.current = worker
    } catch {
      runMainThreadFallback()
      return
    }

    worker.onmessage = (event: MessageEvent<ScanWorkerResponse>) => {
      if (event.data.requestId !== requestId) return

      if (event.data.ok) {
        completeWithResult(event.data.result)
      } else {
        completeWithError(event.data.error)
      }

      worker.terminate()
      workerRef.current = null
    }

    worker.onerror = () => {
      worker.terminate()
      workerRef.current = null
      runMainThreadFallback()
    }

    try {
      worker.postMessage({ requestId, sourceLabel: label, input } satisfies ScanWorkerRequest)
    } catch {
      worker.terminate()
      workerRef.current = null
      runMainThreadFallback()
    }
  }

  async function handleFile(file: File) {
    setScanResult(null)
    setScanError(null)

    if (!file.name.toLowerCase().endsWith('.json') && file.type !== 'application/json') {
      setStatus('error')
      setScanError({
        code: 'invalid_json',
        title: 'Upload a JSON file',
        detail: 'n8n workflow exports should be uploaded as .json files.',
      })
      return
    }

    if (file.size > maxFileBytes) {
      setSizeLimitError('file')
      return
    }

    const text = await file.text()
    setRawInput(text)
    setSourceLabel(file.name)
    setSelectedDemoId('')
    runScan(text, file.name)
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault()
    setIsDragging(false)

    const file = event.dataTransfer.files[0]
    if (file) void handleFile(file)
  }

  function handleRawInputChange(value: string) {
    setRawInput(value)
    setSourceLabel('Pasted workflow')
    setSelectedDemoId('')
    setScanResult(null)

    if (byteSize(value) > maxFileBytes) {
      setSizeLimitError('paste')
      return
    }

    setStatus('idle')
    setScanError(null)
  }

  function loadDemo(demoId: string) {
    if (!demoId) {
      setSelectedDemoId('')
      setRawInput('')
      setSourceLabel('Pasted workflow')
      setScanResult(null)
      setScanError(null)
      setStatus('idle')
      return
    }

    const demo = demoWorkflows.find((item) => item.id === demoId)
    if (!demo) return

    setSelectedDemoId(demo.id)
    setRawInput(demo.json)
    setSourceLabel(demo.name)
    setScanResult(null)
    setScanError(null)
    setStatus('idle')
  }

  async function copyText(value: string, target: 'report' | 'checklist') {
    const setCopyState = target === 'report' ? setReportCopyState : setChecklistCopyState

    if (await writeClipboard(value)) {
      setCopyState('copied')
      window.setTimeout(() => setCopyState('idle'), 1600)
      return
    }

    setCopyState('failed')
    window.setTimeout(() => setCopyState('idle'), 2200)
  }

  function downloadReport(result: ScanResult) {
    const blob = new Blob([buildMarkdownReport(result)], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${slugify(result.workflowName)}-reliability-report.md`
    document.body.append(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Local n8n reliability scanner</p>
          <h1>n8n Workflow Linter</h1>
          <p className="header-promise">Check whether an exported n8n workflow is safe to share or use in production.</p>
          <p className="header-subline">Upload your workflow JSON and get a local security and reliability report.</p>
        </div>
        <div className="privacy-badge">
          <ShieldCheck size={18} aria-hidden="true" />
          <span>Your workflow is analyzed locally in your browser.</span>
        </div>
      </header>

      <section className="workspace-grid">
        <section className="input-panel" aria-label="Workflow input">
          <div className="panel-heading">
            <div>
              <h2>Workflow JSON</h2>
              <p>Upload, paste, or inspect a sample export.</p>
            </div>
            <FileJson size={22} aria-hidden="true" />
          </div>

          <label
            className={`dropzone ${isDragging ? 'dragging' : ''}`}
            onDragEnter={(event) => {
              event.preventDefault()
              setIsDragging(true)
            }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
          >
            <Upload size={24} aria-hidden="true" />
            <span>Drop or choose workflow JSON</span>
            <input
              type="file"
              accept=".json,application/json"
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) void handleFile(file)
                event.currentTarget.value = ''
              }}
            />
          </label>

          <div className="demo-row">
            <label htmlFor="demo-workflow">Demo</label>
            <select id="demo-workflow" value={selectedDemoId} onChange={(event) => loadDemo(event.target.value)}>
              <option value="">None</option>
              {demoWorkflows.map((demo) => (
                <option key={demo.id} value={demo.id}>
                  {demo.name}
                </option>
              ))}
            </select>
          </div>

          <textarea
            aria-label="Paste n8n workflow JSON"
            value={rawInput}
            onChange={(event) => handleRawInputChange(event.target.value)}
            spellCheck={false}
          />

          <button className="primary-action" type="button" onClick={() => runScan()} disabled={status === 'scanning'}>
            {status === 'scanning' ? (
              <Loader2 className="spin" size={18} aria-hidden="true" />
            ) : (
              <Play size={18} aria-hidden="true" />
            )}
            <span>{status === 'scanning' ? 'Scanning' : 'Scan workflow'}</span>
          </button>

          {selectedDemoId ? (
            <p className="demo-note">{demoWorkflows.find((demo) => demo.id === selectedDemoId)?.description}</p>
          ) : null}
        </section>

        <section className="report-panel" aria-live="polite">
          {status === 'idle' ? <EmptyState /> : null}
          {status === 'scanning' ? <ScanningState /> : null}
          {status === 'error' && scanError ? <ErrorState error={scanError} /> : null}
          {status === 'ready' && scanResult ? (
            <ReportView
              result={scanResult}
              visibleFindings={visibleFindings}
              categoryOptions={categoryOptions}
              severityFilter={severityFilter}
              categoryFilter={categoryFilter}
              showInfoFindings={showInfoFindings}
              reportCopyState={reportCopyState}
              checklistCopyState={checklistCopyState}
              onSeverityChange={setSeverityFilter}
              onCategoryChange={setCategoryFilter}
              onShowInfoChange={setShowInfoFindings}
              onCopyReport={() => void copyText(buildMarkdownReport(scanResult), 'report')}
              onCopyChecklist={() => void copyText(buildFixChecklist(scanResult), 'checklist')}
              onDownloadReport={() => downloadReport(scanResult)}
            />
          ) : null}
        </section>
      </section>

      <DocsBlock />
    </main>
  )
}

function EmptyState() {
  return (
    <div className="empty-state">
      <FileText size={34} aria-hidden="true" />
      <h2>Ready to scan</h2>
      <p>Choose a sample or add a workflow JSON export.</p>
    </div>
  )
}

function ScanningState() {
  return (
    <div className="empty-state">
      <Loader2 className="spin" size={34} aria-hidden="true" />
      <h2>Scanning workflow</h2>
      <p>The analysis is running in a browser worker.</p>
    </div>
  )
}

function ErrorState({ error }: { error: ScanError }) {
  return (
    <div className="error-state">
      <XCircle size={34} aria-hidden="true" />
      <h2>{error.title}</h2>
      <p>{error.detail}</p>
    </div>
  )
}

interface ReportViewProps {
  result: ScanResult
  visibleFindings: ScanResult['findings']
  categoryOptions: string[]
  severityFilter: 'all' | Severity
  categoryFilter: string
  showInfoFindings: boolean
  reportCopyState: CopyState
  checklistCopyState: CopyState
  onSeverityChange: (severity: 'all' | Severity) => void
  onCategoryChange: (category: string) => void
  onShowInfoChange: (showInfo: boolean) => void
  onCopyReport: () => void
  onCopyChecklist: () => void
  onDownloadReport: () => void
}

function ReportView({
  result,
  visibleFindings,
  categoryOptions,
  severityFilter,
  categoryFilter,
  showInfoFindings,
  reportCopyState,
  checklistCopyState,
  onSeverityChange,
  onCategoryChange,
  onShowInfoChange,
  onCopyReport,
  onCopyChecklist,
  onDownloadReport,
}: ReportViewProps) {
  const verdict = getReportVerdict(result)
  const highCount = result.findings.filter(
    (finding) => finding.severity === 'critical' || finding.severity === 'high',
  ).length
  const highAffectedNodeCount = new Set(
    result.findings
      .filter((finding) => finding.severity === 'critical' || finding.severity === 'high')
      .flatMap((finding) => finding.nodeIds),
  ).size
  const infoCount = result.findings.filter((finding) => finding.severity === 'info').length
  const hiddenInfoCount = severityFilter === 'all' && !showInfoFindings ? infoCount : 0
  const groupedFindings = severityOrder
    .map((severity) => ({
      severity,
      findings: visibleFindings.filter((finding) => finding.severity === severity),
    }))
    .filter((group) => group.findings.length > 0)

  return (
    <div className="report-stack">
      <div className="report-header">
        <div>
          <p className="eyebrow">{result.sourceLabel}</p>
          <h2>{result.workflowName}</h2>
        </div>
        <div className={highCount > 0 ? 'risk-pill high' : 'risk-pill clean'}>
          {highCount > 0 ? (
            <AlertTriangle size={18} aria-hidden="true" />
          ) : (
            <CheckCircle2 size={18} aria-hidden="true" />
          )}
          <span>{highCount > 0 ? `${highCount} critical/high, ${highAffectedNodeCount} nodes` : 'No critical/high findings'}</span>
        </div>
      </div>

      <div className={`verdict-band ${verdict.tone}`}>
        {verdict.tone === 'success' ? (
          <CheckCircle2 size={21} aria-hidden="true" />
        ) : (
          <AlertTriangle size={21} aria-hidden="true" />
        )}
        <div>
          <strong>{verdict.label}</strong>
          <span>{verdict.detail}</span>
        </div>
      </div>

      <div className="summary-grid">
        <SummaryMetric label="Nodes" value={result.summary.totalNodes} />
        <SummaryMetric label="Active" value={result.summary.activeNodes} />
        <SummaryMetric label="Disabled" value={result.summary.disabledNodes} />
        <SummaryMetric label="Skipped" value={result.summary.skippedNodes} />
        <SummaryMetric label="Affected" value={result.summary.affectedNodes} />
        <SummaryMetric label="Connections" value={result.summary.totalEdges} />
        <SummaryMetric label="Triggers" value={result.summary.triggerNodes} />
        <SummaryMetric label="HTTP" value={result.summary.httpNodes} />
        <SummaryMetric label="No timeout" value={result.summary.httpNodesMissingTimeout} />
        <SummaryMetric label="No retry" value={result.summary.httpNodesMissingRetry} />
        <SummaryMetric label="Error risk" value={result.summary.httpNodesMissingErrorHandling} />
        <SummaryMetric label="Credential IDs" value={result.summary.uniqueCredentialLeaks} />
        <SummaryMetric label="CRM writes" value={result.summary.crmWriteNodes} />
        <SummaryMetric label="Warnings" value={result.summary.parserWarnings} />
      </div>

      <div className="report-actions">
        <button type="button" onClick={onCopyReport}>
          <Copy size={17} aria-hidden="true" />
          <span>{copyLabel(reportCopyState, 'Copy report')}</span>
        </button>
        <button type="button" onClick={onCopyChecklist}>
          <Clipboard size={17} aria-hidden="true" />
          <span>{copyLabel(checklistCopyState, 'Copy checklist')}</span>
        </button>
        <button type="button" onClick={onDownloadReport}>
          <Download size={17} aria-hidden="true" />
          <span>Download .md</span>
        </button>
      </div>

      <FeedbackCta result={result} />

      <div className="filters">
        <Filter size={17} aria-hidden="true" />
        <select value={severityFilter} onChange={(event) => onSeverityChange(event.target.value as 'all' | Severity)}>
          <option value="all">All severities</option>
          {severityOrder.map((severity) => (
            <option key={severity} value={severity}>
              {titleCase(severity)}
            </option>
          ))}
        </select>
        <select value={categoryFilter} onChange={(event) => onCategoryChange(event.target.value)}>
          <option value="all">All categories</option>
          {categoryOptions.map((category) => (
            <option key={category} value={category}>
              {category}
            </option>
          ))}
        </select>
        {infoCount > 0 ? (
          <label className="info-toggle">
            <input
              type="checkbox"
              checked={showInfoFindings}
              onChange={(event) => onShowInfoChange(event.target.checked)}
            />
            <span>Show info ({infoCount})</span>
          </label>
        ) : null}
      </div>

      {hiddenInfoCount > 0 ? (
        <p className="filter-note">
          {hiddenInfoCount} info-level hygiene {pluralize(hiddenInfoCount, 'finding')} hidden by default.
        </p>
      ) : null}

      {result.parserWarnings.length > 0 ? (
        <details className="warning-details">
          <summary>
            <AlertTriangle size={18} aria-hidden="true" />
            <span>{result.parserWarnings.length} parser warning found. Scan continued with usable workflow data.</span>
          </summary>
          <ul>
            {result.parserWarnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </details>
      ) : null}

      <div className="finding-list">
        {visibleFindings.length === 0 ? (
          <div className="success-state">
            <CheckCircle2 size={28} aria-hidden="true" />
            <h3>No matching risks found</h3>
            <p>Current scanner rules did not flag findings for this filter.</p>
          </div>
        ) : (
          groupedFindings.map((group) => (
            <section key={group.severity} className={`finding-group ${group.severity}`}>
              <h3>
                {titleCase(group.severity)} <span>{group.findings.length}</span>
              </h3>
              {group.findings.map((finding) => (
                <article key={finding.id} className={`finding-card ${finding.severity}`}>
                  <div className="finding-topline">
                    <span className={`severity ${finding.severity}`}>{titleCase(finding.severity)}</span>
                    <span>{finding.category}</span>
                    {finding.affectedNodeCount && finding.affectedNodeCount > 1 ? (
                      <span>{finding.affectedNodeCount} affected nodes</span>
                    ) : null}
                  </div>
                  <h4>{finding.plainTitle}</h4>
                  <p className="node-line">{formatNodeLine(finding.nodeNames)}</p>
                  <p className="finding-meaning">{finding.plainMeaning}</p>
                  <dl>
                    <div>
                      <dt>Problem</dt>
                      <dd>{finding.problem}</dd>
                    </div>
                    <div>
                      <dt>Fix steps</dt>
                      <dd>
                        <ol>
                          {finding.fixSteps.map((step) => (
                            <li key={step}>{step}</li>
                          ))}
                        </ol>
                      </dd>
                    </div>
                  </dl>
                </article>
              ))}
            </section>
          ))
        )}
      </div>
    </div>
  )
}

function FeedbackCta({ result }: { result: ScanResult }) {
  const subject = encodeURIComponent(`n8n Workflow Linter feedback: ${result.workflowName}`)
  const body = encodeURIComponent(
    [
      'Please attach the exported markdown report from the app.',
      '',
      'Do not send raw workflow JSON unless it is fully sanitized.',
      '',
      'Feedback format:',
      '- Verdict shown:',
      '- Finding IDs that looked wrong:',
      '- Expected result:',
      '- Actual result:',
      '- Safe redacted workflow shape:',
    ].join('\n'),
  )

  return (
    <div className="feedback-cta">
      <div>
        <strong>Send safe beta feedback</strong>
        <p>Send the markdown report and a short note. Do not send raw workflow JSON.</p>
      </div>
      <a href={`mailto:${feedbackEmail}?subject=${subject}&body=${body}`}>
        <Mail size={17} aria-hidden="true" />
        <span>Email feedback</span>
      </a>
    </div>
  )
}

function SummaryMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="summary-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function formatNodeLine(nodeNames: string[]): string {
  if (nodeNames.length === 0) return 'Workflow level'
  const visibleNames = nodeNames.slice(0, 8)
  const hiddenCount = nodeNames.length - visibleNames.length
  return hiddenCount > 0 ? `${visibleNames.join(', ')} and ${hiddenCount} more` : visibleNames.join(', ')
}

function DocsBlock() {
  return (
    <section className="docs-block" aria-label="Scanner notes">
      <article>
        <h2>How to export JSON from n8n</h2>
        <ol>
          <li>Open the workflow in n8n.</li>
          <li>Use Download or Export from the workflow menu.</li>
          <li>Upload the exported .json file here.</li>
        </ol>
      </article>
      <article>
        <h2>Where your data goes</h2>
        <p>The file is parsed and scanned in your browser. This app does not add analytics, storage, or server uploads.</p>
      </article>
      <article>
        <h2>What this scanner checks</h2>
        <p>Webhook exposure, unsafe write paths, HubSpot dedupe gaps, HTTP timeout/retry/error handling, secrets, pinned data, disabled nodes, and naming hygiene.</p>
      </article>
      <article>
        <h2>What it does not guarantee</h2>
        <p>It cannot prove runtime behavior, credentials, API permissions, or business logic correctness. Treat the report as a pre-share reliability review.</p>
      </article>
    </section>
  )
}

function createRequestId(): string {
  return typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function normalizeScanError(error: unknown): ScanError {
  if (error instanceof ScannerInputError) {
    return {
      code: error.code,
      title: error.title,
      detail: error.detail,
    }
  }

  return {
    code: 'invalid_workflow',
    title: 'Workflow could not be scanned',
    detail: error instanceof Error ? error.message : 'An unexpected scanner error occurred.',
  }
}

function titleCase(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`
}

function copyLabel(state: CopyState, defaultLabel: string): string {
  if (state === 'copied') return 'Copied'
  if (state === 'failed') return 'Copy failed'
  return defaultLabel
}

function pluralize(count: number, singular: string): string {
  return count === 1 ? singular : `${singular}s`
}

async function writeClipboard(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value)
    return true
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = value
    textarea.setAttribute('readonly', 'true')
    textarea.style.position = 'fixed'
    textarea.style.top = '-9999px'
    document.body.append(textarea)
    textarea.select()

    try {
      return document.execCommand('copy')
    } catch {
      return false
    } finally {
      textarea.remove()
    }
  }
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80)
}

function byteSize(value: string): number {
  return new TextEncoder().encode(value).byteLength
}

export default App
