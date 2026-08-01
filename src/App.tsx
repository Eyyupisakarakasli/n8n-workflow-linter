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
  Play,
  ShieldCheck,
  Upload,
  XCircle,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import { buildFixChecklist, buildMarkdownReport } from './core/report/markdown'
import type { ScanError, ScanResult } from './core/scan'
import type { Severity } from './core/rules/types'
import { demoWorkflows } from './data/demoWorkflows'
import type { ScanWorkerRequest, ScanWorkerResponse } from './worker/scanner.worker'

const maxFileBytes = 2 * 1024 * 1024
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

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
  const [reportCopyState, setReportCopyState] = useState<CopyState>('idle')
  const [checklistCopyState, setChecklistCopyState] = useState<CopyState>('idle')
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
      return matchesSeverity && matchesCategory
    })
  }, [categoryFilter, scanResult, severityFilter])

  const categoryOptions = useMemo(() => {
    if (!scanResult) return []
    return [...new Set(scanResult.findings.map((finding) => finding.category))].sort()
  }, [scanResult])

  function runScan(input = rawInput, label = sourceLabel) {
    workerRef.current?.terminate()
    const worker = new Worker(new URL('./worker/scanner.worker.ts', import.meta.url), { type: 'module' })
    const requestId = createRequestId()
    workerRef.current = worker

    setStatus('scanning')
    setScanError(null)
    setReportCopyState('idle')
    setChecklistCopyState('idle')

    worker.onmessage = (event: MessageEvent<ScanWorkerResponse>) => {
      if (event.data.requestId !== requestId) return

      if (event.data.ok) {
        setScanResult(event.data.result)
        setStatus('ready')
      } else {
        setScanResult(null)
        setScanError(event.data.error)
        setStatus('error')
      }

      worker.terminate()
      workerRef.current = null
    }

    worker.onerror = () => {
      setScanResult(null)
      setScanError({
        code: 'invalid_workflow',
        title: 'Scanner worker failed',
        detail: 'The workflow could not be scanned in the browser worker.',
      })
      setStatus('error')
      worker.terminate()
      workerRef.current = null
    }

    worker.postMessage({ requestId, sourceLabel: label, input } satisfies ScanWorkerRequest)
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
      setStatus('error')
      setScanError({
        code: 'invalid_workflow',
        title: 'Workflow file is too large',
        detail: 'The current public beta accepts workflow JSON files up to 2 MB.',
      })
      return
    }

    const text = await file.text()
    setRawInput(text)
    setSourceLabel(file.name)
    setSelectedDemoId('')
    runScan(text, file.name)
  }

  function loadDemo(demoId: string) {
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
              <p>Upload, paste, or inspect a demo export.</p>
            </div>
            <FileJson size={22} aria-hidden="true" />
          </div>

          <label className="dropzone">
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
            <select
              id="demo-workflow"
              value={selectedDemoId}
              onChange={(event) => loadDemo(event.target.value)}
            >
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
            onChange={(event) => {
              setRawInput(event.target.value)
              setSourceLabel('Pasted workflow')
              setSelectedDemoId('')
              setStatus('idle')
              setScanResult(null)
              setScanError(null)
            }}
            spellCheck={false}
          />

          <button className="primary-action" type="button" onClick={() => runScan()} disabled={status === 'scanning'}>
            {status === 'scanning' ? <Loader2 className="spin" size={18} aria-hidden="true" /> : <Play size={18} aria-hidden="true" />}
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
              reportCopyState={reportCopyState}
              checklistCopyState={checklistCopyState}
              onSeverityChange={setSeverityFilter}
              onCategoryChange={setCategoryFilter}
              onCopyReport={() => void copyText(buildMarkdownReport(scanResult), 'report')}
              onCopyChecklist={() => void copyText(buildFixChecklist(scanResult), 'checklist')}
              onDownloadReport={() => downloadReport(scanResult)}
            />
          ) : null}
        </section>
      </section>
    </main>
  )
}

function EmptyState() {
  return (
    <div className="empty-state">
      <FileText size={34} aria-hidden="true" />
      <h2>Ready to scan</h2>
      <p>Choose a demo or add a workflow JSON export.</p>
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
  reportCopyState: CopyState
  checklistCopyState: CopyState
  onSeverityChange: (severity: 'all' | Severity) => void
  onCategoryChange: (category: string) => void
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
  reportCopyState,
  checklistCopyState,
  onSeverityChange,
  onCategoryChange,
  onCopyReport,
  onCopyChecklist,
  onDownloadReport,
}: ReportViewProps) {
  const highCount = result.findings.filter(
    (finding) => finding.severity === 'critical' || finding.severity === 'high',
  ).length

  return (
    <div className="report-stack">
      <div className="report-header">
        <div>
          <p className="eyebrow">{result.sourceLabel}</p>
          <h2>{result.workflowName}</h2>
        </div>
        <div className={highCount > 0 ? 'risk-pill high' : 'risk-pill clean'}>
          {highCount > 0 ? <AlertTriangle size={18} aria-hidden="true" /> : <CheckCircle2 size={18} aria-hidden="true" />}
          <span>{highCount > 0 ? `${highCount} high-risk` : 'No high-risk findings'}</span>
        </div>
      </div>

      <div className="summary-grid">
        <SummaryMetric label="Nodes" value={result.summary.totalNodes} />
        <SummaryMetric label="Connections" value={result.summary.totalEdges} />
        <SummaryMetric label="Triggers" value={result.summary.triggerNodes} />
        <SummaryMetric label="HTTP" value={result.summary.httpNodes} />
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
      </div>

      {result.parserWarnings.length > 0 ? (
        <div className="warning-strip">
          <AlertTriangle size={18} aria-hidden="true" />
          <span>{result.parserWarnings.length} parser warning found. Scan continued with the usable workflow data.</span>
        </div>
      ) : null}

      <div className="finding-list">
        {visibleFindings.length === 0 ? (
          <div className="success-state">
            <CheckCircle2 size={28} aria-hidden="true" />
            <h3>No matching risks found</h3>
            <p>Current scanner rules did not flag findings for this filter.</p>
          </div>
        ) : (
          visibleFindings.map((finding) => (
            <article key={finding.id} className={`finding-card ${finding.severity}`}>
              <div className="finding-topline">
                <span className={`severity ${finding.severity}`}>{titleCase(finding.severity)}</span>
                <span>{finding.category}</span>
                <span>{titleCase(finding.confidence)} confidence</span>
              </div>
              <h3>{finding.title}</h3>
              <p className="node-line">{finding.nodeNames.join(', ')}</p>
              <dl>
                <div>
                  <dt>Problem</dt>
                  <dd>{finding.problem}</dd>
                </div>
                <div>
                  <dt>Why it matters</dt>
                  <dd>{finding.whyItMatters}</dd>
                </div>
                <div>
                  <dt>Suggested fix</dt>
                  <dd>{finding.suggestedFix}</dd>
                </div>
              </dl>
            </article>
          ))
        )}
      </div>
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

function createRequestId(): string {
  return typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function titleCase(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`
}

function copyLabel(state: CopyState, defaultLabel: string): string {
  if (state === 'copied') return 'Copied'
  if (state === 'failed') return 'Copy failed'
  return defaultLabel
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

export default App
