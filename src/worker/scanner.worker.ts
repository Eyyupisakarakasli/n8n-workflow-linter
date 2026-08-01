import { ScannerInputError, scanWorkflowInput, type ScanError, type ScanResult } from '../core/scan'

export interface ScanWorkerRequest {
  requestId: string
  sourceLabel: string
  input: string
}

export type ScanWorkerResponse =
  | {
      requestId: string
      ok: true
      result: ScanResult
    }
  | {
      requestId: string
      ok: false
      error: ScanError
    }

function normalizeError(error: unknown): ScanError {
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

self.onmessage = (event: MessageEvent<ScanWorkerRequest>) => {
  const { requestId, sourceLabel, input } = event.data

  try {
    const result = scanWorkflowInput(input, sourceLabel)
    self.postMessage({ requestId, ok: true, result } satisfies ScanWorkerResponse)
  } catch (error) {
    self.postMessage({ requestId, ok: false, error: normalizeError(error) } satisfies ScanWorkerResponse)
  }
}
