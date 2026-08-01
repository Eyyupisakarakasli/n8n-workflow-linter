import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

interface ErrorBoundaryProps {
  children: ReactNode
}

interface ErrorBoundaryState {
  error: Error | null
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Application render failed', error, info)
  }

  render() {
    if (!this.state.error) return this.props.children

    return (
      <main className="app-shell">
        <section className="fatal-error" role="alert">
          <AlertTriangle size={34} aria-hidden="true" />
          <h1>Scanner could not render</h1>
          <p>Refresh the page and try the workflow JSON again. The file was not uploaded or stored.</p>
        </section>
      </main>
    )
  }
}
