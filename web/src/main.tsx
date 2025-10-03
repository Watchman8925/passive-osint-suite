import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import ModernApp from './ModernApp'
import { SelectedInvestigationProvider } from './contexts/SelectedInvestigationContext'
import ErrorBoundary from './components/ErrorBoundary'
import './globals.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <SelectedInvestigationProvider>
        <ModernApp />
      </SelectedInvestigationProvider>
    </ErrorBoundary>
  </StrictMode>,
)