import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import ModernApp from './ModernApp'
import { SelectedInvestigationProvider } from './contexts/SelectedInvestigationContext'
import ErrorBoundary from './components/ErrorBoundary'
import './globals.css'
import { Toaster } from 'react-hot-toast'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Toaster position="top-right" toastOptions={{ duration: 4000 }} />
    <ErrorBoundary>
      <SelectedInvestigationProvider>
        <ModernApp />
      </SelectedInvestigationProvider>
    </ErrorBoundary>
  </StrictMode>,
)