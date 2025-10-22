import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import ModernApp from './ModernApp'
import { SelectedInvestigationProvider } from './contexts/SelectedInvestigationContext'
import { AuthProvider } from './contexts/AuthContext'
import ErrorBoundary from './components/ErrorBoundary'
import './globals.css'
import { Toaster } from 'react-hot-toast'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Toaster position="top-right" toastOptions={{ duration: 4000 }} />
    <ErrorBoundary>
      <AuthProvider>
        <SelectedInvestigationProvider>
          <div className="theme-cyberpunk cyberpunk-bg min-h-screen">
            <ModernApp />
          </div>
        </SelectedInvestigationProvider>
      </AuthProvider>
    </ErrorBoundary>
  </StrictMode>,
)