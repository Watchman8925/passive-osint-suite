import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import ModernApp from './ModernApp'
import { SelectedInvestigationProvider } from './contexts/SelectedInvestigationContext'
import './globals.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SelectedInvestigationProvider>
      <ModernApp />
    </SelectedInvestigationProvider>
  </StrictMode>,
)