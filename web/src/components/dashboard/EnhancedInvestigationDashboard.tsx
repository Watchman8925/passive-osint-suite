import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  MagnifyingGlassIcon,
  PlayIcon,
  PlusIcon,
  ChartBarIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  GlobeAltIcon,
  CubeIcon,
  DocumentTextIcon,
  HomeIcon
} from '@heroicons/react/24/outline';

import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { Card } from '../ui/Card';
import { StatusPill } from '../ui/StatusPill';
import { MetricTile } from '../ui/MetricTile';
import toast from 'react-hot-toast';
import { Skeleton } from '../ui/Skeleton';
import { useInvestigations } from '../../hooks/useInvestigations';
import { useServiceHealth } from '../../hooks/useServiceHealth';
import { useTheme } from '../../design/ThemeProvider';
import CreateInvestigationModal from './CreateInvestigationModal';
import InvestigationDetailsModal from './InvestigationDetailsModal';
import AnonymityStatusPanel from '../anonymity/AnonymityStatusPanel';
import OSINTModuleGrid, { OSINTModule } from '../modules/OSINTModuleGrid';
import InvestigationResults, { InvestigationResult } from '../results/InvestigationResults';
import VisualizationDashboard from '../visualization/VisualizationDashboard';
import LiveTasksPanel from '../tasks/LiveTasksPanel';
import { useSelectedInvestigation } from '../../contexts/SelectedInvestigationContext';
import { InvestigationRecord } from '../../hooks/useInvestigations';
import { osintAPI } from '../../services/osintAPI';

interface DashboardProps {
  className?: string;
}

type ModuleExecutionState = {
  status: 'idle' | 'running' | 'success' | 'error';
  module: OSINTModule | null;
  error: string | null;
  completedAt: string | null;
};

const normalizeLabel = (value?: string | null) =>
  value ? value.replace(/[_-]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Unknown';

const toStatusKey = (value?: string | null) => value?.toLowerCase().replace(/\s+/g, '_') ?? '';

const mapStatusToPill = (status?: string | null): 'ok' | 'warn' | 'error' | 'unknown' => {
  const normalized = toStatusKey(status);
  if (['completed', 'done', 'success', 'finished'].includes(normalized)) return 'ok';
  if (['active', 'running', 'processing', 'in_progress'].includes(normalized)) return 'ok';
  if (['paused', 'created', 'planning', 'queued'].includes(normalized)) return 'warn';
  if (['failed', 'error', 'stopped', 'cancelled'].includes(normalized)) return 'error';
  return 'unknown';
};

const computeProgressPercent = (investigation: InvestigationRecord): number | null => {
  const raw = typeof investigation.progress === 'number'
    ? investigation.progress
    : typeof (investigation as any)?.overall_progress === 'number'
      ? (investigation as any).overall_progress
      : undefined;

  if (raw === undefined || raw === null || Number.isNaN(raw)) return null;
  const scaled = raw <= 1 ? raw * 100 : raw;
  return Math.max(0, Math.min(100, Math.round(scaled)));
};

const getTaskSummary = (investigation: InvestigationRecord) => {
  const completed = (investigation as any)?.tasks_completed
    ?? (investigation as any)?.completed_tasks
    ?? (investigation as any)?.stats?.completed_tasks
    ?? null;
  const total = (investigation as any)?.tasks_total
    ?? (investigation as any)?.total_tasks
    ?? (investigation as any)?.stats?.total_tasks
    ?? null;

  if (typeof completed === 'number' && typeof total === 'number') {
    return { completed, total };
  }
  return { completed: null, total: null };
};

const EnhancedInvestigationDashboard: React.FC<DashboardProps> = ({ className }) => {
  const { data, loading, error, refresh } = useInvestigations();
  const investigations = data ?? [];
  const { selectedId, setSelectedId } = useSelectedInvestigation();
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState<'overview' | 'modules' | 'results' | 'analytics'>('overview');
  const [selectedModule, setSelectedModule] = useState<OSINTModule | null>(null);
  const [moduleExecutionState, setModuleExecutionState] = useState<ModuleExecutionState>({
    status: 'idle',
    module: null,
    error: null,
    completedAt: null
  });
  const [resultsRefreshToken, setResultsRefreshToken] = useState(0);
  const [latestResults, setLatestResults] = useState<InvestigationResult[]>([]);
  const health = useServiceHealth(6000);
  const { mode, toggle } = useTheme();

  const selectedInvestigation = useMemo(
    () => investigations.find(inv => inv.investigation_id === selectedId) ?? null,
    [investigations, selectedId]
  );

  const filteredInvestigations = useMemo(() => {
    if (!searchTerm) return investigations;
    const term = searchTerm.toLowerCase();
    return investigations.filter(inv => {
      const nameMatch = inv.name?.toLowerCase().includes(term);
      const targetMatch = inv.targets?.some(target => target.toLowerCase().includes(term));
      const statusMatch = inv.status?.toLowerCase().includes(term);
      return Boolean(nameMatch || targetMatch || statusMatch);
    });
  }, [investigations, searchTerm]);

  const stats = useMemo(() => {
    const activeStatuses = new Set(['active', 'running', 'in_progress', 'processing']);
    const completedStatuses = new Set(['completed', 'done', 'finished', 'success']);
    return {
      total: investigations.length,
      active: investigations.filter(inv => activeStatuses.has((inv.status ?? '').toLowerCase())).length,
      completed: investigations.filter(inv => completedStatuses.has((inv.status ?? '').toLowerCase())).length,
      critical: investigations.filter(inv => (inv.priority ?? '').toString().toLowerCase() === 'critical').length
    };
  }, [investigations]);

  useEffect(() => {
    if (!selectedInvestigation) {
      setDetailsOpen(false);
      setSelectedModule(null);
      setModuleExecutionState({ status: 'idle', module: null, error: null, completedAt: null });
    }
  }, [selectedInvestigation]);

  const handleInvestigationClick = useCallback((investigation: InvestigationRecord) => {
    setSelectedId(investigation.investigation_id);
    setDetailsOpen(true);
  }, [setSelectedId]);

  const handleModuleSelect = useCallback(async (module: OSINTModule) => {
    setSelectedModule(module);
    if (!selectedInvestigation) {
      toast.error('Select an investigation before running a module.');
      return;
    }
    if (!selectedInvestigation.targets || selectedInvestigation.targets.length === 0) {
      toast.error('Selected investigation does not have any targets.');
      return;
    }

    setModuleExecutionState({ status: 'running', module, error: null, completedAt: null });
    try {
      await osintAPI.executeModule(module.id, {
        investigation_id: selectedInvestigation.investigation_id,
        investigation_name: selectedInvestigation.name,
        targets: selectedInvestigation.targets,
        priority: selectedInvestigation.priority,
        investigation_type: selectedInvestigation.investigation_type,
      });
      setModuleExecutionState({
        status: 'success',
        module,
        error: null,
        completedAt: new Date().toISOString(),
      });
      setResultsRefreshToken((token) => token + 1);
      refresh();
      setActiveTab('results');
    } catch (err: any) {
      const message = err?.response?.data?.message || err?.message || 'Module execution failed';
      setModuleExecutionState({ status: 'error', module, error: message, completedAt: null });
    }
  }, [refresh, selectedInvestigation]);

  const renderModuleTab = () => {
    const pillStatus: 'ok' | 'warn' | 'error' | 'unknown' =
      moduleExecutionState.status === 'success'
        ? 'ok'
        : moduleExecutionState.status === 'running'
          ? 'warn'
          : moduleExecutionState.status === 'error'
            ? 'error'
            : 'unknown';

    let statusMessage: string | null = null;
    if (moduleExecutionState.status === 'running') {
      statusMessage = `Executing ${moduleExecutionState.module?.name ?? 'module'}...`;
    } else if (moduleExecutionState.status === 'success') {
      statusMessage = 'Module execution completed. Results will refresh automatically.';
    } else if (moduleExecutionState.status === 'error') {
      statusMessage = moduleExecutionState.error ?? 'Module execution failed.';
    }

    return (
      <div className="space-y-6">
        {!selectedInvestigation && (
          <Card title="No investigation selected">
            <p className="text-sm text-gray-600">
              Choose an investigation from the overview tab to execute OSINT modules against its configured targets.
            </p>
          </Card>
        )}

        {moduleExecutionState.status !== 'idle' && (
          <Card>
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-800">
                  {moduleExecutionState.module?.name ?? 'Module Execution'}
                </p>
                {statusMessage && <p className="text-xs text-gray-500 mt-1">{statusMessage}</p>}
                {moduleExecutionState.completedAt && (
                  <p className="text-xs text-gray-400 mt-1">
                    Last run {new Date(moduleExecutionState.completedAt).toLocaleTimeString()}
                  </p>
                )}
              </div>
              <StatusPill
                status={pillStatus}
                label={normalizeLabel(moduleExecutionState.status)}
              />
            </div>
          </Card>
        )}

        <OSINTModuleGrid onModuleSelect={handleModuleSelect} selectedModule={selectedModule} />
      </div>
    );
  };

  const renderOverviewContent = () => {
    const initialLoading = loading && investigations.length === 0;

    return (
      <>
        {health.errors.length > 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mb-6"
          >
            <Card title={`Service Warnings (${health.errors.length})`}>
              <div className="max-h-40 overflow-auto text-xs font-mono space-y-1 pr-1">
                {health.errors.slice(-10).reverse().map((e, i) => (
                  <div key={i} className="text-amber-600 dark:text-amber-400">{e}</div>
                ))}
              </div>
            </Card>
          </motion.div>
        )}

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
        >
          {initialLoading ? (
            <>
              {Array.from({ length: 4 }).map((_, index) => (
                <div key={index} className="p-5 rounded-xl border border-gray-200 bg-white/70">
                  <Skeleton className="h-4 w-20 mb-4" />
                  <Skeleton className="h-8 w-24" />
                </div>
              ))}
            </>
          ) : (
            <>
              <MetricTile label="Total" value={stats.total} icon={<ChartBarIcon className="w-8 h-8 text-slate-400" />} />
              <MetricTile label="Active" value={stats.active} icon={<PlayIcon className="w-8 h-8 text-emerald-500" />} accent="emerald" />
              <MetricTile label="Completed" value={stats.completed} icon={<CheckCircleIcon className="w-8 h-8 text-emerald-500" />} accent="emerald" />
              <MetricTile label="Critical" value={stats.critical} icon={<ExclamationTriangleIcon className="w-8 h-8 text-rose-500" />} accent="rose" />
            </>
          )}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="bg-gradient-to-r from-purple-600 to-blue-600 rounded-xl p-6 text-white mb-8"
        >
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xl font-bold mb-2">🛡️ Advanced Security Active</h3>
              <p className="text-purple-100">Tor routing, DNS-over-HTTPS, and query obfuscation enabled</p>
            </div>
            <div className="flex space-x-4">
              <div className="flex items-center space-x-2">
                <LockClosedIcon className="w-5 h-5" />
                <span className="text-sm">Tor Active</span>
              </div>
              <div className="flex items-center space-x-2">
                <ShieldCheckIcon className="w-5 h-5" />
                <span className="text-sm">Encrypted</span>
              </div>
              <div className="flex items-center space-x-2">
                <GlobeAltIcon className="w-5 h-5" />
                <span className="text-sm">Anonymous</span>
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-white rounded-xl shadow-lg p-6 mb-8"
        >
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <h2 className="text-2xl font-bold text-gray-900">Investigations</h2>
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                onClick={refresh}
                disabled={loading}
              >
                Refresh
              </Button>
              <Button
                onClick={() => setShowCreateModal(true)}
                className="bg-purple-600 hover:bg-purple-700 text-white"
              >
                <PlusIcon className="w-5 h-5 mr-2" />
                New Investigation
              </Button>
            </div>
          </div>

          <div className="mb-6">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search investigations..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                disabled={loading && investigations.length === 0}
                className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              />
            </div>
          </div>

          {error ? (
            <Card title="Unable to load investigations" className="bg-rose-50 border-rose-200" padded>
              <p className="text-sm text-rose-700" data-testid="investigations-error">{error}</p>
              <Button className="mt-4" variant="outline" onClick={refresh}>Retry</Button>
            </Card>
          ) : (
            <div className="space-y-4">
              {initialLoading ? (
                <div className="space-y-4" data-testid="investigation-list-loading">
                  {Array.from({ length: 3 }).map((_, index) => (
                    <div key={index} className="bg-gray-50 rounded-xl p-6 border border-gray-200">
                      <Skeleton className="h-5 w-48 mb-3" />
                      <Skeleton className="h-3 w-32 mb-4" />
                      <Skeleton className="h-2 w-full" />
                    </div>
                  ))}
                </div>
              ) : filteredInvestigations.length > 0 ? (
                filteredInvestigations.map((investigation, index) => {
                  const isSelected = selectedInvestigation?.investigation_id === investigation.investigation_id;
                  const targets = investigation.targets?.length
                    ? investigation.targets.slice(0, 2).join(', ')
                    : 'No targets defined';
                  const progressPercent = computeProgressPercent(investigation);
                  const { completed, total } = getTaskSummary(investigation);

                  return (
                    <motion.div
                      key={investigation.investigation_id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.05 * index }}
                      className={`bg-gray-50 rounded-xl p-6 shadow-sm border transition-all duration-300 cursor-pointer ${
                        isSelected ? 'border-purple-400 ring-2 ring-purple-200 bg-white' : 'border-gray-200 hover:shadow-md'
                      }`}
                      onClick={() => handleInvestigationClick(investigation)}
                    >
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1">
                          <h3 className="text-lg font-semibold text-gray-900 mb-1">
                            {investigation.name}
                          </h3>
                          <p className="text-gray-600 text-sm">Targets: {targets}</p>
                          {investigation.created_at && (
                            <p className="text-xs text-gray-400 mt-1">
                              Created {new Date(investigation.created_at).toLocaleString()}
                            </p>
                          )}
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant={normalizeLabel(investigation.priority).toLowerCase() === 'critical' ? 'destructive' : 'secondary'}>
                            {normalizeLabel(investigation.priority)}
                          </Badge>
                          <StatusPill
                            status={mapStatusToPill(investigation.status)}
                            label={normalizeLabel(investigation.status)}
                          />
                        </div>
                      </div>

                      <div className="space-y-3">
                        {progressPercent !== null ? (
                          <>
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-gray-600">Progress</span>
                              <span className="text-gray-900 font-medium">{progressPercent}%</span>
                            </div>
                            <div className="w-full bg-gray-200 rounded-full h-2">
                              <div
                                className="bg-gradient-to-r from-purple-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                                style={{ width: `${progressPercent}%` }}
                              />
                            </div>
                          </>
                        ) : (
                          <p className="text-sm text-gray-500">Progress data unavailable</p>
                        )}

                        {completed !== null && total !== null && (
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-gray-600">Tasks</span>
                            <span className="text-gray-900">
                              {completed}/{total}
                            </span>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  );
                })
              ) : (
                <div className="text-center py-12" data-testid="investigation-list-empty">
                  <div className="text-5xl mb-4">🗂️</div>
                  <h3 className="text-xl font-semibold text-gray-700 mb-2">No investigations found</h3>
                  <p className="text-gray-500">
                    {searchTerm
                      ? 'Try adjusting your search to find investigations.'
                      : 'Create a new investigation to begin collecting intelligence.'}
                  </p>
                </div>
              )}
            </div>
          )}
        </motion.div>
      </>
    );
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'modules':
        return renderModuleTab();
      case 'results':
        return (
          <InvestigationResults
            investigationId={selectedInvestigation?.investigation_id}
            refreshToken={resultsRefreshToken}
            onResultsUpdate={setLatestResults}
          />
        );
      case 'analytics':
        return <VisualizationDashboard results={latestResults} />;
      default:
        return renderOverviewContent();
    }
  };

  return (
    <div className={`min-h-screen bg-gray-50 ${className || ''}`}>
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white shadow-sm border-b border-gray-200"
      >
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <CubeIcon className="w-8 h-8 text-purple-600" />
                <h1 className="text-2xl font-bold text-gray-900">OSINT Suite</h1>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {/* Navigation Tabs */}
              <nav className="flex space-x-1">
                {[
                  { id: 'overview', label: 'Overview', icon: HomeIcon },
                  { id: 'modules', label: 'Modules', icon: CubeIcon },
                  { id: 'results', label: 'Results', icon: DocumentTextIcon },
                  { id: 'analytics', label: 'Analytics', icon: ChartBarIcon }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors ${
                      activeTab === tab.id
                        ? 'bg-purple-100 text-purple-700'
                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                    }`}
                  >
                    <tab.icon className="w-5 h-5" />
                    <span>{tab.label}</span>
                  </button>
                ))}
              </nav>

              {/* Theme Toggle */}
              <button
                onClick={toggle}
                className="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 transition-colors"
              >
                {mode === 'dark' ? '☀️' : '🌙'}
              </button>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-3">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.3 }}
              >
                {renderTabContent()}
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            <AnonymityStatusPanel />
            <LiveTasksPanel />
          </div>
        </div>
      </div>

      {/* Modals */}
      <CreateInvestigationModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSuccess={() => {
          setShowCreateModal(false);
          refresh();
        }}
      />

      {selectedInvestigation && (
        <InvestigationDetailsModal
          investigationId={selectedInvestigation.investigation_id}
          isOpen={detailsOpen}
          onClose={() => setDetailsOpen(false)}
        />
      )}
    </div>
  );
};

export default EnhancedInvestigationDashboard;
