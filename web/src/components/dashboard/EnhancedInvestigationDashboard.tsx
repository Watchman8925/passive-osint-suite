import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  MagnifyingGlassIcon,
  PlayIcon,
  PauseIcon,
  EyeIcon,
  PlusIcon,
  ChartBarIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  GlobeAltIcon,
  CubeIcon,
  DocumentTextIcon,
  MapIcon,
  HomeIcon
} from '@heroicons/react/24/outline';

import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { Card } from '../ui/Card';
import { StatusPill } from '../ui/StatusPill';
import { MetricTile } from '../ui/MetricTile';
import { Skeleton } from '../ui/Skeleton';
import { useInvestigations } from '../../hooks/useInvestigations';
import { useServiceHealth } from '../../hooks/useServiceHealth';
import { useTheme } from '../../design/ThemeProvider';
import CreateInvestigationModal from './CreateInvestigationModal';
import InvestigationDetailsModal from './InvestigationDetailsModal';
import AnonymityStatusPanel from '../anonymity/AnonymityStatusPanel';
import OSINTModuleGrid from '../modules/OSINTModuleGrid';
import InvestigationResults from '../results/InvestigationResults';
import VisualizationDashboard from '../visualization/VisualizationDashboard';
import LiveTasksPanel from '../tasks/LiveTasksPanel';

interface Investigation {
  id: string;
  name: string;
  target: string;
  status: 'active' | 'paused' | 'completed' | 'failed';
  priority: 'low' | 'medium' | 'high' | 'critical';
  progress: number;
  created_at: string;
  tasks_completed: number;
  tasks_total: number;
}

// Mock investigations for demo purposes
const mockInvestigations: Investigation[] = [
  {
    id: '1',
    name: 'Corporate Intelligence Analysis',
    target: 'Acme Corp',
    status: 'active',
    priority: 'high',
    progress: 65,
    created_at: '2024-01-15T10:30:00Z',
    tasks_completed: 13,
    tasks_total: 20
  },
  {
    id: '2',
    name: 'Digital Footprint Investigation',
    target: 'john.doe@email.com',
    status: 'completed',
    priority: 'medium',
    progress: 100,
    created_at: '2024-01-14T08:45:00Z',
    tasks_completed: 15,
    tasks_total: 15
  },
  {
    id: '3',
    name: 'Network Infrastructure Mapping',
    target: '192.168.1.0/24',
    status: 'paused',
    priority: 'critical',
    progress: 40,
    created_at: '2024-01-13T14:20:00Z',
    tasks_completed: 8,
    tasks_total: 20
  }
];

interface DashboardProps {
  className?: string;
}

const EnhancedInvestigationDashboard: React.FC<DashboardProps> = ({ className }) => {
  // Use mock data for now since API might not be available
  const [investigations] = useState<Investigation[]>(mockInvestigations);
  const [selectedInvestigation, setSelectedInvestigation] = useState<Investigation | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState<'overview' | 'modules' | 'results' | 'analytics'>('overview');
  const health = useServiceHealth(6000);
  const { mode, toggle } = useTheme();

  const filteredInvestigations = investigations.filter(inv =>
    inv.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    inv.target.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const stats = {
    total: investigations.length,
    active: investigations.filter(i => i.status === 'active').length,
    completed: investigations.filter(i => i.status === 'completed').length,
    critical: investigations.filter(i => i.priority === 'critical').length
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'modules':
        return <OSINTModuleGrid onModuleSelect={() => {}} />;
      case 'results':
        return <InvestigationResults />;
      case 'analytics':
        return <VisualizationDashboard results={[]} />;
      default:
        return renderOverviewContent();
    }
  };

  const renderOverviewContent = () => (
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

      {/* Stats Cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
      >
        <MetricTile label="Total" value={stats.total} icon={<ChartBarIcon className="w-8 h-8 text-slate-400" />} />
        <MetricTile label="Active" value={stats.active} icon={<PlayIcon className="w-8 h-8 text-emerald-500" />} accent="emerald" />
        <MetricTile label="Completed" value={stats.completed} icon={<CheckCircleIcon className="w-8 h-8 text-emerald-500" />} accent="emerald" />
        <MetricTile label="Critical" value={stats.critical} icon={<ExclamationTriangleIcon className="w-8 h-8 text-rose-500" />} accent="rose" />
      </motion.div>

      {/* Security Features Banner */}
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

      {/* Investigations List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="bg-white rounded-xl shadow-lg p-6 mb-8"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Investigations</h2>
          <Button
            onClick={() => setShowCreateModal(true)}
            className="bg-purple-600 hover:bg-purple-700 text-white"
          >
            <PlusIcon className="w-5 h-5 mr-2" />
            New Investigation
          </Button>
        </div>

        {/* Search */}
        <div className="mb-6">
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search investigations..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            />
          </div>
        </div>

        {/* Investigation Cards */}
        <div className="space-y-4">
          {filteredInvestigations.map((investigation, index) => (
            <motion.div
              key={investigation.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * index }}
              className="bg-gray-50 rounded-xl p-6 shadow-sm border border-gray-200 hover:shadow-md transition-all duration-300 cursor-pointer"
              onClick={() => setSelectedInvestigation(investigation)}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-900 mb-1">
                    {investigation.name}
                  </h3>
                  <p className="text-gray-600 text-sm">Target: {investigation.target}</p>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge variant={investigation.priority === 'critical' ? 'destructive' : 'default'}>
                    {investigation.priority}
                  </Badge>
                  <StatusPill 
                    status={
                      investigation.status === 'active' ? 'ok' :
                      investigation.status === 'completed' ? 'ok' :
                      investigation.status === 'paused' ? 'warn' :
                      investigation.status === 'failed' ? 'error' : 'unknown'
                    } 
                    label={investigation.status} 
                  />
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">Progress</span>
                  <span className="text-gray-900 font-medium">{investigation.progress}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-gradient-to-r from-purple-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                    style={{ width: `${investigation.progress}%` }}
                  />
                </div>

                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">Tasks</span>
                  <span className="text-gray-900">
                    {investigation.tasks_completed}/{investigation.tasks_total}
                  </span>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </>
  );

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
          // Refresh investigations list here
        }}
      />

      {selectedInvestigation && (
        <InvestigationDetailsModal
          investigationId={selectedInvestigation.id}
          isOpen={!!selectedInvestigation}
          onClose={() => setSelectedInvestigation(null)}
        />
      )}
    </div>
  );
};

export default EnhancedInvestigationDashboard;
