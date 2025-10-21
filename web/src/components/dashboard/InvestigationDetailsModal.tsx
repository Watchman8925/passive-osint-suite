import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  XMarkIcon,
  PlayIcon,
  PauseIcon,
  ChartBarIcon,
  DocumentTextIcon,
  ChatBubbleLeftRightIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ArchiveBoxArrowDownIcon
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

import { Investigation, InvestigationProgress } from '../../types/investigation';
import { investigationApi, aiApi } from '../../services/api';
import { CapabilityCatalog } from '../CapabilityCatalog';
import { PlanViewer } from '../PlanViewer';
import { ProvenancePanel } from '../ProvenancePanel';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { ProgressBar } from '../ui/ProgressBar';
import { useInvestigationWebSocket } from '../../hooks/useWebSocket';

interface InvestigationDetailsModalProps {
  investigationId: string;
  isOpen: boolean;
  onClose: () => void;
}

export default function InvestigationDetailsModal({ 
  investigationId, 
  isOpen, 
  onClose 
}: InvestigationDetailsModalProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'tasks' | 'results' | 'ai' | 'reports' | 'capabilities' | 'plan' | 'provenance'>('overview');
  const queryClient = useQueryClient();
  
  // Fetch investigation details
  const { data: investigation, isLoading: loadingInvestigation } = useQuery({
    queryKey: ['investigation', investigationId],
    queryFn: () => investigationApi.getInvestigation(investigationId),
    enabled: isOpen && !!investigationId
  });

  // Fetch progress for active investigations
  const { data: progress } = useQuery({
    queryKey: ['investigation-progress', investigationId],
    queryFn: () => investigationApi.getInvestigationProgress(investigationId),
    enabled: isOpen && !!investigationId && investigation?.status === 'active',
    refetchInterval: 5000
  });

  const archiveMutation = useMutation({
    mutationFn: investigationApi.archiveInvestigation,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['investigations'] });
      queryClient.invalidateQueries({ queryKey: ['investigation', investigationId] });
      queryClient.invalidateQueries({ queryKey: ['investigation-progress', investigationId] });
      toast.success(data?.message ?? 'Investigation archived successfully');
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail ?? error?.message ?? 'Unknown error';
      toast.error(`Failed to archive investigation: ${detail}`);
    }
  });

  // WebSocket for real-time updates
  const { subscribeToInvestigation, unsubscribeFromInvestigation } = useInvestigationWebSocket();

  useEffect(() => {
    if (isOpen && investigationId) {
      subscribeToInvestigation(investigationId);
      return () => unsubscribeFromInvestigation(investigationId);
    }
  }, [isOpen, investigationId, subscribeToInvestigation, unsubscribeFromInvestigation]);

  if (!isOpen) return null;

  if (loadingInvestigation) {
    return (
      <Modal isOpen={isOpen} onClose={onClose} size="xl">
        <div className="p-6">
          <div className="animate-pulse space-y-4">
            <div className="h-8 bg-gray-200 rounded w-1/3"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
            <div className="h-64 bg-gray-200 rounded"></div>
          </div>
        </div>
      </Modal>
    );
  }

  if (!investigation) {
    return (
      <Modal isOpen={isOpen} onClose={onClose} size="xl">
        <div className="p-6">
          <div className="text-center">
            <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
            <p className="text-gray-600">Investigation not found</p>
            <Button onClick={onClose} className="mt-4">Close</Button>
          </div>
        </div>
      </Modal>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: ChartBarIcon },
    { id: 'tasks', label: 'Tasks', icon: ClockIcon },
    { id: 'results', label: 'Results', icon: DocumentTextIcon },
    { id: 'capabilities', label: 'Capabilities', icon: ChartBarIcon },
    { id: 'plan', label: 'Plan', icon: ClockIcon },
    { id: 'provenance', label: 'Provenance', icon: DocumentTextIcon },
    { id: 'ai', label: 'AI Analysis', icon: ChatBubbleLeftRightIcon },
    { id: 'reports', label: 'Reports', icon: DocumentTextIcon }
  ];

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="xl">
      <div className="flex flex-col h-[80vh]">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">{investigation.name}</h2>
            <p className="text-sm text-gray-600 mt-1">{investigation.description}</p>
          </div>
          <div className="flex items-center space-x-3">
            <Badge className={getStatusColor(investigation.status)}>
              {investigation.status}
            </Badge>
            {investigation.status !== 'archived' && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => archiveMutation.mutate(investigationId)}
                loading={archiveMutation.isPending}
                className="flex items-center space-x-1"
              >
                <ArchiveBoxArrowDownIcon className="h-4 w-4" />
                <span>{archiveMutation.isPending ? 'Archiving...' : 'Archive'}</span>
              </Button>
            )}
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>
        </div>

        {/* Progress Bar for Active Investigations */}
        {investigation.status === 'active' && progress && (
          <div className="px-6 py-3 bg-blue-50 border-b border-blue-200">
            <div className="flex items-center justify-between text-sm text-blue-800 mb-2">
              <span>Investigation Progress: {progress.completed_tasks}/{progress.total_tasks} tasks</span>
              <span>{Math.round(progress.overall_progress * 100)}%</span>
            </div>
            <ProgressBar 
              progress={progress.overall_progress * 100} 
              color="blue"
              className="h-2"
            />
          </div>
        )}

        {/* Tabs */}
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`
                    flex items-center py-4 px-1 border-b-2 font-medium text-sm
                    ${activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                    }
                  `}
                >
                  <Icon className="h-4 w-4 mr-2" />
                  {tab.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'overview' && (
            <InvestigationOverview investigation={investigation} progress={progress} />
          )}
          {activeTab === 'tasks' && (
            <TasksView investigation={investigation} progress={progress} />
          )}
          {activeTab === 'results' && (
            <ResultsView investigation={investigation} />
          )}
          {activeTab === 'capabilities' && (
            <div className="space-y-4">
              <CapabilityCatalog />
            </div>
          )}
          {activeTab === 'plan' && (
            <div className="space-y-4">
              <PlanViewer investigationId={investigationId} />
            </div>
          )}
          {activeTab === 'provenance' && (
            <div className="space-y-4">
              <ProvenancePanel investigationId={investigationId} />
            </div>
          )}
          {activeTab === 'ai' && (
            <AIAnalysisView investigationId={investigationId} />
          )}
          {activeTab === 'reports' && (
            <ReportsView investigationId={investigationId} />
          )}
        </div>
      </div>
    </Modal>
  );
}

// Helper function for status colors
function getStatusColor(status: string): string {
  const colors = {
    created: 'bg-gray-100 text-gray-800',
    planning: 'bg-blue-100 text-blue-800',
    active: 'bg-green-100 text-green-800',
    paused: 'bg-yellow-100 text-yellow-800',
    completed: 'bg-emerald-100 text-emerald-800',
    failed: 'bg-red-100 text-red-800',
    archived: 'bg-gray-100 text-gray-600'
  };
  return colors[status] || 'bg-gray-100 text-gray-800';
}

// Sub-components for different tabs
function InvestigationOverview({ investigation, progress }: { investigation: Investigation; progress?: InvestigationProgress }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-3">Investigation Details</h3>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-gray-600">Type:</dt>
              <dd className="text-gray-900">{investigation.investigation_type}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-600">Priority:</dt>
              <dd className="text-gray-900">{investigation.priority}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-600">Analyst:</dt>
              <dd className="text-gray-900">{investigation.analyst}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-gray-600">Created:</dt>
              <dd className="text-gray-900">{new Date(investigation.created_at).toLocaleDateString()}</dd>
            </div>
          </dl>
        </div>

        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-3">Targets</h3>
          <div className="space-y-1">
            {investigation.targets.map((target, index) => (
              <Badge key={index} variant="secondary" className="mr-1 mb-1">
                {target}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      {progress && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-3">Progress Summary</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <div>
              <div className="text-2xl font-bold text-blue-600">{progress.total_tasks}</div>
              <div className="text-sm text-gray-600">Total Tasks</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-green-600">{progress.completed_tasks}</div>
              <div className="text-sm text-gray-600">Completed</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-yellow-600">{progress.running_tasks}</div>
              <div className="text-sm text-gray-600">Running</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-red-600">{progress.failed_tasks}</div>
              <div className="text-sm text-gray-600">Failed</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function TasksView({ investigation, progress }: { investigation: Investigation; progress?: InvestigationProgress }) {
  const tasks = Object.values(investigation.tasks || {});

  return (
    <div className="space-y-4">
      <h3 className="font-medium text-gray-900">Investigation Tasks</h3>
      
      {tasks.length === 0 ? (
        <div className="text-center py-8">
          <ClockIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600">No tasks configured for this investigation</p>
        </div>
      ) : (
        <div className="space-y-3">
          {tasks.map((task) => {
            const taskProgress = progress?.task_progress[task.id];
            return (
              <div key={task.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-gray-900">{task.name}</h4>
                  <Badge className={getStatusColor(task.status.toString())}>
                    {task.status}
                  </Badge>
                </div>
                
                {taskProgress && (
                  <ProgressBar 
                    progress={taskProgress.progress * 100}
                    showLabel
                    className="mb-2"
                  />
                )}
                
                <div className="text-sm text-gray-600">
                  <p>Type: {task.task_type}</p>
                  <p>Targets: {task.targets.join(', ')}</p>
                  {task.error && (
                    <p className="text-red-600 mt-1">Error: {task.error}</p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ResultsView({ investigation }: { investigation: Investigation }) {
  const results = Object.entries(investigation.results || {});

  return (
    <div className="space-y-4">
      <h3 className="font-medium text-gray-900">Investigation Results</h3>
      
      {results.length === 0 ? (
        <div className="text-center py-8">
          <DocumentTextIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600">No results available yet</p>
        </div>
      ) : (
        <div className="space-y-4">
          {results.map(([taskId, result]) => (
            <div key={taskId} className="border border-gray-200 rounded-lg p-4">
              <h4 className="font-medium text-gray-900 mb-2">Task: {taskId}</h4>
              <pre className="text-sm text-gray-600 bg-gray-50 p-3 rounded overflow-auto max-h-64">
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AIAnalysisView({ investigationId }: { investigationId: string }) {
  const [analysisType, setAnalysisType] = useState('summary');
  
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-medium text-gray-900">AI Analysis</h3>
        <select
          value={analysisType}
          onChange={(e) => setAnalysisType(e.target.value)}
          className="border border-gray-300 rounded-md px-3 py-1 text-sm"
        >
          <option value="summary">Summary</option>
          <option value="threat_assessment">Threat Assessment</option>
          <option value="recommendations">Recommendations</option>
        </select>
      </div>
      
      <div className="border border-gray-200 rounded-lg p-4">
        <p className="text-gray-600">AI analysis functionality will be implemented here.</p>
        <p className="text-sm text-gray-500 mt-2">
          This will show AI-generated insights, threat assessments, and recommendations 
          based on the investigation results.
        </p>
      </div>
    </div>
  );
}

function ReportsView({ investigationId }: { investigationId: string }) {
  return (
    <div className="space-y-4">
      <h3 className="font-medium text-gray-900">Generated Reports</h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-2">Executive Summary</h4>
          <p className="text-sm text-gray-600 mb-3">High-level overview for stakeholders</p>
          <Button size="sm" variant="outline">
            Generate PDF
          </Button>
        </div>
        
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-2">Technical Report</h4>
          <p className="text-sm text-gray-600 mb-3">Detailed technical findings</p>
          <Button size="sm" variant="outline">
            Generate PDF
          </Button>
        </div>
        
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-2">Threat Assessment</h4>
          <p className="text-sm text-gray-600 mb-3">Security-focused analysis</p>
          <Button size="sm" variant="outline">
            Generate PDF
          </Button>
        </div>
        
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-2">Raw Data Export</h4>
          <p className="text-sm text-gray-600 mb-3">Complete dataset in JSON format</p>
          <Button size="sm" variant="outline">
            Download JSON
          </Button>
        </div>
      </div>
    </div>
  );
}