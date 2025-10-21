import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  MagnifyingGlassIcon,
  DocumentArrowDownIcon,
  EyeIcon,
  ChartBarIcon,
  CalendarIcon,
  ClockIcon,
  CheckCircleIcon,
  DocumentTextIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';

import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { Skeleton } from '../ui/Skeleton';
import { Card } from '../ui/Card';
import { ProgressBar } from '../ui/ProgressBar';
import { investigationApi } from '../../services/api';
import { useSelectedInvestigation } from '../../contexts/SelectedInvestigationContext';
import { Investigation, InvestigationProgress } from '../../types/investigation';

export type InvestigationResultStatus =
  | 'completed'
  | 'processing'
  | 'failed'
  | 'partial'
  | 'running'
  | 'pending'
  | 'queued'
  | 'active'
  | string;

export interface InvestigationResult {
  id: string;
  investigation_id: string;
  investigation_name: string;
  module_type: string;
  target: string;
  timestamp?: string;
  status: InvestigationResultStatus;
  data: any;
  metadata: {
    execution_time?: number;
    data_sources: string[];
    confidence_score: number;
    items_found: number;
  };
  tags: string[];
  size_mb?: number;
}

const statusColors: Record<string, string> = {
  completed: 'bg-green-100 text-green-800',
  processing: 'bg-blue-100 text-blue-800',
  running: 'bg-blue-100 text-blue-800',
  active: 'bg-blue-100 text-blue-800',
  failed: 'bg-red-100 text-red-800',
  partial: 'bg-yellow-100 text-yellow-800',
  pending: 'bg-gray-100 text-gray-800',
  queued: 'bg-gray-100 text-gray-800'
};

const moduleTypeColors: Record<string, string> = {
  'domain-recon': 'bg-purple-100 text-purple-800',
  'company-intel': 'bg-blue-100 text-blue-800',
  'email-intel': 'bg-green-100 text-green-800',
  'crypto-intel': 'bg-yellow-100 text-yellow-800',
  'flight-intel': 'bg-indigo-100 text-indigo-800',
  'ip-intel': 'bg-gray-100 text-gray-800'
};

interface InvestigationResultsProps {
  investigationId?: string;
  className?: string;
  refreshToken?: number;
  onResultsUpdate?: (results: InvestigationResult[]) => void;
}

const normalizeLabel = (value?: string | null) =>
  value ? value.replace(/[_-]/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase()) : 'Unknown';

const toStringArray = (value: any): string[] => {
  if (Array.isArray(value)) return value.map((item) => String(item));
  if (typeof value === 'string') return [value];
  return [];
};

const shouldFetchProgress = (status?: string | null) => {
  const normalized = status?.toLowerCase();
  return normalized ? ['active', 'running', 'processing', 'planning'].includes(normalized) : false;
};

const normalizeResults = (investigation: Partial<Investigation> & { results?: any }): InvestigationResult[] => {
  const payload = (investigation as any)?.results;
  if (!payload) return [];

  const investigationId = String(
    (investigation as any)?.investigation_id ?? investigation.id ?? (investigation as any)?.id ?? 'investigation'
  );
  const investigationName = investigation.name ?? 'Investigation';
  const defaultTarget = Array.isArray(investigation.targets) && investigation.targets.length > 0
    ? String(investigation.targets[0])
    : 'Unknown target';

  const list: InvestigationResult[] = [];

  const pushResult = (entry: any, key: string, index: number) => {
    const data = entry && typeof entry === 'object' ? entry : { data: entry };
    const moduleType = String(data?.module_type ?? data?.module ?? key ?? `module-${index}`);
    const status = String(data?.status ?? data?.state ?? 'completed');
    const timestamp = data?.timestamp ?? data?.completed_at ?? data?.updated_at ?? data?.created_at;
    const executionRaw = data?.metadata?.execution_time ?? data?.execution_time ?? data?.duration;
    const execution_time = typeof executionRaw === 'number' ? executionRaw : undefined;
    const confidenceRaw = data?.metadata?.confidence_score ?? data?.confidence_score ?? data?.confidence ?? 0;
    let confidence = Number(confidenceRaw);
    if (!Number.isFinite(confidence)) confidence = 0;
    if (confidence > 1) confidence = confidence / 100;
    confidence = Math.max(0, Math.min(1, confidence));
    const itemsRaw = data?.metadata?.items_found ?? data?.items_found ?? (Array.isArray(data?.items) ? data.items.length : 0);
    const items_found = Number.isFinite(Number(itemsRaw)) ? Number(itemsRaw) : 0;
    const data_sources = toStringArray(data?.metadata?.data_sources ?? data?.data_sources);
    const tags = toStringArray(data?.tags ?? data?.metadata?.tags);
    const sizeRaw = data?.size_mb ?? data?.size ?? data?.metadata?.size_mb;
    const size_mb = typeof sizeRaw === 'number' ? sizeRaw : undefined;
    const target = data?.target ?? defaultTarget;

    list.push({
      id: String(data?.id ?? `${investigationId}-${moduleType}-${index}`),
      investigation_id: investigationId,
      investigation_name: investigationName,
      module_type: moduleType,
      target: String(target),
      timestamp: timestamp ? String(timestamp) : undefined,
      status,
      data: data?.data ?? data?.result ?? data,
      metadata: {
        execution_time,
        data_sources,
        confidence_score: confidence,
        items_found
      },
      tags,
      size_mb
    });
  };

  if (Array.isArray(payload)) {
    payload.forEach((entry, index) => pushResult(entry, entry?.module_type ?? `module-${index}`, index));
  } else if (typeof payload === 'object') {
    Object.entries(payload).forEach(([key, value], index) => pushResult(value, key, index));
  }

  return list;
};

const mapStatusClass = (status: string) => statusColors[status] ?? 'bg-gray-100 text-gray-800';

const InvestigationResults: React.FC<InvestigationResultsProps> = ({
  investigationId,
  className = '',
  refreshToken = 0,
  onResultsUpdate
}) => {
  const { selectedId: contextInvestigationId } = useSelectedInvestigation();
  const effectiveInvestigationId = investigationId ?? contextInvestigationId ?? null;

  const [results, setResults] = useState<InvestigationResult[]>([]);
  const [selectedResult, setSelectedResult] = useState<InvestigationResult | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [moduleFilter, setModuleFilter] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [investigationStatus, setInvestigationStatus] = useState<string | null>(null);
  const [investigationName, setInvestigationName] = useState<string>('');
  const [progress, setProgress] = useState<InvestigationProgress | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  useEffect(() => {
    setStatusFilter('all');
    setModuleFilter('all');
    setSearchTerm('');
    setSelectedResult(null);
  }, [effectiveInvestigationId]);

  const loadInvestigation = useCallback(async () => {
    if (!effectiveInvestigationId) {
      setResults([]);
      setInvestigationStatus(null);
      setInvestigationName('');
      setProgress(null);
      setError(null);
      setLastUpdated(null);
      onResultsUpdate?.([]);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const details = await investigationApi.getInvestigation(effectiveInvestigationId);
      const normalized = normalizeResults(details);
      setResults(normalized);
      setInvestigationStatus(details.status ?? null);
      setInvestigationName(details.name ?? '');
      setLastUpdated(new Date().toISOString());
      onResultsUpdate?.(normalized);

      if (shouldFetchProgress(details.status)) {
        try {
          const progressResponse = await investigationApi.getInvestigationProgress(effectiveInvestigationId);
          setProgress(progressResponse);
        } catch {
          setProgress(null);
        }
      } else {
        setProgress(null);
      }
    } catch (err: any) {
      const message = err?.response?.data?.message || err?.message || 'Failed to load investigation results';
      setError(message);
      setResults([]);
      setProgress(null);
      onResultsUpdate?.([]);
    } finally {
      setIsLoading(false);
    }
  }, [effectiveInvestigationId, onResultsUpdate]);

  useEffect(() => {
    loadInvestigation();
  }, [loadInvestigation, refreshToken]);

  const availableStatuses = useMemo(
    () => Array.from(new Set(results.map((result) => result.status))).sort(),
    [results]
  );

  const availableModules = useMemo(
    () => Array.from(new Set(results.map((result) => result.module_type))).sort(),
    [results]
  );

  const filteredResults = useMemo(() => {
    const term = searchTerm.toLowerCase();
    return results.filter((result) => {
      if (effectiveInvestigationId && result.investigation_id !== effectiveInvestigationId) return false;

      const matchesSearch =
        term === '' ||
        result.investigation_name.toLowerCase().includes(term) ||
        result.target.toLowerCase().includes(term) ||
        result.module_type.toLowerCase().includes(term) ||
        result.tags.some((tag) => tag.toLowerCase().includes(term));

      const matchesStatus = statusFilter === 'all' || result.status === statusFilter;
      const matchesModule = moduleFilter === 'all' || result.module_type === moduleFilter;

      return matchesSearch && matchesStatus && matchesModule;
    });
  }, [results, effectiveInvestigationId, searchTerm, statusFilter, moduleFilter]);

  const totalDataSize = filteredResults.reduce((sum, result) => sum + (result.size_mb ?? 0), 0);
  const completedResults = filteredResults.filter((result) => result.status === 'completed').length;
  const initialLoading = isLoading && results.length === 0;

  const handleExport = async (result: InvestigationResult, format: 'json' | 'csv' | 'pdf') => {
    try {
      console.log(`Exporting result ${result.id} as ${format}`);
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  const handleVisualize = (result: InvestigationResult) => {
    console.log(`Visualizing result ${result.id}`);
  };

  if (!effectiveInvestigationId) {
    return (
      <div className={`space-y-6 ${className}`}>
        <Card title="No investigation selected" className="bg-white/70">
          <p className="text-sm text-gray-600">
            Choose an investigation from the dashboard to review collected intelligence outputs.
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Investigation Results</h2>
            <p className="text-gray-600">View, analyze, and export your investigation findings</p>
          </div>
          <div className="flex space-x-4 text-sm">
            <div className="text-center">
              <p className="text-2xl font-bold text-blue-600">{filteredResults.length}</p>
              <p className="text-gray-600">Total Results</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-green-600">{completedResults}</p>
              <p className="text-gray-600">Completed</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-purple-600">{totalDataSize.toFixed(1)} MB</p>
              <p className="text-gray-600">Data Size</p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-600">Investigation:</span>
            <span className="text-sm font-medium text-gray-900">
              {investigationName || effectiveInvestigationId}
            </span>
            {investigationStatus && (
              <Badge className={mapStatusClass(investigationStatus)}>
                {normalizeLabel(investigationStatus)}
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-gray-500">
            {lastUpdated && <span>Last updated {new Date(lastUpdated).toLocaleTimeString()}</span>}
            <Button
              variant="outline"
              size="sm"
              loading={isLoading}
              onClick={loadInvestigation}
            >
              Refresh
            </Button>
          </div>
        </div>

        {progress && (
          <div className="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center justify-between text-sm text-blue-800 mb-2">
              <span>
                Tasks {progress.completed_tasks}/{progress.total_tasks}
              </span>
              <span>{Math.round((progress.overall_progress ?? 0) * 100)}%</span>
            </div>
            <ProgressBar
              progress={(progress.overall_progress ?? 0) * 100}
              color="blue"
              className="h-2"
            />
          </div>
        )}

        <div className="flex flex-col lg:flex-row gap-4 mt-6">
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="w-5 h-5 absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Search results, targets, or tags..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All Statuses</option>
              {availableStatuses.map((status) => (
                <option key={status} value={status}>
                  {normalizeLabel(status)}
                </option>
              ))}
            </select>
            <select
              value={moduleFilter}
              onChange={(e) => setModuleFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All Modules</option>
              {availableModules.map((module) => (
                <option key={module} value={module}>
                  {normalizeLabel(module)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {error && (
        <Card className="bg-rose-50 border-rose-200" title="Unable to load results">
          <div className="flex items-start gap-3 text-sm text-rose-700">
            <InformationCircleIcon className="w-5 h-5 mt-0.5" />
            <div>
              <p>{error}</p>
              <Button className="mt-3" variant="outline" size="sm" onClick={loadInvestigation}>
                Retry
              </Button>
            </div>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {initialLoading ? (
          Array.from({ length: 6 }).map((_, index) => (
            <div key={index} className="bg-white/70 rounded-xl p-6 shadow-lg border border-white/20">
              <Skeleton className="h-5 w-3/4 mb-4" />
              <Skeleton className="h-4 w-1/2 mb-6" />
              <Skeleton className="h-3 w-full mb-2" />
              <Skeleton className="h-3 w-2/3" />
            </div>
          ))
        ) : (
          <AnimatePresence>
            {filteredResults.map((result, index) => (
              <motion.div
                key={result.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ delay: index * 0.05 }}
                className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20 hover:shadow-xl transition-all duration-300"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="font-semibold text-gray-900 mb-1">{result.investigation_name}</h3>
                    <p className="text-sm text-gray-600">{result.target}</p>
                  </div>
                  <Badge className={mapStatusClass(result.status)}>
                    {normalizeLabel(result.status)}
                  </Badge>
                </div>

                <div className="space-y-3 mb-4">
                  <div className="flex items-center justify-between">
                    <Badge className={moduleTypeColors[result.module_type] || 'bg-gray-100 text-gray-800'}>
                      {normalizeLabel(result.module_type)}
                    </Badge>
                    <span className="text-xs text-gray-500">
                      {result.size_mb !== undefined ? `${result.size_mb.toFixed(1)} MB` : '—'}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-4 text-sm text-gray-600">
                    <div className="flex items-center space-x-1">
                      <ClockIcon className="w-4 h-4" />
                      <span>{result.metadata.execution_time !== undefined ? `${result.metadata.execution_time}s` : '—'}</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <DocumentTextIcon className="w-4 h-4" />
                      <span>{result.metadata.items_found} items</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <CheckCircleIcon className="w-4 h-4" />
                      <span>{Math.round(result.metadata.confidence_score * 100)}%</span>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-1">
                    {result.tags.length > 0 ? (
                      result.tags.map((tag) => (
                        <span
                          key={tag}
                          className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded-full"
                        >
                          {tag}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-gray-400">No tags</span>
                    )}
                  </div>

                  <div className="text-xs text-gray-500">
                    <CalendarIcon className="w-4 h-4 inline mr-1" />
                    {result.timestamp ? new Date(result.timestamp).toLocaleString() : 'Unknown time'}
                  </div>
                </div>

                <div className="flex space-x-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setSelectedResult(result)}
                    className="flex-1"
                  >
                    <EyeIcon className="w-4 h-4 mr-1" />
                    View
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleVisualize(result)}
                  >
                    <ChartBarIcon className="w-4 h-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleExport(result, 'json')}
                  >
                    <DocumentArrowDownIcon className="w-4 h-4" />
                  </Button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>

      {!initialLoading && filteredResults.length === 0 && !error && (
        <div className="text-center py-12">
          <div className="text-6xl mb-4">📊</div>
          <h3 className="text-xl font-semibold text-gray-700 mb-2">No results found</h3>
          <p className="text-gray-500">
            {searchTerm || statusFilter !== 'all' || moduleFilter !== 'all'
              ? 'Try adjusting your search filters'
              : 'Module executions will appear here once completed'}
          </p>
        </div>
      )}

      {selectedResult && (
        <ResultDetailModal
          result={selectedResult}
          isOpen={!!selectedResult}
          onClose={() => setSelectedResult(null)}
        />
      )}
    </div>
  );
};

interface ResultDetailModalProps {
  result: InvestigationResult;
  isOpen: boolean;
  onClose: () => void;
}

const ResultDetailModal: React.FC<ResultDetailModalProps> = ({ result, isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-white rounded-xl max-w-4xl w-full max-h-[90vh] overflow-hidden shadow-xl"
      >
        <div className="bg-gradient-to-r from-purple-600 to-blue-600 p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold">{result.investigation_name}</h2>
              <p className="text-purple-100">
                {normalizeLabel(result.module_type)} • {result.target}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Badge className={mapStatusClass(result.status)}>
                {normalizeLabel(result.status)}
              </Badge>
              <button
                onClick={onClose}
                className="text-white hover:text-purple-200 transition-colors"
              >
                ✕
              </button>
            </div>
          </div>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Execution Time</p>
              <p className="text-lg font-semibold">
                {result.metadata.execution_time !== undefined ? `${result.metadata.execution_time}s` : '—'}
              </p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Items Found</p>
              <p className="text-lg font-semibold">{result.metadata.items_found}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Confidence</p>
              <p className="text-lg font-semibold">{Math.round(result.metadata.confidence_score * 100)}%</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Data Size</p>
              <p className="text-lg font-semibold">
                {result.size_mb !== undefined ? `${result.size_mb.toFixed(1)} MB` : '—'}
              </p>
            </div>
          </div>

          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Data Sources</h3>
            {result.metadata.data_sources.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {result.metadata.data_sources.map((source) => (
                  <Badge key={source} className="bg-blue-100 text-blue-800">
                    {source}
                  </Badge>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No data sources reported.</p>
            )}
          </div>

          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Investigation Data</h3>
            <div className="bg-gray-50 p-4 rounded-lg overflow-x-auto">
              <pre className="text-sm text-gray-700 whitespace-pre-wrap">
                {JSON.stringify(result.data, null, 2)}
              </pre>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <Button onClick={() => console.log('Export JSON')}>
              Export JSON
            </Button>
            <Button variant="outline" onClick={() => console.log('Export CSV')}>
              Export CSV
            </Button>
            <Button variant="outline" onClick={() => console.log('Export PDF')}>
              Export PDF
            </Button>
            <Button variant="outline" onClick={() => console.log('Visualize')}>
              <ChartBarIcon className="w-4 h-4 mr-2" />
              Visualize
            </Button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default InvestigationResults;
