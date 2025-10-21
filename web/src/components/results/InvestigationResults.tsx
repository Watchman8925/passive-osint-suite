import React, { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  DocumentArrowDownIcon,
  EyeIcon,
  TrashIcon,
  ChartBarIcon,
  MapIcon,
  DocumentTextIcon,
  CalendarIcon,
  ClockIcon,
  TagIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';
import { saveAs } from 'file-saver';
import toast from 'react-hot-toast';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { exportService, ExportOptions } from '../../services/exportService';

export interface InvestigationResult {
  id: string;
  investigation_id: string;
  investigation_name: string;
  module_type: string;
  target: string;
  timestamp: string;
  status: 'completed' | 'processing' | 'failed' | 'partial';
  data: any;
  metadata: {
    execution_time: number;
    data_sources: string[];
    confidence_score: number;
    items_found: number;
  };
  tags: string[];
  size_mb: number;
}

const mockResults: InvestigationResult[] = [
  {
    id: '1',
    investigation_id: 'inv-001',
    investigation_name: 'Corporate Intelligence Analysis',
    module_type: 'domain-recon',
    target: 'example.com',
    timestamp: '2024-01-15T14:30:00Z',
    status: 'completed',
    data: {
      domain_info: { registrar: 'GoDaddy', creation_date: '2010-05-15' },
      dns_records: { A: ['192.168.1.1'], MX: ['mail.example.com'] },
      subdomains: ['www.example.com', 'mail.example.com', 'ftp.example.com'],
      ssl_info: { issuer: 'Let\'s Encrypt', expires: '2024-06-15' }
    },
    metadata: {
      execution_time: 45.2,
      data_sources: ['DNS', 'WHOIS', 'Certificate Transparency'],
      confidence_score: 0.92,
      items_found: 27
    },
    tags: ['domain', 'infrastructure', 'security'],
    size_mb: 2.3
  },
  {
    id: '2',
    investigation_id: 'inv-001',
    investigation_name: 'Corporate Intelligence Analysis',
    module_type: 'company-intel',
    target: 'Acme Corp',
    timestamp: '2024-01-15T15:45:00Z',
    status: 'completed',
    data: {
      company_profile: { name: 'Acme Corp', founded: '1995', employees: '500-1000' },
      executives: [
        { name: 'John Smith', title: 'CEO', linkedin: 'linkedin.com/in/johnsmith' },
        { name: 'Jane Doe', title: 'CTO', linkedin: 'linkedin.com/in/janedoe' }
      ],
      financial_data: { revenue: '$50M-100M', funding: 'Series C' },
      locations: ['New York, NY', 'San Francisco, CA']
    },
    metadata: {
      execution_time: 67.8,
      data_sources: ['LinkedIn', 'Crunchbase', 'SEC Filings', 'Company Website'],
      confidence_score: 0.87,
      items_found: 42
    },
    tags: ['company', 'executives', 'financial'],
    size_mb: 5.7
  },
  {
    id: '3',
    investigation_id: 'inv-002',
    investigation_name: 'Email Investigation',
    module_type: 'email-intel',
    target: 'target@example.com',
    timestamp: '2024-01-14T09:20:00Z',
    status: 'completed',
    data: {
      email_validation: { valid: true, deliverable: true, reputation: 'good' },
      breach_data: [
        { source: 'DataBreach2021', date: '2021-03-15', records: 50000 },
        { source: 'LeakDB2020', date: '2020-11-22', records: 25000 }
      ],
      social_links: ['twitter.com/target', 'linkedin.com/in/target'],
      domain_analysis: { mx_records: ['mail.example.com'], spf_valid: true }
    },
    metadata: {
      execution_time: 23.1,
      data_sources: ['HaveIBeenPwned', 'Hunter.io', 'Social Media APIs'],
      confidence_score: 0.94,
      items_found: 15
    },
    tags: ['email', 'breach', 'social-media'],
    size_mb: 1.2
  }
];

const statusColors = {
  completed: 'bg-green-100 text-green-800',
  processing: 'bg-blue-100 text-blue-800',
  failed: 'bg-red-100 text-red-800',
  partial: 'bg-yellow-100 text-yellow-800'
};

const moduleTypeColors = {
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
}

const InvestigationResults: React.FC<InvestigationResultsProps> = ({ investigationId, className }) => {
  const [results, setResults] = useState<InvestigationResult[]>(mockResults);
  const [selectedResult, setSelectedResult] = useState<InvestigationResult | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [moduleFilter, setModuleFilter] = useState<string>('all');

  const filteredResults = results.filter(result => {
    if (investigationId && result.investigation_id !== investigationId) return false;
    
    const matchesSearch = 
      result.investigation_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      result.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      result.module_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      result.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesStatus = statusFilter === 'all' || result.status === statusFilter;
    const matchesModule = moduleFilter === 'all' || result.module_type === moduleFilter;
    
    return matchesSearch && matchesStatus && matchesModule;
  });

  const [activeExportKey, setActiveExportKey] = useState<string | null>(null);

  const isExporting = useCallback(
    (resultId: string, format: ExportOptions['format']) => activeExportKey === `${resultId}:${format}`,
    [activeExportKey]
  );

  const handleExport = useCallback(
    async (result: InvestigationResult, format: ExportOptions['format']) => {
      const exportKey = `${result.id}:${format}`;
      try {
        setActiveExportKey(exportKey);
        const exportResult = await exportService.exportResult(result, {
          format,
          includeMetadata: true,
          includeRawData: true,
        });

        if (!exportResult.success || (!exportResult.blob && !exportResult.downloadUrl)) {
          toast.error(exportResult.error || `Unable to export result as ${format.toUpperCase()}`);
          return;
        }

        const filename =
          exportResult.filename ||
          `result_${result.id}.${format === 'excel' ? 'xlsx' : format === 'pdf' ? 'pdf' : format}`;

        if (exportResult.blob) {
          saveAs(exportResult.blob, filename);
        } else if (exportResult.downloadUrl) {
          const link = document.createElement('a');
          link.href = exportResult.downloadUrl;
          link.download = filename;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          if (exportResult.downloadUrl.startsWith('blob:')) {
            URL.revokeObjectURL(exportResult.downloadUrl);
          }
        }

        toast.success(`Exported result as ${format.toUpperCase()}`);
      } catch (error) {
        console.error('Export failed:', error);
        const message = error instanceof Error ? error.message : 'Unknown error';
        toast.error(`Failed to export result: ${message}`);
      } finally {
        setActiveExportKey(prev => (prev === exportKey ? null : prev));
      }
    },
    [exportService, toast, saveAs]
  );

  const handleVisualize = (result: InvestigationResult) => {
    // Implementation will be added in visualization functionality
    console.log(`Visualizing result ${result.id}`);
  };

  const totalDataSize = filteredResults.reduce((sum, result) => sum + result.size_mb, 0);
  const completedResults = filteredResults.filter(r => r.status === 'completed').length;

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header with Statistics */}
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

        {/* Search and Filters */}
        <div className="flex flex-col lg:flex-row gap-4">
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
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="processing">Processing</option>
              <option value="failed">Failed</option>
              <option value="partial">Partial</option>
            </select>
            <select
              value={moduleFilter}
              onChange={(e) => setModuleFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All Modules</option>
              <option value="domain-recon">Domain Recon</option>
              <option value="company-intel">Company Intel</option>
              <option value="email-intel">Email Intel</option>
              <option value="crypto-intel">Crypto Intel</option>
              <option value="flight-intel">Flight Intel</option>
              <option value="ip-intel">IP Intel</option>
            </select>
          </div>
        </div>
      </div>

      {/* Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        <AnimatePresence>
          {filteredResults.map((result, index) => (
            <motion.div
              key={result.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ delay: index * 0.1 }}
              className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20 hover:shadow-xl transition-all duration-300"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="font-semibold text-gray-900 mb-1">{result.investigation_name}</h3>
                  <p className="text-sm text-gray-600">{result.target}</p>
                </div>
                <Badge className={statusColors[result.status]}>
                  {result.status}
                </Badge>
              </div>

              <div className="space-y-3 mb-4">
                <div className="flex items-center justify-between">
                  <Badge className={moduleTypeColors[result.module_type] || 'bg-gray-100 text-gray-800'}>
                    {result.module_type.replace('-', ' ')}
                  </Badge>
                  <span className="text-xs text-gray-500">{result.size_mb.toFixed(1)} MB</span>
                </div>

                <div className="flex items-center space-x-4 text-sm text-gray-600">
                  <div className="flex items-center space-x-1">
                    <ClockIcon className="w-4 h-4" />
                    <span>{result.metadata.execution_time}s</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <DocumentTextIcon className="w-4 h-4" />
                    <span>{result.metadata.items_found} items</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <CheckCircleIcon className="w-4 h-4" />
                    <span>{(result.metadata.confidence_score * 100).toFixed(0)}%</span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-1">
                  {result.tags.map(tag => (
                    <span
                      key={tag}
                      className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded-full"
                    >
                      {tag}
                    </span>
                  ))}
                </div>

                <div className="text-xs text-gray-500">
                  <CalendarIcon className="w-4 h-4 inline mr-1" />
                  {new Date(result.timestamp).toLocaleString()}
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
                  disabled={isExporting(result.id, 'json')}
                  aria-label={`Export ${result.investigation_name} as JSON`}
                >
                  {isExporting(result.id, 'json') ? (
                    <span className="flex items-center gap-2 text-xs">
                      <span className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
                      Exporting
                    </span>
                  ) : (
                    <DocumentArrowDownIcon className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {filteredResults.length === 0 && (
        <div className="text-center py-12">
          <div className="text-6xl mb-4">📊</div>
          <h3 className="text-xl font-semibold text-gray-700 mb-2">No results found</h3>
          <p className="text-gray-500">
            {searchTerm || statusFilter !== 'all' || moduleFilter !== 'all'
              ? 'Try adjusting your search filters'
              : 'Start an investigation to see results here'
            }
          </p>
        </div>
      )}

      {/* Result Detail Modal */}
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

// Result Detail Modal Component
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
        {/* Header */}
        <div className="bg-gradient-to-r from-purple-600 to-blue-600 p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold">{result.investigation_name}</h2>
              <p className="text-purple-100">{result.module_type} • {result.target}</p>
            </div>
            <button
              onClick={onClose}
              className="text-white hover:text-purple-200 transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
          {/* Metadata */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Execution Time</p>
              <p className="text-lg font-semibold">{result.metadata.execution_time}s</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Items Found</p>
              <p className="text-lg font-semibold">{result.metadata.items_found}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Confidence</p>
              <p className="text-lg font-semibold">{(result.metadata.confidence_score * 100).toFixed(0)}%</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-600">Data Size</p>
              <p className="text-lg font-semibold">{result.size_mb.toFixed(1)} MB</p>
            </div>
          </div>

          {/* Data Sources */}
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Data Sources</h3>
            <div className="flex flex-wrap gap-2">
              {result.metadata.data_sources.map(source => (
                <Badge key={source} className="bg-blue-100 text-blue-800">
                  {source}
                </Badge>
              ))}
            </div>
          </div>

          {/* Raw Data */}
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Investigation Data</h3>
            <div className="bg-gray-50 p-4 rounded-lg overflow-x-auto">
              <pre className="text-sm text-gray-700 whitespace-pre-wrap">
                {JSON.stringify(result.data, null, 2)}
              </pre>
            </div>
          </div>

          {/* Export Options */}
          <div className="flex space-x-4">
            <Button
              onClick={() => handleExport(result, 'json')}
              disabled={isExporting(result.id, 'json')}
            >
              {isExporting(result.id, 'json') ? 'Exporting JSON…' : 'Export JSON'}
            </Button>
            <Button
              variant="outline"
              onClick={() => handleExport(result, 'csv')}
              disabled={isExporting(result.id, 'csv')}
            >
              {isExporting(result.id, 'csv') ? 'Exporting CSV…' : 'Export CSV'}
            </Button>
            <Button
              variant="outline"
              onClick={() => handleExport(result, 'pdf')}
              disabled={isExporting(result.id, 'pdf')}
            >
              {isExporting(result.id, 'pdf') ? 'Exporting PDF…' : 'Export PDF'}
            </Button>
            <Button
              variant="outline"
              onClick={() => handleExport(result, 'excel')}
              disabled={isExporting(result.id, 'excel')}
            >
              {isExporting(result.id, 'excel') ? 'Exporting Excel…' : 'Export Excel'}
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