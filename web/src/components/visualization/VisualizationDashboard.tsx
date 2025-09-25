import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  EyeIcon,
  ChartBarIcon,
  MapIcon,
  DocumentArrowDownIcon,
  ShareIcon,
  FunnelIcon,
  MagnifyingGlassIcon
} from '@heroicons/react/24/outline';
import { Button } from '../ui/Button';
import { InvestigationResult } from '../results/InvestigationResults';
import DataVisualization from './DataVisualization';
import MapVisualization from './MapVisualization';

interface VisualizationDashboardProps {
  results: InvestigationResult[];
  className?: string;
}

const VisualizationDashboard: React.FC<VisualizationDashboardProps> = ({ results, className }) => {
  const [activeView, setActiveView] = useState<'overview' | 'individual' | 'map'>('overview');
  const [selectedResult, setSelectedResult] = useState<InvestigationResult | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [moduleFilter, setModuleFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const getFilteredResults = (): InvestigationResult[] => {
    return results.filter(result => {
      const matchesSearch = searchQuery === '' || 
        result.investigation_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        result.target.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesModule = moduleFilter === 'all' || result.module_type === moduleFilter;

      const matchesSeverity = severityFilter === 'all' || 
        getSeverityLevel(result) === severityFilter;

      return matchesSearch && matchesModule && matchesSeverity;
    });
  };

  const getSeverityLevel = (result: InvestigationResult): string => {
    const confidence = result.metadata.confidence_score;
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.7) return 'high';
    if (confidence >= 0.5) return 'medium';
    return 'low';
  };

  const getUniqueModules = (): string[] => {
    const modules = new Set(results.map(r => r.module_type));
    return Array.from(modules).sort();
  };

  const getOverviewStats = () => {
    const filteredResults = getFilteredResults();
    
    const stats = {
      total: filteredResults.length,
      byModule: {} as { [key: string]: number },
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      averageConfidence: 0,
      totalDataPoints: 0
    };

    let totalConfidence = 0;

    filteredResults.forEach(result => {
      // Count by module
      stats.byModule[result.module_type] = (stats.byModule[result.module_type] || 0) + 1;

      // Count by severity
      const severity = getSeverityLevel(result);
      stats.bySeverity[severity as keyof typeof stats.bySeverity]++;

      // Sum confidence scores
      totalConfidence += result.metadata.confidence_score;

      // Count data points
      stats.totalDataPoints += result.metadata.items_found || 0;
    });

    stats.averageConfidence = filteredResults.length > 0 ? totalConfidence / filteredResults.length : 0;

    return stats;
  };

  const renderOverviewDashboard = () => {
    const stats = getOverviewStats();

    return (
      <div className="space-y-6">
        {/* Statistics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Investigations</p>
                <p className="text-3xl font-bold text-gray-900">{stats.total}</p>
              </div>
              <ChartBarIcon className="w-8 h-8 text-purple-600" />
            </div>
          </div>

          <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Average Confidence</p>
                <p className="text-3xl font-bold text-gray-900">
                  {(stats.averageConfidence * 100).toFixed(0)}%
                </p>
              </div>
              <EyeIcon className="w-8 h-8 text-green-600" />
            </div>
          </div>

          <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Critical Findings</p>
                <p className="text-3xl font-bold text-red-600">{stats.bySeverity.critical}</p>
              </div>
              <ShareIcon className="w-8 h-8 text-red-600" />
            </div>
          </div>

          <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Data Points</p>
                <p className="text-3xl font-bold text-gray-900">{stats.totalDataPoints}</p>
              </div>
              <DocumentArrowDownIcon className="w-8 h-8 text-blue-600" />
            </div>
          </div>
        </div>

        {/* Module Distribution */}
        <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Investigation Distribution by Module</h3>
          <div className="space-y-4">
            {Object.entries(stats.byModule).map(([module, count]) => {
              const percentage = (count / stats.total) * 100;
              return (
                <div key={module} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium capitalize">{module.replace('-', ' ')}</span>
                    <span className="text-sm text-gray-600">{count} investigations</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-purple-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Risk Distribution</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(stats.bySeverity).map(([severity, count]) => {
              const colors = {
                critical: 'bg-red-100 text-red-800 border-red-200',
                high: 'bg-orange-100 text-orange-800 border-orange-200',
                medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
                low: 'bg-green-100 text-green-800 border-green-200'
              };

              return (
                <div key={severity} className={`p-4 rounded-lg border ${colors[severity as keyof typeof colors]}`}>
                  <p className="text-sm font-medium capitalize">{severity}</p>
                  <p className="text-2xl font-bold">{count}</p>
                  <p className="text-xs">
                    {stats.total > 0 ? ((count / stats.total) * 100).toFixed(1) : 0}% of total
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Investigations */}
        <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-gray-900">Recent Investigations</h3>
            <Button size="sm" variant="outline" onClick={() => setActiveView('individual')}>
              View All
            </Button>
          </div>
          <div className="space-y-3">
            {getFilteredResults().slice(0, 5).map(result => (
              <div
                key={result.id}
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100 transition-colors"
                onClick={() => {
                  setSelectedResult(result);
                  setActiveView('individual');
                }}
              >
                <div className="flex items-center space-x-3">
                  <div className={`w-3 h-3 rounded-full ${
                    getSeverityLevel(result) === 'critical' ? 'bg-red-500' :
                    getSeverityLevel(result) === 'high' ? 'bg-orange-500' :
                    getSeverityLevel(result) === 'medium' ? 'bg-yellow-500' :
                    'bg-green-500'
                  }`} />
                  <div>
                    <p className="font-medium">{result.investigation_name}</p>
                    <p className="text-sm text-gray-600">{result.target} • {result.module_type}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium">
                    {(result.metadata.confidence_score * 100).toFixed(0)}%
                  </p>
                  <p className="text-xs text-gray-500">
                    {new Date(result.timestamp).toLocaleDateString()}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  const renderIndividualView = () => {
    if (!selectedResult) {
      return (
        <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Select an Investigation to Visualize</h3>
          <div className="space-y-3">
            {getFilteredResults().map(result => (
              <div
                key={result.id}
                className="flex items-center justify-between p-4 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100 transition-colors"
                onClick={() => setSelectedResult(result)}
              >
                <div className="flex items-center space-x-3">
                  <div className={`w-4 h-4 rounded-full ${
                    getSeverityLevel(result) === 'critical' ? 'bg-red-500' :
                    getSeverityLevel(result) === 'high' ? 'bg-orange-500' :
                    getSeverityLevel(result) === 'medium' ? 'bg-yellow-500' :
                    'bg-green-500'
                  }`} />
                  <div>
                    <p className="font-medium">{result.investigation_name}</p>
                    <p className="text-sm text-gray-600">{result.target} • {result.module_type}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium">
                    {(result.metadata.confidence_score * 100).toFixed(0)}% confidence
                  </p>
                  <p className="text-xs text-gray-500">
                    {result.metadata.items_found} items found
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    }

    return <DataVisualization result={selectedResult} />;
  };

  const renderMapView = () => {
    return <MapVisualization results={getFilteredResults()} />;
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header with Navigation */}
      <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Investigation Analytics</h1>
            <p className="text-gray-600">Visualize and analyze your OSINT investigation results</p>
          </div>

          {/* View Tabs */}
          <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
            {[
              { id: 'overview', label: 'Overview', icon: ChartBarIcon },
              { id: 'individual', label: 'Individual', icon: EyeIcon },
              { id: 'map', label: 'Geographic', icon: MapIcon }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveView(tab.id as any)}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
                    activeView === tab.id
                      ? 'bg-white text-purple-600 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Filters */}
        <div className="mt-4 flex flex-col sm:flex-row gap-4">
          <div className="flex-1 relative">
            <MagnifyingGlassIcon className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search investigations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            />
          </div>

          <select
            value={moduleFilter}
            onChange={(e) => setModuleFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
          >
            <option value="all">All Modules</option>
            {getUniqueModules().map(module => (
              <option key={module} value={module}>
                {module.replace('-', ' ').toUpperCase()}
              </option>
            ))}
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeView}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.3 }}
        >
          {activeView === 'overview' && renderOverviewDashboard()}
          {activeView === 'individual' && renderIndividualView()}
          {activeView === 'map' && renderMapView()}
        </motion.div>
      </AnimatePresence>

      {/* Results Count */}
      <div className="text-center text-sm text-gray-500">
        Showing {getFilteredResults().length} of {results.length} investigations
      </div>
    </div>
  );
};

export default VisualizationDashboard;