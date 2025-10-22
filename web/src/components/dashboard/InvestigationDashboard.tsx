import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  MagnifyingGlassIcon, 
  PlayIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ChartBarIcon,
  PlusIcon
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';

import { Investigation, InvestigationStatus, Priority } from '../../types/investigation';
import { useWebSocket } from '../../hooks/useWebSocket';
import { investigationApi } from '../../services/api';
import { osintAPI } from '../../services/osintAPI';
import { generatedClient } from '../../services/apiClientGenerated';
import InvestigationCard from './InvestigationCard';
import CreateInvestigationModal from './CreateInvestigationModal';
import InvestigationDetailsModal from './InvestigationDetailsModal';
import { ProgressBar } from '../ui/ProgressBar';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { SearchInput } from '../ui/SearchInput';
import { FilterDropdown } from '../ui/FilterDropdown';

interface DashboardProps {
  className?: string;
}

const statusColors = {
  [InvestigationStatus.CREATED]: 'bg-gray-100 text-gray-800',
  [InvestigationStatus.PLANNING]: 'bg-blue-100 text-blue-800',
  [InvestigationStatus.ACTIVE]: 'bg-green-100 text-green-800',
  [InvestigationStatus.PAUSED]: 'bg-yellow-100 text-yellow-800',
  [InvestigationStatus.COMPLETED]: 'bg-emerald-100 text-emerald-800',
  [InvestigationStatus.FAILED]: 'bg-red-100 text-red-800',
  [InvestigationStatus.ARCHIVED]: 'bg-gray-100 text-gray-600'
};

const priorityColors = {
  [Priority.LOW]: 'bg-gray-100 text-gray-800',
  [Priority.MEDIUM]: 'bg-blue-100 text-blue-800',
  [Priority.HIGH]: 'bg-orange-100 text-orange-800',
  [Priority.CRITICAL]: 'bg-red-100 text-red-800'
};

export default function InvestigationDashboard({ className = '' }: DashboardProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<InvestigationStatus | 'all'>('all');
  const [priorityFilter, setPriorityFilter] = useState<Priority | 'all'>('all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedInvestigation, setSelectedInvestigation] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<'created_at' | 'name' | 'priority'>('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const queryClient = useQueryClient();

  // WebSocket connection for real-time updates
  const { isConnected, lastMessage } = useWebSocket('/ws');

  // Fetch investigations
  const { 
    data: investigations = [], 
    isLoading, 
    error,
    refetch 
  } = useQuery({
    queryKey: ['investigations', statusFilter, priorityFilter],
    // Incremental migration: use generated client (falls back to legacy types if generation placeholder)
    queryFn: async () => {
      const data = await generatedClient.listInvestigations({
        status: statusFilter !== 'all' ? statusFilter : undefined,
        // priority filter not yet modeled in OpenAPI list params; filter client-side for now
      } as any);
      // Ensure we always return an array shaped like Investigation[] expected downstream.
      const anyData: any = data as any;
      return Array.isArray(anyData) ? anyData : (anyData?.items || []);
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  // Real-time updates via WebSocket
  useEffect(() => {
    if (lastMessage) {
      let data: any;
      try {
        data = JSON.parse(lastMessage);
      } catch {
        return;
      }
      
      if (data.type === 'investigation_update') {
        // Update specific investigation in cache
        queryClient.setQueryData(['investigations'], (oldData: Investigation[] | undefined) => {
          if (!oldData) return oldData;
          
          return oldData.map(inv => 
            inv.id === data.investigation_id 
              ? { ...inv, ...data.updates }
              : inv
          );
        });
        
        // Show notification
        if (data.updates.status) {
          toast.success(`Investigation "${data.investigation_name}" status updated to ${data.updates.status}`);
        }
      } else if (data.type === 'task_update') {
        // Invalidate investigation progress queries
        queryClient.invalidateQueries({ queryKey: ['investigation-progress'] });
      }
    }
  }, [lastMessage, queryClient]);

  // Mutation for investigation actions
  const startInvestigationMutation = useMutation({
    mutationFn: investigationApi.startInvestigation,
    onSuccess: (_, investigationId) => {
      queryClient.invalidateQueries({ queryKey: ['investigations'] });
      toast.success('Investigation started successfully');
    },
    onError: (error) => {
      toast.error(`Failed to start investigation: ${error.message}`);
    }
  });

  const archiveInvestigationMutation = useMutation({
    mutationFn: investigationApi.archiveInvestigation,
    onSuccess: (data, investigationId) => {
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

  // pause/delete not supported in backend currently
  const pauseInvestigationMutation = { isPending: false, mutateAsync: async (_: string) => { toast.error('Pause not implemented'); } } as any;
  const deleteInvestigationMutation = { isPending: false, mutateAsync: async (_: string) => { toast.error('Delete not implemented'); } } as any;

  // Filter and sort investigations
  const filteredInvestigations = investigations
    .filter(inv => {
      const matchesSearch = inv.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          inv.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          inv.targets.some(target => target.toLowerCase().includes(searchTerm.toLowerCase()));
      
      const matchesStatus = statusFilter === 'all' || inv.status === statusFilter;
      const matchesPriority = priorityFilter === 'all' || inv.priority === priorityFilter;
      
      return matchesSearch && matchesStatus && matchesPriority;
    })
    .sort((a, b) => {
      let aValue, bValue;
      
      switch (sortBy) {
        case 'name':
          aValue = a.name.toLowerCase();
          bValue = b.name.toLowerCase();
          break;
        case 'priority':
          aValue = a.priority;
          bValue = b.priority;
          break;
        case 'created_at':
        default:
          aValue = new Date(a.created_at).getTime();
          bValue = new Date(b.created_at).getTime();
          break;
      }
      
      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

  // Calculate dashboard statistics
  const stats = {
    total: investigations.length,
    active: investigations.filter(inv => inv.status === InvestigationStatus.ACTIVE).length,
    completed: investigations.filter(inv => inv.status === InvestigationStatus.COMPLETED).length,
    failed: investigations.filter(inv => inv.status === InvestigationStatus.FAILED).length
  };

  const handleInvestigationAction = async (
    investigationId: string,
    action: 'start' | 'pause' | 'delete' | 'archive'
  ) => {
    try {
      switch (action) {
        case 'start':
          await startInvestigationMutation.mutateAsync(investigationId);
          break;
        case 'resume':
          await resumeInvestigationMutation.mutateAsync(investigationId);
          break;
        case 'pause':
          await pauseInvestigationMutation.mutateAsync(investigationId);
          break;
        case 'delete':
          await stopInvestigationMutation.mutateAsync(investigationId);
          break;
        case 'archive':
          await archiveInvestigationMutation.mutateAsync(investigationId);
          break;
      }
    } catch (error) {
      // Error handling is done in mutation callbacks
    }
  };

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-600">Failed to load investigations</p>
          <Button onClick={() => refetch()} className="mt-2">
            Try Again
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Investigation Dashboard</h1>
          <p className="text-gray-600 mt-1">
            Manage and monitor your OSINT investigations
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          {/* Connection Status */}
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm text-gray-600">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          
          <Button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 hover:bg-blue-700"
          >
            <PlusIcon className="h-4 w-4 mr-2" />
            New Investigation
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-lg shadow p-6"
        >
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <ChartBarIcon className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Total</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white rounded-lg shadow p-6"
        >
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <PlayIcon className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Active</p>
              <p className="text-2xl font-bold text-gray-900">{stats.active}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white rounded-lg shadow p-6"
        >
          <div className="flex items-center">
            <div className="p-2 bg-emerald-100 rounded-lg">
              <CheckCircleIcon className="h-6 w-6 text-emerald-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Completed</p>
              <p className="text-2xl font-bold text-gray-900">{stats.completed}</p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-white rounded-lg shadow p-6"
        >
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <XCircleIcon className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Failed</p>
              <p className="text-2xl font-bold text-gray-900">{stats.failed}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Filters and Search */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="md:col-span-2">
            <SearchInput
              placeholder="Search investigations..."
              value={searchTerm}
              onChange={setSearchTerm}
            />
          </div>
          
          <FilterDropdown
            value={statusFilter}
            onChange={(val: string) => setStatusFilter(val as InvestigationStatus | 'all')}
            placeholder="Status"
            options={[
              { value: 'all', label: 'All Statuses' },
              ...Object.values(InvestigationStatus).map(status => ({
                value: status,
                label: status.charAt(0).toUpperCase() + status.slice(1)
              }))
            ]}
          />
          
          <FilterDropdown
            value={priorityFilter}
            onChange={(val: string) => setPriorityFilter(val as Priority | 'all')}
            placeholder="Priority"
            options={[
              { value: 'all', label: 'All Priorities' },
              ...Object.values(Priority).map(priority => ({
                value: priority,
                label: priority.charAt(0).toUpperCase() + priority.slice(1)
              }))
            ]}
          />
        </div>

        <div className="flex items-center justify-between mt-4">
          <p className="text-sm text-gray-600">
            Showing {filteredInvestigations.length} of {investigations.length} investigations
          </p>
          
          <div className="flex items-center space-x-2">
            <label className="text-sm text-gray-600">Sort by:</label>
            <select
              value={`${sortBy}-${sortOrder}`}
              onChange={(e) => {
                const [field, order] = e.target.value.split('-');
                setSortBy(field as typeof sortBy);
                setSortOrder(order as typeof sortOrder);
              }}
              className="text-sm border-gray-300 rounded-md"
            >
              <option value="created_at-desc">Newest First</option>
              <option value="created_at-asc">Oldest First</option>
              <option value="name-asc">Name A-Z</option>
              <option value="name-desc">Name Z-A</option>
              <option value="priority-desc">High Priority First</option>
            </select>
          </div>
        </div>
      </div>

      {/* Investigations Grid */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="bg-white rounded-lg shadow p-6 animate-pulse">
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                <div className="h-3 bg-gray-200 rounded w-1/2 mb-4"></div>
                <div className="space-y-2">
                  <div className="h-3 bg-gray-200 rounded"></div>
                  <div className="h-3 bg-gray-200 rounded w-5/6"></div>
                </div>
              </div>
            ))}
          </div>
        ) : filteredInvestigations.length === 0 ? (
          <div className="text-center py-12">
            <MagnifyingGlassIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600">No investigations found</p>
            <p className="text-sm text-gray-500 mt-1">
              {searchTerm || statusFilter !== 'all' || priorityFilter !== 'all'
                ? 'Try adjusting your filters'
                : 'Create your first investigation to get started'
              }
            </p>
          </div>
        ) : (
          <AnimatePresence>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredInvestigations.map((investigation) => (
                <motion.div
                  key={investigation.id}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  transition={{ duration: 0.2 }}
                >
                  <InvestigationCard
                    investigation={investigation}
                    onView={() => setSelectedInvestigation(investigation.id)}
                    onStart={() =>
                      handleInvestigationAction(
                        investigation.id,
                        investigation.status === InvestigationStatus.PAUSED
                          ? 'resume'
                          : 'start'
                      )
                    }
                    onPause={() => handleInvestigationAction(investigation.id, 'pause')}
                    onDelete={() => handleInvestigationAction(investigation.id, 'delete')}
                    onArchive={() => handleInvestigationAction(investigation.id, 'archive')}
                    isLoading={
                      startInvestigationMutation.isPending ||
                      pauseInvestigationMutation.isPending ||
                      deleteInvestigationMutation.isPending ||
                      archiveInvestigationMutation.isPending
                    }
                  />
                </motion.div>
              ))}
            </div>
          </AnimatePresence>
        )}
      </div>

      {/* Modals */}
      <CreateInvestigationModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSuccess={() => {
          setShowCreateModal(false);
          queryClient.invalidateQueries({ queryKey: ['investigations'] });
        }}
      />

      {selectedInvestigation && (
        <InvestigationDetailsModal
          investigationId={selectedInvestigation}
          isOpen={!!selectedInvestigation}
          onClose={() => setSelectedInvestigation(null)}
        />
      )}
    </div>
  );
}