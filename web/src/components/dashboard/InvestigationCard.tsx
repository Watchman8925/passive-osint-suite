import React from 'react';
import { motion } from 'framer-motion';
import { 
  PlayIcon, 
  PauseIcon, 
  EyeIcon,
  TrashIcon,
  ClockIcon,
  UserIcon,
  TagIcon,
  CalendarIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';
import { format, formatDistanceToNow } from 'date-fns';

import { Investigation, InvestigationStatus, Priority } from '../../types/investigation';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { ProgressBar } from '../ui/ProgressBar';
import { useQuery } from '@tanstack/react-query';
import { investigationApi } from '../../services/api';

interface InvestigationCardProps {
  investigation: Investigation;
  onView: () => void;
  onStart: () => void;
  onPause: () => void;
  onDelete: () => void;
  isLoading?: boolean;
}

const statusColors = {
  [InvestigationStatus.CREATED]: 'bg-gray-100 text-gray-800 border-gray-200',
  [InvestigationStatus.PLANNING]: 'bg-blue-100 text-blue-800 border-blue-200',
  [InvestigationStatus.ACTIVE]: 'bg-green-100 text-green-800 border-green-200',
  [InvestigationStatus.PAUSED]: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  [InvestigationStatus.COMPLETED]: 'bg-emerald-100 text-emerald-800 border-emerald-200',
  [InvestigationStatus.FAILED]: 'bg-red-100 text-red-800 border-red-200',
  [InvestigationStatus.ARCHIVED]: 'bg-gray-100 text-gray-600 border-gray-200'
};

const priorityColors = {
  [Priority.LOW]: 'bg-gray-100 text-gray-800',
  [Priority.MEDIUM]: 'bg-blue-100 text-blue-800',
  [Priority.HIGH]: 'bg-orange-100 text-orange-800',
  [Priority.CRITICAL]: 'bg-red-100 text-red-800'
};

const statusIcons = {
  [InvestigationStatus.CREATED]: ClockIcon,
  [InvestigationStatus.PLANNING]: ClockIcon,
  [InvestigationStatus.ACTIVE]: PlayIcon,
  [InvestigationStatus.PAUSED]: PauseIcon,
  [InvestigationStatus.COMPLETED]: ChartBarIcon,
  [InvestigationStatus.FAILED]: ClockIcon,
  [InvestigationStatus.ARCHIVED]: ClockIcon
};

export default function InvestigationCard({ 
  investigation, 
  onView, 
  onStart, 
  onPause, 
  onDelete,
  isLoading = false 
}: InvestigationCardProps) {
  
  // Fetch progress data for active investigations
  const { data: progress } = useQuery({
    queryKey: ['investigation-progress', investigation.id],
    queryFn: () => investigationApi.getInvestigationProgress(investigation.id),
    enabled: investigation.status === InvestigationStatus.ACTIVE,
    refetchInterval: 5000 // Update every 5 seconds for active investigations
  });

  const StatusIcon = statusIcons[investigation.status];
  
  const canStart = investigation.status === InvestigationStatus.CREATED || 
                   investigation.status === InvestigationStatus.PAUSED;
  const canPause = investigation.status === InvestigationStatus.ACTIVE;
  
  const getTimeInfo = () => {
    if (investigation.completed_at) {
      return `Completed ${formatDistanceToNow(new Date(investigation.completed_at))} ago`;
    } else if (investigation.started_at) {
      return `Started ${formatDistanceToNow(new Date(investigation.started_at))} ago`;
    } else {
      return `Created ${formatDistanceToNow(new Date(investigation.created_at))} ago`;
    }
  };

  const getProgressInfo = () => {
    if (progress) {
      return {
        percentage: Math.round(progress.overall_progress * 100),
        completed: progress.completed_tasks,
        total: progress.total_tasks,
        failed: progress.failed_tasks
      };
    }
    return null;
  };

  const progressInfo = getProgressInfo();

  return (
    <motion.div
      whileHover={{ y: -2 }}
      className="bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden hover:shadow-lg transition-shadow duration-200"
    >
      {/* Header */}
      <div className="p-6 border-b border-gray-100">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-gray-900 truncate">
              {investigation.name}
            </h3>
            <p className="text-sm text-gray-600 mt-1 line-clamp-2">
              {investigation.description}
            </p>
          </div>
          
          <div className="flex items-center space-x-2 ml-4">
            <Badge 
              className={statusColors[investigation.status]}
              size="sm"
            >
              <StatusIcon className="h-3 w-3 mr-1" />
              {investigation.status}
            </Badge>
          </div>
        </div>

        {/* Targets */}
        <div className="mt-3">
          <div className="flex items-center text-sm text-gray-600">
            <TagIcon className="h-4 w-4 mr-1" />
            <span className="font-medium">Targets:</span>
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {investigation.targets.slice(0, 3).map((target, index) => (
              <Badge key={index} variant="secondary" size="sm">
                {target}
              </Badge>
            ))}
            {investigation.targets.length > 3 && (
              <Badge variant="secondary" size="sm">
                +{investigation.targets.length - 3} more
              </Badge>
            )}
          </div>
        </div>
      </div>

      {/* Progress (for active investigations) */}
      {progressInfo && investigation.status === InvestigationStatus.ACTIVE && (
        <div className="px-6 py-3 bg-gray-50">
          <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
            <span>Progress: {progressInfo.completed}/{progressInfo.total} tasks</span>
            <span>{progressInfo.percentage}%</span>
          </div>
          <ProgressBar 
            progress={progressInfo.percentage} 
            className="h-2"
            color="blue"
          />
          {progressInfo.failed > 0 && (
            <p className="text-xs text-red-600 mt-1">
              {progressInfo.failed} task(s) failed
            </p>
          )}
        </div>
      )}

      {/* Metadata */}
      <div className="p-6 pt-4">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex items-center text-gray-600">
            <UserIcon className="h-4 w-4 mr-2" />
            <span className="truncate">{investigation.analyst}</span>
          </div>
          
          <div className="flex items-center justify-end">
            <Badge 
              className={priorityColors[investigation.priority]}
              size="sm"
            >
              {investigation.priority}
            </Badge>
          </div>
          
          <div className="flex items-center text-gray-600">
            <CalendarIcon className="h-4 w-4 mr-2" />
            <span className="truncate">{getTimeInfo()}</span>
          </div>
          
          <div className="flex items-center justify-end text-gray-600">
            <span className="text-xs">
              {investigation.investigation_type}
            </span>
          </div>
        </div>

        {/* Tags */}
        {investigation.tags && investigation.tags.length > 0 && (
          <div className="mt-3">
            <div className="flex flex-wrap gap-1">
              {investigation.tags.slice(0, 3).map((tag, index) => (
                <Badge key={index} variant="outline" size="sm">
                  {tag}
                </Badge>
              ))}
              {investigation.tags.length > 3 && (
                <Badge variant="outline" size="sm">
                  +{investigation.tags.length - 3}
                </Badge>
              )}
            </div>
          </div>
        )}

        {/* Deadline warning */}
        {investigation.deadline && new Date(investigation.deadline) < new Date() && 
         investigation.status !== InvestigationStatus.COMPLETED && (
          <div className="mt-3 p-2 bg-red-50 border border-red-200 rounded-md">
            <p className="text-xs text-red-700">
              Deadline passed: {format(new Date(investigation.deadline), 'MMM d, yyyy')}
            </p>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="px-6 py-4 bg-gray-50 border-t border-gray-100">
        <div className="flex items-center justify-between">
          <Button
            variant="outline"
            size="sm"
            onClick={onView}
            className="flex items-center"
          >
            <EyeIcon className="h-4 w-4 mr-1" />
            View
          </Button>
          
          <div className="flex items-center space-x-2">
            {canStart && (
              <Button
                size="sm"
                onClick={onStart}
                disabled={isLoading}
                className="bg-green-600 hover:bg-green-700 text-white"
              >
                <PlayIcon className="h-4 w-4 mr-1" />
                Start
              </Button>
            )}
            
            {canPause && (
              <Button
                size="sm"
                onClick={onPause}
                disabled={isLoading}
                className="bg-yellow-600 hover:bg-yellow-700 text-white"
              >
                <PauseIcon className="h-4 w-4 mr-1" />
                Pause
              </Button>
            )}
            
            <Button
              variant="outline"
              size="sm"
              onClick={onDelete}
              disabled={isLoading}
              className="text-red-600 border-red-200 hover:bg-red-50"
            >
              <TrashIcon className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}