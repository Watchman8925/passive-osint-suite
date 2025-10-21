import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  GlobeAltIcon,
  BuildingOfficeIcon,
  EnvelopeIcon,
  CurrencyDollarIcon,
  PaperAirplaneIcon,
  MapIcon,
  ShieldCheckIcon,
  DocumentMagnifyingGlassIcon,
  UserGroupIcon,
  ServerIcon,
  EyeIcon,
  CogIcon,
  ChartBarIcon,
  LockClosedIcon
} from '@heroicons/react/24/outline';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import { apiClient } from '../../services/apiClient';
import type { NormalizedError } from '../../services/apiClient';

export interface OSINTModule {
  moduleName: string;
  displayName: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  category: string;
  categoryLabel: string;
  status: 'active' | 'beta' | 'premium';
  className: string;
  features: string[];
}

interface APIModuleInfo {
  name: string;
  description: string;
  category: string;
  class_name: string;
}

const extractErrorMessage = (error: unknown): string => {
  if (!error) {
    return 'Failed to load modules';
  }

  if (typeof error === 'string') {
    return error;
  }

  const normalized = error as NormalizedError;
  if (normalized && typeof normalized.message === 'string') {
    return normalized.message;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'Failed to load modules';
};

const categoryIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  domain: GlobeAltIcon,
  network: ServerIcon,
  web: DocumentMagnifyingGlassIcon,
  social: UserGroupIcon,
  breach: ShieldCheckIcon,
  business: BuildingOfficeIcon,
  email: EnvelopeIcon,
  aviation: PaperAirplaneIcon,
  crypto: CurrencyDollarIcon,
  code: DocumentMagnifyingGlassIcon,
  general: CogIcon,
  geospatial: MapIcon,
  financial: CurrencyDollarIcon,
  document: DocumentMagnifyingGlassIcon,
  darkweb: LockClosedIcon,
  iot: ServerIcon,
  malware: ShieldCheckIcon,
  forensics: EyeIcon,
  security: ShieldCheckIcon,
  monitoring: EyeIcon,
  reporting: ChartBarIcon,
  analysis: DocumentMagnifyingGlassIcon,
  investigation: UserGroupIcon,
  orchestration: CogIcon,
  academic: DocumentMagnifyingGlassIcon,
  patent: DocumentMagnifyingGlassIcon
};

const statusByCategory: Partial<Record<string, OSINTModule['status']>> = {
  analysis: 'premium',
  forensics: 'beta',
  monitoring: 'beta',
  orchestration: 'premium',
  investigation: 'premium',
  financial: 'premium',
  crypto: 'premium',
  security: 'beta'
};

const statusColors = {
  active: 'bg-green-100 text-green-800',
  beta: 'bg-yellow-100 text-yellow-800',
  premium: 'bg-purple-100 text-purple-800'
};

interface OSINTModuleGridProps {
  onModuleSelect: (module: OSINTModule) => void;
  selectedModule?: OSINTModule | null;
}

const OSINTModuleGrid: React.FC<OSINTModuleGridProps> = ({ onModuleSelect, selectedModule }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [modules, setModules] = useState<OSINTModule[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const formatCategory = useCallback((category: string) => {
    return category
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }, []);

  const deriveFeatures = useCallback((description: string, className: string) => {
    const fragments = description
      .split(/[,;\.]+/)
      .map(fragment => fragment.trim())
      .filter(Boolean);

    // Always include className in the features array, deduplicated
    return Array.from(new Set([...fragments, className]));
  }, []);

  const deriveStatus = useCallback(
    (module: APIModuleInfo): OSINTModule['status'] => {
      return statusByCategory[module.category] ?? 'active';
    },
    []
  );

  const buildModule = useCallback(
    (module: APIModuleInfo): OSINTModule => {
      const Icon = categoryIcons[module.category] ?? CogIcon;
      const displayName = module.name
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');

      const categoryLabel = formatCategory(module.category);

      return {
        moduleName: module.name,
        displayName,
        description: module.description,
        icon: Icon,
        category: module.category,
        categoryLabel,
        status: deriveStatus(module),
        className: module.class_name,
        features: deriveFeatures(module.description, module.class_name)
      };
    },
    [deriveFeatures, deriveStatus, formatCategory]
  );

  const loadModules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.get<APIModuleInfo[]>('/api/modules');
      const moduleList = Array.isArray(response) ? response : [];
      const transformed = moduleList.map(buildModule);
      setModules(transformed);
    } catch (err) {
      setError(extractErrorMessage(err));
      setModules([]);
    } finally {
      setLoading(false);
    }
  }, [buildModule]);

  useEffect(() => {
    loadModules();
  }, []);

  const categories = useMemo(() => {
    const unique = new Map<string, string>();
    modules.forEach(module => {
      if (!unique.has(module.category)) {
        unique.set(module.category, module.categoryLabel);
      }
    });
    return Array.from(unique.entries()).map(([value, label]) => ({ value, label }));
  }, [modules]);

  const filteredModules = modules.filter(module => {
    const matchesCategory = selectedCategory === 'all' || module.category === selectedCategory;
    const matchesSearch =
      module.displayName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      module.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      module.features.some(feature => feature.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-3xl font-bold bg-gradient-to-r from-purple-600 to-blue-600 bg-clip-text text-transparent mb-4">
          🕵️ OSINT Intelligence Modules
        </h2>
        <p className="text-gray-600 max-w-2xl mx-auto">
          Comprehensive suite of open source intelligence tools for investigation and analysis. 
          Select a module to begin your investigation.
        </p>
      </div>

      {/* Search and Filters */}
      <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="Search modules and features..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant={selectedCategory === 'all' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setSelectedCategory('all')}
            >
              All Modules
            </Button>
            {categories.map(category => (
              <Button
                key={category.value}
                variant={selectedCategory === category.value ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedCategory(category.value)}
              >
                {category.label}
              </Button>
            ))}
          </div>
        </div>
      </div>

      {loading && (
        <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20 text-center">
          <p className="text-gray-600">Loading modules...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4">
          <p className="font-medium">Failed to load modules</p>
          <p className="text-sm mb-3">{error}</p>
          <Button size="sm" variant="outline" onClick={loadModules}>
            Retry
          </Button>
        </div>
      )}

      {/* Module Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredModules.map((module, index) => {
          const Icon = module.icon;
          const isSelected = selectedModule?.moduleName === module.moduleName;

          return (
            <motion.div
              key={module.moduleName}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border transition-all duration-300 cursor-pointer hover:shadow-xl hover:scale-105 ${
                isSelected ? 'border-purple-500 ring-2 ring-purple-200' : 'border-white/20'
              }`}
              onClick={() => onModuleSelect(module)}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-gradient-to-r from-purple-600 to-blue-600 rounded-lg">
                    <Icon className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900">{module.displayName}</h3>
                    <p className="text-sm text-gray-600">{module.categoryLabel}</p>
                  </div>
                </div>
                <Badge className={statusColors[module.status]}>
                  {module.status}
                </Badge>
              </div>

              <p className="text-sm text-gray-700 mb-4 line-clamp-2">
                {module.description}
              </p>

              <div className="space-y-3">
                <div>
                  <p className="text-xs font-medium text-gray-500 mb-2">Key Features:</p>
                  <div className="flex flex-wrap gap-1">
                    {module.features.slice(0, 3).map(feature => (
                      <span
                        key={feature}
                        className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded-full"
                      >
                        {feature}
                      </span>
                    ))}
                    {module.features.length > 3 && (
                      <span className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded-full">
                        +{module.features.length - 3} more
                      </span>
                    )}
                  </div>
                </div>

                <Button
                  className="w-full"
                  size="sm"
                  variant={isSelected ? 'default' : 'outline'}
                >
                  {isSelected ? 'Selected' : 'Select Module'}
                </Button>
              </div>
            </motion.div>
          );
        })}
      </div>

      {!loading && !error && filteredModules.length === 0 && (
        <div className="text-center py-12">
          <div className="text-6xl mb-4">🔍</div>
          <h3 className="text-xl font-semibold text-gray-700 mb-2">No modules found</h3>
          <p className="text-gray-500">Try adjusting your search terms or category filter</p>
        </div>
      )}
    </div>
  );
};

export default OSINTModuleGrid;