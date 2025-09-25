import React, { useState } from 'react';
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

export interface OSINTModule {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  category: string;
  status: 'active' | 'beta' | 'premium';
  endpoint: string;
  features: string[];
}

const osintModules: OSINTModule[] = [
  {
    id: 'domain-recon',
    name: 'Domain Reconnaissance',
    description: 'Comprehensive passive domain analysis including DNS, WHOIS, subdomains, and security assessment',
    icon: GlobeAltIcon,
    category: 'Network Intelligence',
    status: 'active',
    endpoint: '/api/domain-recon',
    features: ['DNS Analysis', 'WHOIS Data', 'Subdomain Discovery', 'SSL/TLS Analysis', 'Security Headers']
  },
  {
    id: 'company-intel',
    name: 'Company Intelligence',
    description: 'Corporate investigation and business intelligence gathering from public sources',
    icon: BuildingOfficeIcon,
    category: 'Business Intelligence',
    status: 'active',
    endpoint: '/api/company-intel',
    features: ['Company Profiles', 'Executive Information', 'Financial Data', 'News & Events', 'Regulatory Filings']
  },
  {
    id: 'email-intel',
    name: 'Email Intelligence',
    description: 'Email investigation including breach detection, reputation analysis, and domain validation',
    icon: EnvelopeIcon,
    category: 'Communication Intelligence',
    status: 'active',
    endpoint: '/api/email-intel',
    features: ['Breach Detection', 'Email Validation', 'Domain Analysis', 'Reputation Check', 'Social Media Links']
  },
  {
    id: 'crypto-intel',
    name: 'Cryptocurrency Intelligence',
    description: 'Blockchain analysis and cryptocurrency transaction investigation',
    icon: CurrencyDollarIcon,
    category: 'Financial Intelligence',
    status: 'active',
    endpoint: '/api/crypto-intel',
    features: ['Wallet Analysis', 'Transaction Tracking', 'Exchange Detection', 'Risk Assessment', 'Flow Analysis']
  },
  {
    id: 'flight-intel',
    name: 'Flight Intelligence',
    description: 'Aviation intelligence including flight tracking, aircraft data, and airport information',
    icon: PaperAirplaneIcon,
    category: 'Transportation Intelligence',
    status: 'active',
    endpoint: '/api/flight-intel',
    features: ['Flight Tracking', 'Aircraft Registry', 'Airport Data', 'Route Analysis', 'Operator Information']
  },
  {
    id: 'ip-intel',
    name: 'IP Intelligence',
    description: 'IP address investigation including geolocation, ownership, and threat intelligence',
    icon: ServerIcon,
    category: 'Network Intelligence',
    status: 'active',
    endpoint: '/api/ip-intel',
    features: ['Geolocation', 'ISP Information', 'Threat Intelligence', 'Port Scanning', 'Historical Data']
  },
  {
    id: 'media-forensics',
    name: 'Media Forensics',
    description: 'Image and video analysis including metadata extraction and reverse image search',
    icon: EyeIcon,
    category: 'Digital Forensics',
    status: 'beta',
    endpoint: '/api/media-forensics',
    features: ['EXIF Analysis', 'Reverse Image Search', 'Face Recognition', 'Object Detection', 'Geolocation']
  },
  {
    id: 'network-intel',
    name: 'Network Intelligence',
    description: 'Network infrastructure analysis and mapping capabilities',
    icon: MapIcon,
    category: 'Network Intelligence',
    status: 'active',
    endpoint: '/api/network-intel',
    features: ['Network Mapping', 'Traceroute Analysis', 'ASN Information', 'BGP Data', 'Peering Relationships']
  },
  {
    id: 'conspiracy-analyzer',
    name: 'Pattern Analysis',
    description: 'Advanced pattern detection and relationship analysis across multiple data sources',
    icon: DocumentMagnifyingGlassIcon,
    category: 'Advanced Analytics',
    status: 'premium',
    endpoint: '/api/conspiracy-analyzer',
    features: ['Pattern Recognition', 'Relationship Mapping', 'Anomaly Detection', 'Timeline Analysis', 'Correlation Engine']
  },
  {
    id: 'bellingcat-toolkit',
    name: 'Bellingcat Toolkit',
    description: 'Specialized tools for investigative journalism and open source research',
    icon: UserGroupIcon,
    category: 'Investigative Tools',
    status: 'active',
    endpoint: '/api/bellingcat-toolkit',
    features: ['Social Media Analysis', 'Verification Tools', 'Archive Search', 'Metadata Analysis', 'Timeline Creation']
  },
  {
    id: 'audit-trail',
    name: 'Audit & Compliance',
    description: 'Investigation audit trail and compliance reporting system',
    icon: ShieldCheckIcon,
    category: 'Compliance',
    status: 'active',
    endpoint: '/api/audit-trail',
    features: ['Activity Logging', 'Compliance Reports', 'Data Retention', 'Access Control', 'Legal Documentation']
  },
  {
    id: 'reporting-engine',
    name: 'Reporting Engine',
    description: 'Comprehensive reporting and data visualization capabilities',
    icon: ChartBarIcon,
    category: 'Reporting',
    status: 'active',
    endpoint: '/api/reporting-engine',
    features: ['Custom Reports', 'Data Visualization', 'Export Options', 'Automated Reporting', 'Dashboard Creation']
  }
];

const categories = Array.from(new Set(osintModules.map(m => m.category)));

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

  const filteredModules = osintModules.filter(module => {
    const matchesCategory = selectedCategory === 'all' || module.category === selectedCategory;
    const matchesSearch = module.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
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
                key={category}
                variant={selectedCategory === category ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedCategory(category)}
              >
                {category}
              </Button>
            ))}
          </div>
        </div>
      </div>

      {/* Module Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredModules.map((module, index) => {
          const Icon = module.icon;
          const isSelected = selectedModule?.id === module.id;
          
          return (
            <motion.div
              key={module.id}
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
                    <h3 className="font-semibold text-gray-900">{module.name}</h3>
                    <p className="text-sm text-gray-600">{module.category}</p>
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

      {filteredModules.length === 0 && (
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