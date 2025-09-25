import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  ChartBarIcon,
  MapIcon,
  ShareIcon,
  GlobeAltIcon,
  BuildingOfficeIcon,
  UserIcon,
  ServerIcon,
  ClockIcon,
  TagIcon
} from '@heroicons/react/24/outline';
import { Button } from '../ui/Button';
import { InvestigationResult } from '../results/InvestigationResults';

interface VisualizationProps {
  result: InvestigationResult;
  className?: string;
}

interface NetworkNode {
  id: string;
  label: string;
  type: 'domain' | 'ip' | 'email' | 'company' | 'person' | 'location';
  data: any;
  x?: number;
  y?: number;
  connections: string[];
}

interface NetworkEdge {
  source: string;
  target: string;
  relationship: string;
  weight: number;
}

interface ChartData {
  labels: string[];
  datasets: {
    label: string;
    data: number[];
    backgroundColor: string[];
    borderColor: string[];
  }[];
}

const DataVisualization: React.FC<VisualizationProps> = ({ result, className }) => {
  const [activeTab, setActiveTab] = useState<'network' | 'charts' | 'timeline' | 'geographic'>('network');
  const [networkData, setNetworkData] = useState<{ nodes: NetworkNode[], edges: NetworkEdge[] }>({ nodes: [], edges: [] });
  const [chartData, setChartData] = useState<ChartData | null>(null);
  const [timelineData, setTimelineData] = useState<any[]>([]);
  const [geographicData, setGeographicData] = useState<any[]>([]);
  
  const networkCanvasRef = useRef<HTMLCanvasElement>(null);
  const chartCanvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    processDataForVisualization();
  }, [result]);

  const processDataForVisualization = () => {
    // Process network data
    const nodes: NetworkNode[] = [];
    const edges: NetworkEdge[] = [];

    // Create main target node
    nodes.push({
      id: 'target',
      label: result.target,
      type: getNodeType(result.module_type),
      data: result.data,
      connections: []
    });

    // Process data based on module type
    switch (result.module_type) {
      case 'domain-recon':
        processDomainData(result.data, nodes, edges);
        break;
      case 'company-intel':
        processCompanyData(result.data, nodes, edges);
        break;
      case 'email-intel':
        processEmailData(result.data, nodes, edges);
        break;
      case 'ip-intel':
        processIPData(result.data, nodes, edges);
        break;
      default:
        processGenericData(result.data, nodes, edges);
    }

    setNetworkData({ nodes, edges });

    // Process chart data
    const charts = generateChartData(result);
    setChartData(charts);

    // Process timeline data
    const timeline = generateTimelineData(result);
    setTimelineData(timeline);

    // Process geographic data
    const geographic = generateGeographicData(result);
    setGeographicData(geographic);
  };

  const getNodeType = (moduleType: string): NetworkNode['type'] => {
    switch (moduleType) {
      case 'domain-recon': return 'domain';
      case 'company-intel': return 'company';
      case 'email-intel': return 'email';
      case 'ip-intel': return 'ip';
      default: return 'domain';
    }
  };

  const processDomainData = (data: any, nodes: NetworkNode[], edges: NetworkEdge[]) => {
    // Add DNS records
    if (data.dns_records) {
      Object.entries(data.dns_records).forEach(([type, records]: [string, any]) => {
        if (Array.isArray(records)) {
          records.forEach((record, index) => {
            const nodeId = `dns_${type}_${index}`;
            nodes.push({
              id: nodeId,
              label: `${type}: ${record}`,
              type: type === 'A' ? 'ip' : 'domain',
              data: { record, type },
              connections: ['target']
            });
            edges.push({
              source: 'target',
              target: nodeId,
              relationship: `DNS ${type}`,
              weight: 1
            });
          });
        }
      });
    }

    // Add subdomains
    if (data.subdomains) {
      data.subdomains.forEach((subdomain: string, index: number) => {
        const nodeId = `subdomain_${index}`;
        nodes.push({
          id: nodeId,
          label: subdomain,
          type: 'domain',
          data: { subdomain },
          connections: ['target']
        });
        edges.push({
          source: 'target',
          target: nodeId,
          relationship: 'Subdomain',
          weight: 1
        });
      });
    }
  };

  const processCompanyData = (data: any, nodes: NetworkNode[], edges: NetworkEdge[]) => {
    // Add executives
    if (data.executives) {
      data.executives.forEach((exec: any, index: number) => {
        const nodeId = `exec_${index}`;
        nodes.push({
          id: nodeId,
          label: exec.name,
          type: 'person',
          data: exec,
          connections: ['target']
        });
        edges.push({
          source: 'target',
          target: nodeId,
          relationship: exec.title || 'Executive',
          weight: 2
        });
      });
    }

    // Add locations
    if (data.locations) {
      data.locations.forEach((location: string, index: number) => {
        const nodeId = `location_${index}`;
        nodes.push({
          id: nodeId,
          label: location,
          type: 'location',
          data: { location },
          connections: ['target']
        });
        edges.push({
          source: 'target',
          target: nodeId,
          relationship: 'Location',
          weight: 1
        });
      });
    }
  };

  const processEmailData = (data: any, nodes: NetworkNode[], edges: NetworkEdge[]) => {
    // Add breach data
    if (data.breach_data) {
      data.breach_data.forEach((breach: any, index: number) => {
        const nodeId = `breach_${index}`;
        nodes.push({
          id: nodeId,
          label: breach.source,
          type: 'domain',
          data: breach,
          connections: ['target']
        });
        edges.push({
          source: 'target',
          target: nodeId,
          relationship: 'Data Breach',
          weight: 3
        });
      });
    }

    // Add social links
    if (data.social_links) {
      data.social_links.forEach((link: string, index: number) => {
        const nodeId = `social_${index}`;
        const platform = link.split('.')[0].replace('https://', '').replace('http://', '');
        nodes.push({
          id: nodeId,
          label: platform,
          type: 'domain',
          data: { link },
          connections: ['target']
        });
        edges.push({
          source: 'target',
          target: nodeId,
          relationship: 'Social Media',
          weight: 2
        });
      });
    }
  };

  const processIPData = (data: any, nodes: NetworkNode[], edges: NetworkEdge[]) => {
    // Add ISP information
    if (data.isp_info) {
      const ispNode = 'isp_info';
      nodes.push({
        id: ispNode,
        label: data.isp_info.name || 'ISP',
        type: 'company',
        data: data.isp_info,
        connections: ['target']
      });
      edges.push({
        source: 'target',
        target: ispNode,
        relationship: 'ISP',
        weight: 2
      });
    }

    // Add geolocation
    if (data.geolocation) {
      const locationNode = 'geolocation';
      nodes.push({
        id: locationNode,
        label: `${data.geolocation.city}, ${data.geolocation.country}`,
        type: 'location',
        data: data.geolocation,
        connections: ['target']
      });
      edges.push({
        source: 'target',
        target: locationNode,
        relationship: 'Located in',
        weight: 1
      });
    }
  };

  const processGenericData = (data: any, nodes: NetworkNode[], edges: NetworkEdge[]) => {
    // Generic processing for unknown module types
    Object.entries(data).forEach(([key, value], index) => {
      if (Array.isArray(value) && value.length > 0) {
        value.forEach((item, itemIndex) => {
          const nodeId = `${key}_${itemIndex}`;
          nodes.push({
            id: nodeId,
            label: typeof item === 'string' ? item : JSON.stringify(item),
            type: 'domain',
            data: item,
            connections: ['target']
          });
          edges.push({
            source: 'target',
            target: nodeId,
            relationship: key,
            weight: 1
          });
        });
      }
    });
  };

  const generateChartData = (result: InvestigationResult): ChartData => {
    const moduleTypeData: { [key: string]: number } = {};
    const statusData: { [key: string]: number } = {};
    const confidenceData: number[] = [];

    // Mock data for demonstration - in real implementation, this would process multiple results
    return {
      labels: ['DNS Records', 'Subdomains', 'SSL Info', 'WHOIS Data', 'Security Headers'],
      datasets: [{
        label: 'Data Points Found',
        data: [12, 8, 3, 5, 7],
        backgroundColor: [
          'rgba(147, 51, 234, 0.7)',
          'rgba(59, 130, 246, 0.7)',
          'rgba(16, 185, 129, 0.7)',
          'rgba(245, 158, 11, 0.7)',
          'rgba(239, 68, 68, 0.7)'
        ],
        borderColor: [
          'rgba(147, 51, 234, 1)',
          'rgba(59, 130, 246, 1)',
          'rgba(16, 185, 129, 1)',
          'rgba(245, 158, 11, 1)',
          'rgba(239, 68, 68, 1)'
        ]
      }]
    };
  };

  const generateTimelineData = (result: InvestigationResult): any[] => {
    const events = [];
    
    // Add investigation start event
    events.push({
      timestamp: result.timestamp,
      event: 'Investigation Started',
      type: 'investigation',
      description: `Started ${result.module_type} investigation for ${result.target}`
    });

    // Process data for timeline events based on module type
    if (result.module_type === 'domain-recon' && result.data.domain_info) {
      if (result.data.domain_info.creation_date) {
        events.push({
          timestamp: result.data.domain_info.creation_date,
          event: 'Domain Registered',
          type: 'domain',
          description: `Domain ${result.target} was registered`
        });
      }
    }

    if (result.module_type === 'email-intel' && result.data.breach_data) {
      result.data.breach_data.forEach((breach: any) => {
        events.push({
          timestamp: breach.date,
          event: 'Data Breach',
          type: 'breach',
          description: `Email found in ${breach.source} breach`
        });
      });
    }

    return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  };

  const generateGeographicData = (result: InvestigationResult): any[] => {
    const locations = [];

    if (result.module_type === 'ip-intel' && result.data.geolocation) {
      locations.push({
        lat: result.data.geolocation.lat,
        lng: result.data.geolocation.lng,
        label: result.target,
        type: 'IP Location',
        data: result.data.geolocation
      });
    }

    if (result.module_type === 'company-intel' && result.data.locations) {
      result.data.locations.forEach((location: string, index: number) => {
        // Mock coordinates - in real implementation, geocode the addresses
        locations.push({
          lat: 40.7128 + (index * 0.1),
          lng: -74.0060 + (index * 0.1),
          label: location,
          type: 'Company Location',
          data: { address: location }
        });
      });
    }

    return locations;
  };

  // Network visualization using Canvas
  const drawNetwork = () => {
    const canvas = networkCanvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const { width, height } = canvas;
    ctx.clearRect(0, 0, width, height);

    // Set canvas size
    canvas.width = width;
    canvas.height = height;

    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.3;

    // Position nodes in a circle around the center
    networkData.nodes.forEach((node, index) => {
      if (node.id === 'target') {
        node.x = centerX;
        node.y = centerY;
      } else {
        const angle = (index * 2 * Math.PI) / (networkData.nodes.length - 1);
        node.x = centerX + radius * Math.cos(angle);
        node.y = centerY + radius * Math.sin(angle);
      }
    });

    // Draw edges
    ctx.strokeStyle = '#cbd5e1';
    ctx.lineWidth = 1;
    networkData.edges.forEach(edge => {
      const sourceNode = networkData.nodes.find(n => n.id === edge.source);
      const targetNode = networkData.nodes.find(n => n.id === edge.target);
      
      if (sourceNode && targetNode && sourceNode.x && sourceNode.y && targetNode.x && targetNode.y) {
        ctx.beginPath();
        ctx.moveTo(sourceNode.x, sourceNode.y);
        ctx.lineTo(targetNode.x, targetNode.y);
        ctx.stroke();
      }
    });

    // Draw nodes
    networkData.nodes.forEach(node => {
      if (node.x && node.y) {
        const color = getNodeColor(node.type);
        const size = node.id === 'target' ? 12 : 8;

        // Draw node circle
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
        ctx.fill();

        // Draw node border
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Draw label
        ctx.fillStyle = '#374151';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(node.label.length > 15 ? node.label.substring(0, 15) + '...' : node.label, node.x, node.y + size + 15);
      }
    });
  };

  const getNodeColor = (type: NetworkNode['type']): string => {
    const colors = {
      domain: '#8b5cf6',
      ip: '#3b82f6',
      email: '#10b981',
      company: '#f59e0b',
      person: '#ef4444',
      location: '#06b6d4'
    };
    return colors[type] || '#6b7280';
  };

  useEffect(() => {
    if (activeTab === 'network') {
      drawNetwork();
    }
  }, [networkData, activeTab]);

  const renderTabContent = () => {
    switch (activeTab) {
      case 'network':
        return (
          <div className="relative">
            <canvas
              ref={networkCanvasRef}
              width={800}
              height={600}
              className="border border-gray-200 rounded-lg bg-white w-full max-w-4xl mx-auto"
            />
            <div className="mt-4 flex justify-center space-x-4 text-sm">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                <span>Domain</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                <span>IP Address</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                <span>Email</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                <span>Company</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                <span>Person</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-cyan-500 rounded-full"></div>
                <span>Location</span>
              </div>
            </div>
          </div>
        );

      case 'charts':
        return (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg border">
              <h3 className="text-lg font-semibold mb-4">Data Distribution</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {chartData && (
                  <div className="space-y-4">
                    {chartData.labels.map((label, index) => (
                      <div key={label} className="flex items-center justify-between">
                        <span className="text-sm font-medium">{label}</span>
                        <div className="flex items-center space-x-2">
                          <div className="w-20 bg-gray-200 rounded-full h-2">
                            <div
                              className="h-2 rounded-full"
                              style={{
                                backgroundColor: chartData.datasets[0].backgroundColor[index],
                                width: `${(chartData.datasets[0].data[index] / Math.max(...chartData.datasets[0].data)) * 100}%`
                              }}
                            />
                          </div>
                          <span className="text-sm text-gray-600">{chartData.datasets[0].data[index]}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                <div className="space-y-4">
                  <h4 className="font-semibold">Investigation Metrics</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-purple-50 p-4 rounded-lg">
                      <p className="text-sm text-purple-600">Confidence Score</p>
                      <p className="text-2xl font-bold text-purple-700">
                        {(result.metadata.confidence_score * 100).toFixed(0)}%
                      </p>
                    </div>
                    <div className="bg-blue-50 p-4 rounded-lg">
                      <p className="text-sm text-blue-600">Items Found</p>
                      <p className="text-2xl font-bold text-blue-700">{result.metadata.items_found}</p>
                    </div>
                    <div className="bg-green-50 p-4 rounded-lg">
                      <p className="text-sm text-green-600">Data Sources</p>
                      <p className="text-2xl font-bold text-green-700">{result.metadata.data_sources.length}</p>
                    </div>
                    <div className="bg-yellow-50 p-4 rounded-lg">
                      <p className="text-sm text-yellow-600">Execution Time</p>
                      <p className="text-2xl font-bold text-yellow-700">{result.metadata.execution_time}s</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      case 'timeline':
        return (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Investigation Timeline</h3>
            <div className="space-y-4">
              {timelineData.map((event, index) => (
                <div key={index} className="flex items-start space-x-4 p-4 bg-white rounded-lg border">
                  <div className="flex-shrink-0">
                    <div className={`w-3 h-3 rounded-full ${
                      event.type === 'investigation' ? 'bg-purple-500' :
                      event.type === 'domain' ? 'bg-blue-500' :
                      event.type === 'breach' ? 'bg-red-500' :
                      'bg-gray-500'
                    }`} />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium">{event.event}</h4>
                      <span className="text-sm text-gray-500">
                        {new Date(event.timestamp).toLocaleDateString()}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mt-1">{event.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'geographic':
        return (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Geographic Distribution</h3>
            <div className="bg-white rounded-lg border p-6">
              <div className="space-y-4">
                {geographicData.length > 0 ? (
                  geographicData.map((location, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <div>
                        <h4 className="font-medium">{location.label}</h4>
                        <p className="text-sm text-gray-600">{location.type}</p>
                      </div>
                      <div className="text-sm text-gray-500">
                        {location.lat.toFixed(4)}, {location.lng.toFixed(4)}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8">
                    <MapIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <p className="text-gray-500">No geographic data available for this investigation</p>
                  </div>
                )}
              </div>
              {geographicData.length > 0 && (
                <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                  <p className="text-sm text-blue-700">
                    💡 Interactive map visualization would be displayed here using a mapping library like Leaflet or Google Maps
                  </p>
                </div>
              )}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Data Visualization</h2>
            <p className="text-gray-600">{result.investigation_name} • {result.target}</p>
          </div>
          <div className="flex space-x-2">
            <Button size="sm" variant="outline">
              <ShareIcon className="w-4 h-4 mr-2" />
              Share
            </Button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            {[
              { id: 'network', label: 'Network Graph', icon: ShareIcon },
              { id: 'charts', label: 'Charts', icon: ChartBarIcon },
              { id: 'timeline', label: 'Timeline', icon: ClockIcon },
              { id: 'geographic', label: 'Geographic', icon: MapIcon }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                    activeTab === tab.id
                      ? 'border-purple-500 text-purple-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Tab Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20"
      >
        {renderTabContent()}
      </motion.div>
    </div>
  );
};

export default DataVisualization;