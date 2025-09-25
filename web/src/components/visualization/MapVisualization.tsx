import React, { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  MapIcon,
  GlobeAltIcon,
  BuildingOfficeIcon,
  SignalIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';
import { Button } from '../ui/Button';
import { InvestigationResult } from '../results/InvestigationResults';

interface MapViewProps {
  results: InvestigationResult[];
  className?: string;
}

interface MapPoint {
  id: string;
  lat: number;
  lng: number;
  type: 'ip' | 'company' | 'person' | 'domain' | 'threat';
  title: string;
  description: string;
  data: any;
  severity: 'low' | 'medium' | 'high' | 'critical';
  investigation: string;
}

interface MapCluster {
  lat: number;
  lng: number;
  points: MapPoint[];
  radius: number;
}

const MapVisualization: React.FC<MapViewProps> = ({ results, className }) => {
  const [mapPoints, setMapPoints] = useState<MapPoint[]>([]);
  const [selectedPoint, setSelectedPoint] = useState<MapPoint | null>(null);
  const [mapType, setMapType] = useState<'satellite' | 'terrain' | 'roadmap'>('roadmap');
  const [showClusters, setShowClusters] = useState(true);
  const [threatFilter, setThreatFilter] = useState<'all' | 'high' | 'critical'>('all');
  const mapCanvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    processResultsForMapping();
  }, [results]);

  const processResultsForMapping = () => {
    const points: MapPoint[] = [];

    results.forEach(result => {
      switch (result.module_type) {
        case 'ip-intel':
          if (result.data.geolocation) {
            points.push({
              id: `ip_${result.id}`,
              lat: result.data.geolocation.lat || 0,
              lng: result.data.geolocation.lng || 0,
              type: 'ip',
              title: result.target,
              description: `IP: ${result.target} • ${result.data.geolocation.city}, ${result.data.geolocation.country}`,
              data: result.data.geolocation,
              severity: determineSeverity(result),
              investigation: result.investigation_name
            });
          }
          break;

        case 'company-intel':
          if (result.data.locations) {
            result.data.locations.forEach((location: string, index: number) => {
              // Mock coordinates - in real implementation, geocode addresses
              const baseCoords = getCountryCoordinates(location);
              points.push({
                id: `company_${result.id}_${index}`,
                lat: baseCoords.lat + (Math.random() - 0.5) * 0.1,
                lng: baseCoords.lng + (Math.random() - 0.5) * 0.1,
                type: 'company',
                title: result.target,
                description: `Company: ${result.target} • Location: ${location}`,
                data: { location, company: result.target },
                severity: determineSeverity(result),
                investigation: result.investigation_name
              });
            });
          }
          break;

        case 'domain-recon':
          if (result.data.server_location) {
            points.push({
              id: `domain_${result.id}`,
              lat: result.data.server_location.lat || 0,
              lng: result.data.server_location.lng || 0,
              type: 'domain',
              title: result.target,
              description: `Domain: ${result.target} • Server Location`,
              data: result.data.server_location,
              severity: determineSeverity(result),
              investigation: result.investigation_name
            });
          }
          break;

        case 'network-intel':
          if (result.data.threat_indicators) {
            result.data.threat_indicators.forEach((threat: any, index: number) => {
              if (threat.location) {
                points.push({
                  id: `threat_${result.id}_${index}`,
                  lat: threat.location.lat || 0,
                  lng: threat.location.lng || 0,
                  type: 'threat',
                  title: threat.indicator,
                  description: `Threat: ${threat.type} • Risk: ${threat.risk_level}`,
                  data: threat,
                  severity: threat.risk_level?.toLowerCase() || 'medium',
                  investigation: result.investigation_name
                });
              }
            });
          }
          break;
      }
    });

    setMapPoints(points.filter(point => point.lat !== 0 && point.lng !== 0));
  };

  const determineSeverity = (result: InvestigationResult): MapPoint['severity'] => {
    const confidence = result.metadata.confidence_score;
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.7) return 'high';
    if (confidence >= 0.5) return 'medium';
    return 'low';
  };

  const getCountryCoordinates = (location: string): { lat: number; lng: number } => {
    // Simple country/city coordinate mapping
    const coordinates: { [key: string]: { lat: number; lng: number } } = {
      'united states': { lat: 39.8283, lng: -98.5795 },
      'new york': { lat: 40.7128, lng: -74.0060 },
      'london': { lat: 51.5074, lng: -0.1278 },
      'singapore': { lat: 1.3521, lng: 103.8198 },
      'tokyo': { lat: 35.6762, lng: 139.6503 },
      'germany': { lat: 51.1657, lng: 10.4515 },
      'france': { lat: 46.2276, lng: 2.2137 },
      'canada': { lat: 56.1304, lng: -106.3468 },
      'australia': { lat: -25.2744, lng: 133.7751 },
      'brazil': { lat: -14.2350, lng: -51.9253 }
    };

    const key = location.toLowerCase();
    for (const [country, coords] of Object.entries(coordinates)) {
      if (key.includes(country)) {
        return coords;
      }
    }

    return { lat: 0, lng: 0 };
  };

  const createClusters = (points: MapPoint[]): MapCluster[] => {
    if (!showClusters) return [];

    const clusters: MapCluster[] = [];
    const processedPoints = new Set<string>();

    points.forEach(point => {
      if (processedPoints.has(point.id)) return;

      const cluster: MapCluster = {
        lat: point.lat,
        lng: point.lng,
        points: [point],
        radius: 50 // km
      };

      // Find nearby points
      points.forEach(otherPoint => {
        if (otherPoint.id !== point.id && !processedPoints.has(otherPoint.id)) {
          const distance = calculateDistance(point.lat, point.lng, otherPoint.lat, otherPoint.lng);
          if (distance <= cluster.radius) {
            cluster.points.push(otherPoint);
            processedPoints.add(otherPoint.id);
          }
        }
      });

      processedPoints.add(point.id);
      clusters.push(cluster);
    });

    return clusters;
  };

  const calculateDistance = (lat1: number, lng1: number, lat2: number, lng2: number): number => {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLng = (lng2 - lng1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLng/2) * Math.sin(dLng/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  };

  const getFilteredPoints = (): MapPoint[] => {
    return mapPoints.filter(point => {
      if (threatFilter === 'all') return true;
      if (threatFilter === 'high') return point.severity === 'high' || point.severity === 'critical';
      if (threatFilter === 'critical') return point.severity === 'critical';
      return true;
    });
  };

  const drawMap = () => {
    const canvas = mapCanvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const { width, height } = canvas;
    ctx.clearRect(0, 0, width, height);

    // Set canvas size
    canvas.width = width;
    canvas.height = height;

    // Draw world map background (simplified)
    drawWorldMap(ctx, width, height);

    // Draw points
    const filteredPoints = getFilteredPoints();
    const clusters = showClusters ? createClusters(filteredPoints) : [];

    if (showClusters && clusters.length > 0) {
      clusters.forEach(cluster => {
        const screenCoords = latLngToScreen(cluster.lat, cluster.lng, width, height);
        drawCluster(ctx, screenCoords.x, screenCoords.y, cluster.points.length, cluster.points[0].severity);
      });
    } else {
      filteredPoints.forEach(point => {
        const screenCoords = latLngToScreen(point.lat, point.lng, width, height);
        drawPoint(ctx, screenCoords.x, screenCoords.y, point);
      });
    }
  };

  const drawWorldMap = (ctx: CanvasRenderingContext2D, width: number, height: number) => {
    // Draw simplified world map outline
    ctx.fillStyle = '#f0f9ff';
    ctx.fillRect(0, 0, width, height);

    // Draw continent outlines (simplified)
    ctx.strokeStyle = '#cbd5e1';
    ctx.lineWidth = 1;

    // North America
    ctx.beginPath();
    ctx.moveTo(width * 0.2, height * 0.3);
    ctx.lineTo(width * 0.4, height * 0.3);
    ctx.lineTo(width * 0.4, height * 0.6);
    ctx.lineTo(width * 0.2, height * 0.6);
    ctx.closePath();
    ctx.stroke();
    ctx.fillStyle = '#e2e8f0';
    ctx.fill();

    // Europe
    ctx.beginPath();
    ctx.moveTo(width * 0.45, height * 0.25);
    ctx.lineTo(width * 0.55, height * 0.25);
    ctx.lineTo(width * 0.55, height * 0.45);
    ctx.lineTo(width * 0.45, height * 0.45);
    ctx.closePath();
    ctx.stroke();
    ctx.fill();

    // Asia
    ctx.beginPath();
    ctx.moveTo(width * 0.55, height * 0.2);
    ctx.lineTo(width * 0.8, height * 0.2);
    ctx.lineTo(width * 0.8, height * 0.6);
    ctx.lineTo(width * 0.55, height * 0.6);
    ctx.closePath();
    ctx.stroke();
    ctx.fill();
  };

  const latLngToScreen = (lat: number, lng: number, width: number, height: number) => {
    // Simple Mercator projection
    const x = (lng + 180) * (width / 360);
    const y = (90 - lat) * (height / 180);
    return { x, y };
  };

  const drawPoint = (ctx: CanvasRenderingContext2D, x: number, y: number, point: MapPoint) => {
    const colors = {
      ip: '#3b82f6',
      company: '#f59e0b',
      person: '#ef4444',
      domain: '#8b5cf6',
      threat: '#dc2626'
    };

    const severityColors = {
      low: '#10b981',
      medium: '#f59e0b',
      high: '#ef4444',
      critical: '#dc2626'
    };

    const color = point.type === 'threat' ? severityColors[point.severity] : colors[point.type];
    const size = point.severity === 'critical' ? 8 : point.severity === 'high' ? 6 : 4;

    // Draw outer glow for high-severity items
    if (point.severity === 'high' || point.severity === 'critical') {
      ctx.shadowColor = color;
      ctx.shadowBlur = 10;
    }

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y, size, 0, 2 * Math.PI);
    ctx.fill();

    ctx.shadowBlur = 0;

    // Draw border
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    ctx.stroke();
  };

  const drawCluster = (ctx: CanvasRenderingContext2D, x: number, y: number, count: number, severity: MapPoint['severity']) => {
    const severityColors = {
      low: '#10b981',
      medium: '#f59e0b',
      high: '#ef4444',
      critical: '#dc2626'
    };

    const size = Math.min(20, 8 + count * 2);
    
    ctx.fillStyle = severityColors[severity];
    ctx.beginPath();
    ctx.arc(x, y, size, 0, 2 * Math.PI);
    ctx.fill();

    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw count
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 12px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(count.toString(), x, y);
  };

  useEffect(() => {
    drawMap();
  }, [mapPoints, showClusters, threatFilter]);

  const handleCanvasClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = mapCanvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Find clicked point
    const filteredPoints = getFilteredPoints();
    for (const point of filteredPoints) {
      const screenCoords = latLngToScreen(point.lat, point.lng, canvas.width, canvas.height);
      const distance = Math.sqrt((x - screenCoords.x) ** 2 + (y - screenCoords.y) ** 2);
      
      if (distance <= 10) {
        setSelectedPoint(point);
        break;
      }
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Geographic Intelligence Map</h2>
            <p className="text-gray-600">{mapPoints.length} data points from {results.length} investigations</p>
          </div>
          <div className="flex space-x-2">
            <Button size="sm" variant="outline">
              <GlobeAltIcon className="w-4 h-4 mr-2" />
              Full Screen
            </Button>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium">View:</label>
            <select
              value={mapType}
              onChange={(e) => setMapType(e.target.value as any)}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm"
            >
              <option value="roadmap">Roadmap</option>
              <option value="satellite">Satellite</option>
              <option value="terrain">Terrain</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium">Filter:</label>
            <select
              value={threatFilter}
              onChange={(e) => setThreatFilter(e.target.value as any)}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm"
            >
              <option value="all">All Threats</option>
              <option value="high">High Risk+</option>
              <option value="critical">Critical Only</option>
            </select>
          </div>

          <label className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={showClusters}
              onChange={(e) => setShowClusters(e.target.checked)}
              className="rounded border-gray-300"
            />
            <span className="text-sm font-medium">Cluster Points</span>
          </label>
        </div>
      </div>

      {/* Map Container */}
      <div className="bg-white/70 backdrop-blur-sm rounded-xl shadow-lg border border-white/20 overflow-hidden">
        <div className="relative">
          <canvas
            ref={mapCanvasRef}
            width={1000}
            height={600}
            onClick={handleCanvasClick}
            className="w-full cursor-pointer"
          />
          
          {/* Legend */}
          <div className="absolute top-4 left-4 bg-white/90 backdrop-blur-sm rounded-lg p-4 shadow-lg">
            <h4 className="font-semibold mb-3">Legend</h4>
            <div className="space-y-2 text-sm">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                <span>IP Address</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                <span>Company</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                <span>Domain</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-600 rounded-full"></div>
                <span>Threat</span>
              </div>
            </div>
          </div>

          {/* Statistics */}
          <div className="absolute top-4 right-4 bg-white/90 backdrop-blur-sm rounded-lg p-4 shadow-lg">
            <h4 className="font-semibold mb-3">Statistics</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span>Total Points:</span>
                <span className="font-medium">{getFilteredPoints().length}</span>
              </div>
              <div className="flex justify-between">
                <span>Critical:</span>
                <span className="font-medium text-red-600">
                  {getFilteredPoints().filter(p => p.severity === 'critical').length}
                </span>
              </div>
              <div className="flex justify-between">
                <span>High Risk:</span>
                <span className="font-medium text-orange-600">
                  {getFilteredPoints().filter(p => p.severity === 'high').length}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Selected Point Details */}
      {selectedPoint && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20"
        >
          <div className="flex items-start justify-between mb-4">
            <div>
              <h3 className="text-xl font-bold text-gray-900">{selectedPoint.title}</h3>
              <p className="text-gray-600">{selectedPoint.description}</p>
            </div>
            <button
              onClick={() => setSelectedPoint(null)}
              className="text-gray-400 hover:text-gray-600"
            >
              ×
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <h4 className="font-semibold text-gray-900">Location</h4>
              <p className="text-sm text-gray-600">
                {selectedPoint.lat.toFixed(4)}, {selectedPoint.lng.toFixed(4)}
              </p>
            </div>
            
            <div className="space-y-2">
              <h4 className="font-semibold text-gray-900">Type</h4>
              <div className="flex items-center space-x-2">
                <div className={`w-3 h-3 rounded-full ${
                  selectedPoint.type === 'ip' ? 'bg-blue-500' :
                  selectedPoint.type === 'company' ? 'bg-yellow-500' :
                  selectedPoint.type === 'domain' ? 'bg-purple-500' :
                  'bg-red-600'
                }`} />
                <span className="text-sm capitalize">{selectedPoint.type}</span>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-semibold text-gray-900">Severity</h4>
              <div className="flex items-center space-x-2">
                {selectedPoint.severity === 'critical' && <ExclamationTriangleIcon className="w-4 h-4 text-red-600" />}
                {selectedPoint.severity === 'high' && <ExclamationTriangleIcon className="w-4 h-4 text-orange-500" />}
                {(selectedPoint.severity === 'medium' || selectedPoint.severity === 'low') && <InformationCircleIcon className="w-4 h-4 text-blue-500" />}
                <span className={`text-sm capitalize font-medium ${
                  selectedPoint.severity === 'critical' ? 'text-red-600' :
                  selectedPoint.severity === 'high' ? 'text-orange-600' :
                  selectedPoint.severity === 'medium' ? 'text-yellow-600' :
                  'text-green-600'
                }`}>
                  {selectedPoint.severity}
                </span>
              </div>
            </div>
          </div>

          {selectedPoint.data && (
            <div className="mt-4 p-4 bg-gray-50 rounded-lg">
              <h4 className="font-semibold text-gray-900 mb-2">Additional Data</h4>
              <pre className="text-xs text-gray-600 overflow-auto">
                {JSON.stringify(selectedPoint.data, null, 2)}
              </pre>
            </div>
          )}
        </motion.div>
      )}

      {/* Instructions */}
      <div className="bg-blue-50 rounded-xl p-6 border border-blue-200">
        <h3 className="font-semibold text-blue-900 mb-2">Interactive Map Features</h3>
        <ul className="text-sm text-blue-700 space-y-1">
          <li>• Click on any point to view detailed information</li>
          <li>• Use filters to focus on specific threat levels</li>
          <li>• Toggle clustering to group nearby points</li>
          <li>• Change map type for different visual perspectives</li>
          <li>• Full integration with Google Maps/Leaflet would provide zoom, pan, and satellite imagery</li>
        </ul>
      </div>
    </div>
  );
};

export default MapVisualization;