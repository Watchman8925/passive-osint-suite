import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ShieldCheckIcon, 
  GlobeAltIcon, 
  LockClosedIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ArrowPathIcon,
  EyeSlashIcon
} from '@heroicons/react/24/outline';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import osintAPI from '../../services/osintAPI';
import toast from 'react-hot-toast';

interface AnonymityStatus {
  tor: {
    active: boolean;
    exitNode?: string;
    country?: string;
    circuitBuilt: boolean;
  };
  doh: {
    active: boolean;
    provider?: string;
  };
  anonymityGrid: {
    active: boolean;
    peers?: number;
  };
  vpn: {
    active: boolean;
    location?: string;
  };
}

const AnonymityStatusPanel: React.FC = () => {
  const [status, setStatus] = useState<AnonymityStatus>({
    tor: { active: false, circuitBuilt: false },
    doh: { active: false },
    anonymityGrid: { active: false },
    vpn: { active: false }
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStatus = async () => {
    try {
      setRefreshing(true);
      const torStatus = await osintAPI.getTorStatus();
      const systemStatus = await osintAPI.getSystemStatus();
      
      setStatus({
        tor: {
          active: torStatus.active,
          exitNode: torStatus.exitNode,
          country: torStatus.country,
          circuitBuilt: torStatus.active
        },
        doh: {
          active: systemStatus.doh?.active || false,
          provider: systemStatus.doh?.provider
        },
        anonymityGrid: {
          active: systemStatus.anonymity_grid?.active || false,
          peers: systemStatus.anonymity_grid?.peers
        },
        vpn: {
          active: systemStatus.vpn?.active || false,
          location: systemStatus.vpn?.location
        }
      });
    } catch (error) {
      console.error('Failed to fetch anonymity status:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    // Refresh status every 30 seconds
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleTorToggle = async () => {
    if (status.tor.active) {
      const success = await osintAPI.disableTor();
      if (success) {
        setStatus(prev => ({ ...prev, tor: { ...prev.tor, active: false } }));
      }
    } else {
      const success = await osintAPI.enableTor();
      if (success) {
        setStatus(prev => ({ ...prev, tor: { ...prev.tor, active: true } }));
      }
    }
  };

  const handleNewTorIdentity = async () => {
    const success = await osintAPI.newTorIdentity();
    if (success) {
      await fetchStatus();
    }
  };

  const getSecurityLevel = () => {
    let level = 0;
    if (status.tor.active) level += 40;
    if (status.doh.active) level += 20;
    if (status.anonymityGrid.active) level += 25;
    if (status.vpn.active) level += 15;
    return level;
  };

  const securityLevel = getSecurityLevel();
  const securityColor = securityLevel >= 80 ? 'green' : securityLevel >= 50 ? 'yellow' : 'red';

  if (loading) {
    return (
      <div className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="space-y-3">
            <div className="h-3 bg-gray-200 rounded"></div>
            <div className="h-3 bg-gray-200 rounded w-5/6"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-white/70 backdrop-blur-sm rounded-xl p-6 shadow-lg border border-white/20"
    >
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <EyeSlashIcon className="w-6 h-6 text-purple-600" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Anonymity Status</h3>
            <p className="text-sm text-gray-600">Security Level: {securityLevel}%</p>
          </div>
        </div>
        <Button 
          size="sm" 
          variant="outline" 
          onClick={fetchStatus}
          disabled={refreshing}
        >
          <ArrowPathIcon className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
        </Button>
      </div>

      {/* Security Level Progress */}
      <div className="mb-6">
        <div className="flex justify-between text-sm mb-2">
          <span className="text-gray-600">Security Level</span>
          <span className={`font-medium ${securityColor === 'green' ? 'text-green-600' : securityColor === 'yellow' ? 'text-yellow-600' : 'text-red-600'}`}>
            {securityLevel}%
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <motion.div 
            className={`h-2 rounded-full ${securityColor === 'green' ? 'bg-green-500' : securityColor === 'yellow' ? 'bg-yellow-500' : 'bg-red-500'}`}
            initial={{ width: 0 }}
            animate={{ width: `${securityLevel}%` }}
            transition={{ duration: 1, ease: "easeOut" }}
          />
        </div>
      </div>

      {/* Tor Status */}
      <div className="space-y-4">
        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div className="flex items-center space-x-3">
            <div className={`w-3 h-3 rounded-full ${status.tor.active ? 'bg-green-500' : 'bg-gray-400'}`} />
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-medium">Tor Network</span>
                {status.tor.active && (
                  <Badge className="bg-green-100 text-green-800">Active</Badge>
                )}
              </div>
              {status.tor.active && status.tor.exitNode && (
                <p className="text-sm text-gray-600">
                  Exit: {status.tor.exitNode} ({status.tor.country})
                </p>
              )}
            </div>
          </div>
          <div className="flex space-x-2">
            {status.tor.active && (
              <Button size="sm" variant="outline" onClick={handleNewTorIdentity}>
                New Identity
              </Button>
            )}
            <Button 
              size="sm" 
              variant={status.tor.active ? "destructive" : "primary"}
              onClick={handleTorToggle}
            >
              {status.tor.active ? 'Disable' : 'Enable'}
            </Button>
          </div>
        </div>

        {/* DNS over HTTPS */}
        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div className="flex items-center space-x-3">
            <div className={`w-3 h-3 rounded-full ${status.doh.active ? 'bg-green-500' : 'bg-gray-400'}`} />
            <div>
              <div className="flex items-center space-x-2">
                <GlobeAltIcon className="w-4 h-4" />
                <span className="font-medium">DNS over HTTPS</span>
                {status.doh.active && (
                  <Badge className="bg-blue-100 text-blue-800">Active</Badge>
                )}
              </div>
              {status.doh.provider && (
                <p className="text-sm text-gray-600">Provider: {status.doh.provider}</p>
              )}
            </div>
          </div>
          <CheckCircleIcon className={`w-5 h-5 ${status.doh.active ? 'text-green-500' : 'text-gray-400'}`} />
        </div>

        {/* Anonymity Grid */}
        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div className="flex items-center space-x-3">
            <div className={`w-3 h-3 rounded-full ${status.anonymityGrid.active ? 'bg-green-500' : 'bg-gray-400'}`} />
            <div>
              <div className="flex items-center space-x-2">
                <ShieldCheckIcon className="w-4 h-4" />
                <span className="font-medium">Anonymity Grid</span>
                {status.anonymityGrid.active && (
                  <Badge className="bg-purple-100 text-purple-800">Active</Badge>
                )}
              </div>
              {status.anonymityGrid.peers && (
                <p className="text-sm text-gray-600">
                  Connected peers: {status.anonymityGrid.peers}
                </p>
              )}
            </div>
          </div>
          <CheckCircleIcon className={`w-5 h-5 ${status.anonymityGrid.active ? 'text-green-500' : 'text-gray-400'}`} />
        </div>

        {/* VPN Status */}
        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div className="flex items-center space-x-3">
            <div className={`w-3 h-3 rounded-full ${status.vpn.active ? 'bg-green-500' : 'bg-gray-400'}`} />
            <div>
              <div className="flex items-center space-x-2">
                <LockClosedIcon className="w-4 h-4" />
                <span className="font-medium">VPN</span>
                {status.vpn.active && (
                  <Badge className="bg-indigo-100 text-indigo-800">Active</Badge>
                )}
              </div>
              {status.vpn.location && (
                <p className="text-sm text-gray-600">Location: {status.vpn.location}</p>
              )}
            </div>
          </div>
          <CheckCircleIcon className={`w-5 h-5 ${status.vpn.active ? 'text-green-500' : 'text-gray-400'}`} />
        </div>
      </div>

      {/* Security Recommendations */}
      {securityLevel < 80 && (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg"
        >
          <div className="flex items-start space-x-3">
            <ExclamationTriangleIcon className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="text-sm font-medium text-yellow-800">Security Recommendations</h4>
              <ul className="text-sm text-yellow-700 mt-1 space-y-1">
                {!status.tor.active && <li>• Enable Tor for maximum anonymity</li>}
                {!status.doh.active && <li>• Enable DNS over HTTPS to prevent DNS leaks</li>}
                {!status.anonymityGrid.active && <li>• Connect to anonymity grid for query mixing</li>}
                {!status.vpn.active && <li>• Consider using a VPN for additional protection</li>}
              </ul>
            </div>
          </div>
        </motion.div>
      )}
    </motion.div>
  );
};

export default AnonymityStatusPanel;