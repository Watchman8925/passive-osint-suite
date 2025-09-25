import React, { useState, useEffect, useRef } from 'react';
import { AlertTriangle, Bell, BellOff, CheckCircle, X, Clock, Zap } from 'lucide-react';
import { securityAPI, SecurityAlert } from '../../services/securityAPI';

interface RealTimeAlertsProps {
  className?: string;
}

export const RealTimeAlerts: React.FC<RealTimeAlertsProps> = ({ className = '' }) => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [showNotification, setShowNotification] = useState(false);
  const [latestAlert, setLatestAlert] = useState<SecurityAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const notificationTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    loadAlerts();
    setupWebSocket();

    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (notificationTimeoutRef.current) {
        clearTimeout(notificationTimeoutRef.current);
      }
    };
  }, []);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const alertsData = await securityAPI.getSecurityAlerts();
      setAlerts(alertsData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  const setupWebSocket = () => {
    try {
      // Connect to WebSocket for real-time alerts
      const wsUrl = `ws://${window.location.host}/ws/security-alerts`;
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        console.log('Connected to security alerts WebSocket');
      };

      wsRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'security_alert') {
            handleNewAlert(data.alert);
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };

      wsRef.current.onclose = () => {
        console.log('Security alerts WebSocket connection closed');
        // Attempt to reconnect after 5 seconds
        setTimeout(setupWebSocket, 5000);
      };

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    } catch (err) {
      console.error('Failed to setup WebSocket:', err);
      setError('Real-time alerts unavailable');
    }
  };

  const handleNewAlert = (alert: SecurityAlert) => {
    setAlerts(prev => [alert, ...prev.slice(0, 49)]); // Keep last 50 alerts
    setLatestAlert(alert);
    setShowNotification(true);

    // Show browser notification if enabled
    if (notificationsEnabled && 'Notification' in window && Notification.permission === 'granted') {
      new Notification(`Security Alert: ${alert.alert_type}`, {
        body: alert.description,
        icon: '/favicon.ico',
        tag: `security-alert-${alert.id}`
      });
    }

    // Auto-hide notification after 5 seconds
    if (notificationTimeoutRef.current) {
      clearTimeout(notificationTimeoutRef.current);
    }
    notificationTimeoutRef.current = setTimeout(() => {
      setShowNotification(false);
    }, 5000);
  };

  const handleResolveAlert = async (alertId: string) => {
    try {
      await securityAPI.resolveAlert(alertId);
      setAlerts(prev => prev.map(alert =>
        alert.id === alertId ? { ...alert, status: 'resolved' } : alert
      ));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to resolve alert');
    }
  };

  const toggleNotifications = () => {
    if (!notificationsEnabled && 'Notification' in window) {
      if (Notification.permission === 'granted') {
        setNotificationsEnabled(true);
      } else if (Notification.permission === 'default') {
        Notification.requestPermission().then(permission => {
          setNotificationsEnabled(permission === 'granted');
        });
      }
    } else {
      setNotificationsEnabled(!notificationsEnabled);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'border-red-500 bg-red-50';
      case 'high': return 'border-orange-500 bg-orange-50';
      case 'medium': return 'border-yellow-500 bg-yellow-50';
      case 'low': return 'border-green-500 bg-green-50';
      default: return 'border-gray-500 bg-gray-50';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <Zap className="h-5 w-5 text-red-600" />;
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-orange-600" />;
      case 'medium':
        return <AlertTriangle className="h-5 w-5 text-yellow-600" />;
      case 'low':
        return <AlertTriangle className="h-5 w-5 text-green-600" />;
      default:
        return <AlertTriangle className="h-5 w-5 text-gray-600" />;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return date.toLocaleDateString();
  };

  if (loading) {
    return (
      <div className={`flex items-center justify-center h-64 ${className}`}>
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <Bell className="h-8 w-8 text-blue-600 mr-3" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Real-Time Security Alerts</h1>
            <p className="text-gray-600">Live security monitoring and notifications</p>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={toggleNotifications}
            className={`flex items-center px-4 py-2 rounded-lg transition-colors ${
              notificationsEnabled
                ? 'bg-green-100 text-green-700 hover:bg-green-200'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            {notificationsEnabled ? (
              <Bell className="h-4 w-4 mr-2" />
            ) : (
              <BellOff className="h-4 w-4 mr-2" />
            )}
            {notificationsEnabled ? 'Notifications On' : 'Notifications Off'}
          </button>
          <button
            onClick={loadAlerts}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <span className="text-red-800">{error}</span>
        </div>
      )}

      {/* Live Notification Banner */}
      {showNotification && latestAlert && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center">
            {getSeverityIcon(latestAlert.severity)}
            <div className="ml-3">
              <p className="text-sm font-medium text-blue-900">New Security Alert</p>
              <p className="text-sm text-blue-700">{latestAlert.alert_type}: {latestAlert.description}</p>
            </div>
          </div>
          <button
            onClick={() => setShowNotification(false)}
            className="text-blue-600 hover:text-blue-800"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Connection Status */}
      <div className="bg-white rounded-lg shadow p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <div className={`w-3 h-3 rounded-full mr-3 ${
              wsRef.current?.readyState === WebSocket.OPEN ? 'bg-green-500' : 'bg-red-500'
            }`}></div>
            <span className="text-sm font-medium text-gray-700">
              Real-time Connection: {wsRef.current?.readyState === WebSocket.OPEN ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div className="text-sm text-gray-500">
            {alerts.length} total alerts
          </div>
        </div>
      </div>

      {/* Alerts List */}
      <div className="space-y-4">
        {alerts.length === 0 ? (
          <div className="bg-white rounded-lg shadow p-8 text-center">
            <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">All Clear</h3>
            <p className="text-gray-600">No security alerts at this time</p>
          </div>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.id}
              className={`border-l-4 rounded-lg p-4 bg-white shadow ${getSeverityColor(alert.severity)}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center mb-2">
                    {getSeverityIcon(alert.severity)}
                    <span className="ml-2 font-medium text-gray-900">{alert.alert_type}</span>
                    <span className={`ml-2 inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      alert.severity === 'critical' ? 'bg-red-100 text-red-800' :
                      alert.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                      alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {alert.severity}
                    </span>
                    <span className={`ml-2 inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      alert.status === 'resolved' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {alert.status}
                    </span>
                  </div>

                  <p className="text-sm text-gray-700 mb-2">{alert.description}</p>

                  <div className="flex items-center text-xs text-gray-500 space-x-4">
                    <span className="flex items-center">
                      <Clock className="h-3 w-3 mr-1" />
                      {formatTimestamp(alert.timestamp)}
                    </span>
                    {alert.user_id && (
                      <span>User: {alert.user_id}</span>
                    )}
                    {alert.metadata && Object.keys(alert.metadata).length > 0 && (
                      <span>Details: {Object.keys(alert.metadata).length} fields</span>
                    )}
                  </div>
                </div>

                {alert.status !== 'resolved' && (
                  <button
                    onClick={() => handleResolveAlert(alert.id)}
                    className="ml-4 px-3 py-1 bg-green-600 text-white text-sm rounded hover:bg-green-700 transition-colors"
                  >
                    Resolve
                  </button>
                )}
              </div>

              {/* Alert Metadata */}
              {alert.metadata && Object.keys(alert.metadata).length > 0 && (
                <div className="mt-3 pt-3 border-t border-gray-200">
                  <details className="text-sm">
                    <summary className="cursor-pointer text-gray-600 hover:text-gray-800">
                      View Details
                    </summary>
                    <div className="mt-2 bg-gray-50 p-3 rounded text-xs font-mono">
                      {Object.entries(alert.metadata).map(([key, value]) => (
                        <div key={key} className="mb-1">
                          <span className="font-medium">{key}:</span> {String(value)}
                        </div>
                      ))}
                    </div>
                  </details>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};