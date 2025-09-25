import React, { useState, useEffect } from 'react';
import { Shield, Users, AlertTriangle, Activity, Database, Lock, Settings, FileText, Bell, Eye } from 'lucide-react';
import { securityAPI, SecurityReport, SecurityEvent, SecurityAlert, User, SecuritySettings } from '../../services/securityAPI';
import { UserManagement } from './UserManagement';
import { DataClassification } from './DataClassification';
import { SecuritySettingsComponent } from './SecuritySettings';
import { RealTimeAlerts } from './RealTimeAlerts';
import { SecurityEventDetails } from './SecurityEventDetails';

interface SecurityDashboardProps {
  className?: string;
}

type TabType = 'dashboard' | 'alerts' | 'users' | 'data' | 'settings';

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({ className = '' }) => {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showEventDetails, setShowEventDetails] = useState(false);

  useEffect(() => {
    if (activeTab === 'dashboard') {
      loadSecurityData();
    }
  }, [activeTab]);

  const loadSecurityData = async () => {
    try {
      setLoading(true);
      const [reportData, eventsData, alertsData, usersData] = await Promise.all([
        securityAPI.getSecurityReport(),
        securityAPI.getSecurityEvents(50),
        securityAPI.getSecurityAlerts(),
        securityAPI.getUsers()
      ]);

      setReport(reportData);
      setEvents(eventsData);
      setAlerts(alertsData);
      setUsers(usersData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security data');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critical': return 'text-red-600';
      case 'high': return 'text-orange-600';
      case 'medium': return 'text-yellow-600';
      case 'low': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const tabs = [
    { id: 'dashboard' as TabType, name: 'Dashboard', icon: Shield },
    { id: 'alerts' as TabType, name: 'Real-Time Alerts', icon: Bell },
    { id: 'users' as TabType, name: 'User Management', icon: Users },
    { id: 'data' as TabType, name: 'Data Classification', icon: FileText },
    { id: 'settings' as TabType, name: 'Settings', icon: Settings },
  ];

  const renderTabContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return renderDashboardContent();
      case 'alerts':
        return <RealTimeAlerts />;
      case 'users':
        return <UserManagement />;
      case 'data':
        return <DataClassification />;
      case 'settings':
        return <SecuritySettingsComponent />;
      default:
        return renderDashboardContent();
    }
  };

  const renderDashboardContent = () => {
    if (loading) {
      return (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      );
    }

    if (error) {
      return (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-600 mr-2" />
            <span className="text-red-800">Error: {error}</span>
          </div>
        </div>
      );
    }

    return (
      <>
        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <Activity className="h-8 w-8 text-blue-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Total Events</p>
                <p className="text-2xl font-bold text-gray-900">{report?.total_events || 0}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <AlertTriangle className="h-8 w-8 text-orange-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Active Alerts</p>
                <p className="text-2xl font-bold text-gray-900">{report?.alerts_summary.unresolved_alerts || 0}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <Users className="h-8 w-8 text-green-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Active Users</p>
                <p className="text-2xl font-bold text-gray-900">{users.filter(u => u.is_active).length}</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <Database className="h-8 w-8 text-purple-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Risk Level</p>
                <p className={`text-2xl font-bold ${getRiskColor(report?.risk_assessment || 'low')}`}>
                  {report?.risk_assessment || 'Unknown'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Events */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-medium text-gray-900">Recent Security Events</h2>
            <button
              onClick={() => setShowEventDetails(true)}
              className="flex items-center px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
            >
              <Eye className="h-4 w-4 mr-1" />
              View All
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Event Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {events.slice(0, 10).map((event) => (
                  <tr key={event.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {event.event_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(event.severity)}`}>
                        {event.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {event.user_id || 'System'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Active Alerts */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">Active Security Alerts</h2>
          </div>
          <div className="p-6">
            {alerts.filter(alert => alert.status !== 'resolved').length === 0 ? (
              <p className="text-gray-500 text-center py-4">No active alerts</p>
            ) : (
              <div className="space-y-4">
                {alerts.filter(alert => alert.status !== 'resolved').slice(0, 5).map((alert) => (
                  <div key={alert.id} className="border border-orange-200 rounded-lg p-4 bg-orange-50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center">
                          <AlertTriangle className="h-5 w-5 text-orange-600 mr-2" />
                          <span className="font-medium text-gray-900">{alert.alert_type}</span>
                          <span className={`ml-2 inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(alert.severity)}`}>
                            {alert.severity}
                          </span>
                        </div>
                        <p className="mt-1 text-sm text-gray-600">{alert.description}</p>
                        <p className="mt-2 text-xs text-gray-500">
                          {new Date(alert.timestamp).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </>
    );
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <Shield className="h-8 w-8 text-blue-600 mr-3" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Security Management</h1>
            <p className="text-gray-600">Monitor and manage OSINT Suite security</p>
          </div>
        </div>
        {activeTab === 'dashboard' && (
          <button
            onClick={loadSecurityData}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Refresh
          </button>
        )}
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm flex items-center ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4 mr-2" />
                {tab.name}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {renderTabContent()}
      </div>

      {/* Security Event Details Modal */}
      <SecurityEventDetails
        isOpen={showEventDetails}
        onClose={() => setShowEventDetails(false)}
      />
    </div>
  );
};