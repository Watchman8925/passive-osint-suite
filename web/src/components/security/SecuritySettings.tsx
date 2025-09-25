import React, { useState, useEffect } from 'react';
import { Settings, Shield, AlertTriangle, Clock, Users, Database, Save } from 'lucide-react';
import { securityAPI, SecuritySettings } from '../../services/securityAPI';

interface SecuritySettingsProps {
  className?: string;
}

export const SecuritySettingsComponent: React.FC<SecuritySettingsProps> = ({ className = '' }) => {
  const [settings, setSettings] = useState<SecuritySettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const settingsData = await securityAPI.getSecuritySettings();
      setSettings(settingsData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security settings');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async () => {
    if (!settings) return;

    try {
      setSaving(true);
      setError(null);
      await securityAPI.updateSecuritySettings(settings);
      setSuccess('Security settings saved successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save security settings');
    } finally {
      setSaving(false);
    }
  };

  const updateSetting = (key: string, value: any) => {
    if (!settings) return;
    setSettings({ ...settings, [key]: value });
  };

  if (loading) {
    return (
      <div className={`flex items-center justify-center h-64 ${className}`}>
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!settings) {
    return (
      <div className={`text-center py-12 ${className}`}>
        <p className="text-gray-500">Failed to load security settings</p>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <Settings className="h-8 w-8 text-blue-600 mr-3" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Security Settings</h1>
            <p className="text-gray-600">Configure security policies and thresholds</p>
          </div>
        </div>
        <button
          onClick={handleSaveSettings}
          disabled={saving}
          className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
        >
          <Save className="h-4 w-4 mr-2" />
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>

      {/* Success/Error Messages */}
      {success && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <span className="text-green-800">{success}</span>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <span className="text-red-800">{error}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Authentication Settings */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center mb-4">
            <Shield className="h-6 w-6 text-blue-600 mr-3" />
            <h2 className="text-lg font-semibold text-gray-900">Authentication</h2>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Session Timeout (minutes)
              </label>
              <input
                type="number"
                value={settings.session_timeout_minutes}
                onChange={(e) => updateSetting('session_timeout_minutes', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="5"
                max="1440"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Maximum Login Attempts
              </label>
              <input
                type="number"
                value={settings.max_login_attempts}
                onChange={(e) => updateSetting('max_login_attempts', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="1"
                max="10"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password Minimum Length
              </label>
              <input
                type="number"
                value={settings.password_min_length}
                onChange={(e) => updateSetting('password_min_length', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="8"
                max="128"
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.require_2fa}
                onChange={(e) => updateSetting('require_2fa', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Require Two-Factor Authentication</label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.password_complexity_required}
                onChange={(e) => updateSetting('password_complexity_required', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Require Password Complexity</label>
            </div>
          </div>
        </div>

        {/* Security Monitoring */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center mb-4">
            <AlertTriangle className="h-6 w-6 text-orange-600 mr-3" />
            <h2 className="text-lg font-semibold text-gray-900">Security Monitoring</h2>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Failed Login Alert Threshold
              </label>
              <input
                type="number"
                value={settings.failed_login_alert_threshold}
                onChange={(e) => updateSetting('failed_login_alert_threshold', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="1"
                max="100"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Suspicious Activity Threshold
              </label>
              <input
                type="number"
                value={settings.suspicious_activity_threshold}
                onChange={(e) => updateSetting('suspicious_activity_threshold', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="1"
                max="1000"
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.enable_intrusion_detection}
                onChange={(e) => updateSetting('enable_intrusion_detection', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Enable Intrusion Detection</label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.log_security_events}
                onChange={(e) => updateSetting('log_security_events', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Log Security Events</label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.enable_audit_trail}
                onChange={(e) => updateSetting('enable_audit_trail', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Enable Audit Trail</label>
            </div>
          </div>
        </div>

        {/* Data Protection */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center mb-4">
            <Database className="h-6 w-6 text-green-600 mr-3" />
            <h2 className="text-lg font-semibold text-gray-900">Data Protection</h2>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Data Retention Period (days)
              </label>
              <input
                type="number"
                value={settings.data_retention_days}
                onChange={(e) => updateSetting('data_retention_days', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="1"
                max="3650"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Encryption Key Rotation (days)
              </label>
              <input
                type="number"
                value={settings.encryption_key_rotation_days}
                onChange={(e) => updateSetting('encryption_key_rotation_days', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="30"
                max="365"
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.enable_data_encryption}
                onChange={(e) => updateSetting('enable_data_encryption', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Enable Data Encryption</label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.enable_backup_encryption}
                onChange={(e) => updateSetting('enable_backup_encryption', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Enable Backup Encryption</label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.require_data_classification}
                onChange={(e) => updateSetting('require_data_classification', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Require Data Classification</label>
            </div>
          </div>
        </div>

        {/* Access Control */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center mb-4">
            <Users className="h-6 w-6 text-purple-600 mr-3" />
            <h2 className="text-lg font-semibold text-gray-900">Access Control</h2>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Default User Clearance
              </label>
              <select
                value={settings.default_user_clearance}
                onChange={(e) => updateSetting('default_user_clearance', e.target.value)}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
              >
                <option value="standard">Standard</option>
                <option value="sensitive">Sensitive</option>
                <option value="confidential">Confidential</option>
                <option value="restricted">Restricted</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Access Review Period (days)
              </label>
              <input
                type="number"
                value={settings.access_review_period_days}
                onChange={(e) => updateSetting('access_review_period_days', parseInt(e.target.value))}
                className="w-full border border-gray-300 rounded-md shadow-sm p-2"
                min="30"
                max="365"
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.enable_role_based_access}
                onChange={(e) => updateSetting('enable_role_based_access', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Enable Role-Based Access Control</label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.enable_attribute_based_access}
                onChange={(e) => updateSetting('enable_attribute_based_access', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Enable Attribute-Based Access Control</label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.require_access_approval}
                onChange={(e) => updateSetting('require_access_approval', e.target.checked)}
                className="mr-2"
              />
              <label className="text-sm font-medium text-gray-700">Require Access Approval</label>
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Settings */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center mb-4">
          <Clock className="h-6 w-6 text-indigo-600 mr-3" />
          <h2 className="text-lg font-semibold text-gray-900">Compliance</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="flex items-center">
            <input
              type="checkbox"
              checked={settings.enable_gdpr_compliance}
              onChange={(e) => updateSetting('enable_gdpr_compliance', e.target.checked)}
              className="mr-2"
            />
            <label className="text-sm font-medium text-gray-700">GDPR Compliance</label>
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              checked={settings.enable_hipaa_compliance}
              onChange={(e) => updateSetting('enable_hipaa_compliance', e.target.checked)}
              className="mr-2"
            />
            <label className="text-sm font-medium text-gray-700">HIPAA Compliance</label>
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              checked={settings.enable_soc2_compliance}
              onChange={(e) => updateSetting('enable_soc2_compliance', e.target.checked)}
              className="mr-2"
            />
            <label className="text-sm font-medium text-gray-700">SOC 2 Compliance</label>
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              checked={settings.enable_iso27001_compliance}
              onChange={(e) => updateSetting('enable_iso27001_compliance', e.target.checked)}
              className="mr-2"
            />
            <label className="text-sm font-medium text-gray-700">ISO 27001 Compliance</label>
          </div>
        </div>
      </div>
    </div>
  );
};