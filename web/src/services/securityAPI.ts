import { APIClient } from './api';
import apiClient from './api';

export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string;
  roles: string[];
  permissions: string[];
  is_active: boolean;
  created_at: string;
  last_login?: string;
  security_clearance: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  user_id?: string;
  ip_address: string;
  user_agent: string;
  details: Record<string, any>;
  source: string;
  description?: string;
  metadata?: Record<string, any>;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  alert_type: string;
  severity: string;
  description: string;
  affected_users: string[];
  affected_data: string[];
  recommended_actions: string[];
  status: string;
  assigned_to?: string;
  resolved_at?: string;
  notes: string;
  user_id?: string;
  metadata?: Record<string, any>;
}

export interface SecurityReport {
  period: string;
  total_events: number;
  events_by_type: Record<string, number>;
  events_by_severity: Record<string, number>;
  top_users: Array<{ user_id: string; event_count: number }>;
  alerts_summary: {
    total_alerts: number;
    alerts_by_type: Record<string, number>;
    alerts_by_severity: Record<string, number>;
    unresolved_alerts: number;
  };
  risk_assessment: string;
  recommendations: string[];
}

export interface AccessPolicy {
  id: string;
  name: string;
  description: string;
  resource_type: string;
  resource_id: string;
  resource_pattern?: string;
  permissions: string[];
  required_permissions?: string[];
  required_roles?: string[];
  conditions: Record<string, any>;
  min_clearance?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface SecuritySettings {
  id: string;
  password_policy: {
    min_length: number;
    require_uppercase: boolean;
    require_lowercase: boolean;
    require_numbers: boolean;
    require_symbols: boolean;
    max_age_days: number;
  };
  session_policy: {
    max_concurrent_sessions: number;
    session_timeout_minutes: number;
    require_mfa: boolean;
  };
  session_timeout_minutes?: number;
  max_login_attempts?: number;
  password_min_length?: number;
  require_2fa?: boolean;
  password_complexity_required?: boolean;
  failed_login_alert_threshold?: number;
  suspicious_activity_threshold?: number;
  enable_intrusion_detection?: boolean;
  log_security_events?: boolean;
  enable_audit_trail?: boolean;
  data_retention_days?: number;
  encryption_key_rotation_days?: number;
  enable_data_encryption?: boolean;
  enable_backup_encryption?: boolean;
  require_data_classification?: boolean;
  default_user_clearance?: string;
  access_review_period_days?: number;
  enable_role_based_access?: boolean;
  enable_attribute_based_access?: boolean;
  require_access_approval?: boolean;
  enable_gdpr_compliance?: boolean;
  enable_hipaa_compliance?: boolean;
  enable_soc2_compliance?: boolean;
  enable_iso27001_compliance?: boolean;
  audit_policy: {
    log_all_actions: boolean;
    retention_days: number;
    alert_on_suspicious: boolean;
  };
  updated_at: string;
}

export interface DataObject {
  id: string;
  name: string;
  classification: string;
  category: string;
  owner_id: string;
  created_at: string;
  last_modified: string;
  tags: string[];
  metadata: Record<string, any>;
  retention_policy: string;
  description?: string;
  data_type?: string;
  updated_at?: string;
}

export class SecurityAPI {
  // User Management
  async getUsers(): Promise<User[]> {
    const response = await apiClient.client.get('/api/security/users');
    return response.data;
  }

  async createUser(userData: Partial<User>): Promise<User> {
    const response = await apiClient.client.post('/api/security/users', userData);
    return response.data;
  }

  async updateUser(userId: string, userData: Partial<User>): Promise<User> {
    const response = await apiClient.client.put(`/api/security/users/${userId}`, userData);
    return response.data;
  }

  async deleteUser(userId: string): Promise<void> {
    await apiClient.client.delete(`/api/security/users/${userId}`);
  }

  // Security Monitoring
  async getSecurityReport(days: number = 7): Promise<SecurityReport> {
    const response = await apiClient.client.get(`/api/security/report?days=${days}`);
    return response.data;
  }

  async getSecurityEvents(limit: number = 100): Promise<SecurityEvent[]> {
    const response = await apiClient.client.get(`/api/security/events?limit=${limit}`);
    return response.data;
  }

  async getSecurityAlerts(status?: string): Promise<SecurityAlert[]> {
    const params = status ? `?status=${status}` : '';
    const response = await apiClient.client.get(`/api/security/alerts${params}`);
    return response.data;
  }

  async resolveAlert(alertId: string, notes?: string): Promise<SecurityAlert> {
    const response = await apiClient.client.post(`/api/security/alerts/${alertId}/resolve`, { notes });
    return response.data;
  }

  // Data Access Control
  async getDataObjects(): Promise<DataObject[]> {
    const response = await apiClient.client.get('/api/security/data-objects');
    return response.data;
  }

  async classifyData(data: {
    id: string;
    name: string;
    classification: string;
    category: string;
    tags?: string[];
    metadata?: Record<string, any>;
  }): Promise<DataObject> {
    const response = await apiClient.client.post('/api/security/data-objects', data);
    return response.data;
  }

  async checkDataAccess(dataId: string, action: string = 'read'): Promise<boolean> {
    try {
      await apiClient.client.post(`/api/security/data-objects/${dataId}/access`, { action });
      return true;
    } catch (error) {
      return false;
    }
  }

  async getAccessPolicies(): Promise<AccessPolicy[]> {
    const response = await apiClient.client.get('/api/security/access-policies');
    return response.data;
  }

  async createDataObject(data: Partial<DataObject>): Promise<DataObject> {
    const response = await apiClient.client.post('/api/security/data-objects', data);
    return response.data;
  }

  async updateDataObject(objectId: string, data: Partial<DataObject>): Promise<DataObject> {
    const response = await apiClient.client.put(`/api/security/data-objects/${objectId}`, data);
    return response.data;
  }

  async deleteDataObject(objectId: string): Promise<void> {
    await apiClient.client.delete(`/api/security/data-objects/${objectId}`);
  }

  async getSecuritySettings(): Promise<SecuritySettings> {
    const response = await apiClient.client.get('/api/security/settings');
    return response.data;
  }

  async updateSecuritySettings(settings: Partial<SecuritySettings>): Promise<SecuritySettings> {
    const response = await apiClient.client.put('/api/security/settings', settings);
    return response.data;
  }

  // Session Management
  async getActiveSessions(): Promise<any[]> {
    const response = await apiClient.client.get('/api/security/sessions');
    return response.data;
  }

  async invalidateSession(sessionId: string): Promise<void> {
    await apiClient.client.delete(`/api/security/sessions/${sessionId}`);
  }

  // Audit Logs
  async getAuditLogs(filters?: {
    user_id?: string;
    action?: string;
    start_date?: string;
    end_date?: string;
    limit?: number;
  }): Promise<any[]> {
    const params = new URLSearchParams();
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) params.append(key, value.toString());
      });
    }
    const response = await apiClient.client.get(`/api/security/audit?${params}`);
    return response.data;
  }
}

// Export singleton instance
export const securityAPI = new SecurityAPI();