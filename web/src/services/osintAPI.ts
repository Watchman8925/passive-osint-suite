import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import toast from 'react-hot-toast';
import { startProgress, finishProgress } from '../utils/progress';

interface TorProxyConfig {
  enabled: boolean;
  host: string;
  port: number;
}

interface TorControlResponse {
  success: boolean;
  message: string;
  status?: {
    active?: boolean;
    [key: string]: any;
  };
}

interface AnonymityConfig {
  tor: TorProxyConfig;
  doh: boolean;
  queryObfuscation: boolean;
  userAgent: string;
}

class OSINTAPIClient {
  private client: AxiosInstance;
  private anonymityConfig: AnonymityConfig;

  constructor() {
    this.anonymityConfig = {
      tor: {
        enabled: true,
        host: 'localhost',
        port: 9050
      },
      doh: true,
      queryObfuscation: true,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    };

    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_URL || '/',
      timeout: 60000, // Longer timeout for Tor
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.anonymityConfig.userAgent,
        'X-Anonymity-Features': JSON.stringify({
          tor: this.anonymityConfig.tor.enabled,
          doh: this.anonymityConfig.doh,
          obfuscation: this.anonymityConfig.queryObfuscation
        })
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor for authentication and anonymity
    this.client.interceptors.request.use(
      (config) => {
        // Start progress bar
        startProgress();

        // Add auth token if available
        const token = localStorage.getItem('osint_auth_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Add anonymity headers
        config.headers['X-Request-ID'] = this.generateRequestId();
        config.headers['X-Timestamp'] = Date.now().toString();
        
        // Note: Tor routing must be handled server-side in a web app
        // Browser cannot directly connect to SOCKS5 proxy

        return config;
      },
      (error) => {
        finishProgress();
        toast.error('Request configuration error');
        return Promise.reject(error);
      }
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => {
        // Finish progress bar
        finishProgress();

        // Log successful anonymized requests
        if (response.headers['x-tor-exit-node']) {
          console.log('✅ Request routed through Tor exit node:', response.headers['x-tor-exit-node']);
        }
        return response;
      },
      (error) => {
        // Finish progress bar
        finishProgress();

        if (error.response?.status === 401) {
          toast.error('Authentication required');
          localStorage.removeItem('osint_auth_token');
        } else if (error.response?.status === 403) {
          toast.error('Access denied - check your permissions');
        } else if (error.response?.status >= 500) {
          toast.error('Server error - please try again later');
        } else if (error.code === 'ECONNABORTED') {
          toast.error('Request timeout - anonymity network may be slow');
        } else {
          toast.error(`API Error: ${error.response?.data?.message || error.message}`);
        }
        return Promise.reject(error);
      }
    );
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Anonymity Control Methods
  async enableTor(): Promise<TorControlResponse> {
    try {
      const response = await this.client.post('/api/anonymity/tor/enable');
      const data: TorControlResponse = response.data;
      if (data.status && data.status.active !== undefined) {
        this.anonymityConfig.tor.enabled = Boolean(data.status.active);
      } else if (data.success) {
        this.anonymityConfig.tor.enabled = true;
      }
      return data;
    } catch (error: any) {
      return {
        success: false,
        message: error?.response?.data?.message || 'Failed to enable Tor network',
        status: error?.response?.data?.status,
      };
    }
  }

  async disableTor(): Promise<TorControlResponse> {
    try {
      const response = await this.client.post('/api/anonymity/tor/disable');
      const data: TorControlResponse = response.data;
      if (data.status && data.status.active !== undefined) {
        this.anonymityConfig.tor.enabled = Boolean(data.status.active);
      } else if (data.success) {
        this.anonymityConfig.tor.enabled = false;
      }
      return data;
    } catch (error: any) {
      return {
        success: false,
        message: error?.response?.data?.message || 'Failed to disable Tor network',
        status: error?.response?.data?.status,
      };
    }
  }

  async getTorStatus(): Promise<{active: boolean, exitNode?: string, country?: string}> {
    try {
      const response = await this.client.get('/api/anonymity/tor/status');
      const status = response.data;
      if (typeof status?.active === 'boolean') {
        this.anonymityConfig.tor.enabled = status.active;
      }
      return status;
    } catch (error) {
      return { active: false };
    }
  }

  async newTorIdentity(): Promise<TorControlResponse> {
    try {
      const response = await this.client.post('/api/anonymity/tor/new-identity');
      const data: TorControlResponse = response.data;
      if (data.status && data.status.active !== undefined) {
        this.anonymityConfig.tor.enabled = Boolean(data.status.active);
      }
      return data;
    } catch (error: any) {
      return {
        success: false,
        message: error?.response?.data?.message || 'Failed to acquire new Tor identity',
        status: error?.response?.data?.status,
      };
    }
  }

  // Investigation Management
  async createInvestigation(data: any): Promise<any> {
    try {
      toast.loading('Creating investigation...', { id: 'create-investigation' });
      const response = await this.client.post('/api/investigations', data);
      toast.success('✅ Investigation created successfully', { id: 'create-investigation' });
      return response.data;
    } catch (error) {
      toast.error('Failed to create investigation', { id: 'create-investigation' });
      throw error;
    }
  }

  async getInvestigations(params?: any): Promise<any[]> {
    try {
      const response = await this.client.get('/api/investigations', { params });
      return response.data;
    } catch (error) {
      console.error('Failed to fetch investigations:', error);
      return [];
    }
  }

  async getInvestigation(id: string): Promise<any> {
    try {
      const response = await this.client.get(`/api/investigations/${id}`);
      return response.data;
    } catch (error) {
      toast.error('Failed to fetch investigation details');
      throw error;
    }
  }

  async startInvestigation(id: string): Promise<boolean> {
    try {
      toast.loading('Starting investigation...', { id: `start-${id}` });
      await this.client.post(`/api/investigations/${id}/start`);
      toast.success('🚀 Investigation started', { id: `start-${id}` });
      return true;
    } catch (error) {
      toast.error('Failed to start investigation', { id: `start-${id}` });
      return false;
    }
  }

  async pauseInvestigation(id: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const response = await this.client.post(`/api/investigations/${id}/pause`);
      return { success: true, data: response.data };
    } catch (error: any) {
      const message = error?.response?.data?.detail || error?.message || 'Failed to pause investigation';
      return { success: false, error: message };
    }
  }

  async resumeInvestigation(id: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const response = await this.client.post(`/api/investigations/${id}/resume`);
      return { success: true, data: response.data };
    } catch (error: any) {
      const message = error?.response?.data?.detail || error?.message || 'Failed to resume investigation';
      return { success: false, error: message };
    }
  }

  async stopInvestigation(id: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const response = await this.client.post(`/api/investigations/${id}/stop`);
      return { success: true, data: response.data };
    } catch (error: any) {
      const message = error?.response?.data?.detail || error?.message || 'Failed to stop investigation';
      return { success: false, error: message };
    }
  }

  // OSINT Module Integration
  async domainRecon(domain: string, options?: any): Promise<any> {
    try {
      toast.loading(`🔍 Analyzing domain: ${domain}`, { id: 'domain-recon' });
      const response = await this.client.post('/api/modules/execute', { 
        module_name: 'domain_analyzer',
        parameters: { 
          domain,
          ...options
        } 
      });
      toast.success('Domain analysis completed', { id: 'domain-recon' });
      return response.data;
    } catch (error) {
      toast.error('Domain analysis failed', { id: 'domain-recon' });
      throw error;
    }
  }

  async emailIntel(email: string, options?: any): Promise<any> {
    try {
      toast.loading(`📧 Investigating email: ${email}`, { id: 'email-intel' });
      const response = await this.client.post('/api/modules/execute', { 
        module_name: 'email_analyzer',
        parameters: { 
          email,
          ...options
        } 
      });
      toast.success('Email investigation completed', { id: 'email-intel' });
      return response.data;
    } catch (error) {
      toast.error('Email investigation failed', { id: 'email-intel' });
      throw error;
    }
  }

  async ipAnalysis(ip: string, options?: any): Promise<any> {
    try {
      toast.loading(`🌐 Analyzing IP: ${ip}`, { id: 'ip-analysis' });
      const response = await this.client.post('/api/modules/execute', { 
        module_name: 'ip_analyzer',
        parameters: { 
          ip,
          ...options
        } 
      });
      toast.success('IP analysis completed', { id: 'ip-analysis' });
      return response.data;
    } catch (error) {
      toast.error('IP analysis failed', { id: 'ip-analysis' });
      throw error;
    }
  }

  // Media Forensics
  async analyzeMedia(file: File, options?: any): Promise<any> {
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('options', JSON.stringify({ 
        ...options, 
        anonymity: this.anonymityConfig 
      }));

      toast.loading('📸 Analyzing media file...', { id: 'media-analysis' });
      const response = await this.client.post('/api/osint/media', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      toast.success('Media analysis completed', { id: 'media-analysis' });
      return response.data;
    } catch (error) {
      toast.error('Media analysis failed', { id: 'media-analysis' });
      throw error;
    }
  }

  // System Status
  async getSystemStatus(): Promise<any> {
    try {
      const response = await this.client.get('/api/health');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch system status:', error);
      return {
        status: 'unknown',
        tor: { active: false },
        doh: { active: false },
        anonymity_grid: { active: false }
      };
    }
  }

  // Authentication
  async authenticate(credentials: { username: string; password: string }): Promise<boolean> {
    try {
      const response = await this.client.post('/api/auth/login', credentials);
      const { token } = response.data;
      localStorage.setItem('osint_auth_token', token);
      toast.success('🔐 Authentication successful');
      return true;
    } catch (error) {
      toast.error('Authentication failed');
      return false;
    }
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/api/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('osint_auth_token');
      toast.success('Logged out successfully');
    }
  }
}

// Export singleton instance
export const osintAPI = new OSINTAPIClient();
export default osintAPI;