import axios, { AxiosInstance } from 'axios';
import {
  Investigation,
  InvestigationProgress,
  CreateInvestigationRequest,
  ListInvestigationsRequest,
  AIAnalysisResult
} from '../types/investigation';

export const AUTH_TOKEN_KEY = 'auth_token';

class APIClient {
  public client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor for authentication
    this.client.interceptors.request.use((config) => {
      const token = localStorage.getItem(AUTH_TOKEN_KEY);
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          // Handle unauthorized access
          localStorage.removeItem(AUTH_TOKEN_KEY);
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Authentication
  async login(credentials: { username: string; password: string }) {
    let response;
    try {
      response = await this.client.post('/auth/login', credentials);
    } catch (error: any) {
      // If the endpoint does not exist, try the old path
      if (error.response && (error.response.status === 404 || error.response.status === 405)) {
        response = await this.client.post('/api/auth/login', credentials);
      } else {
        throw error;
      }
    }
    const { access_token } = response.data ?? {};
    if (!access_token) {
      throw new Error('Authentication response did not include an access token');
    }
    localStorage.setItem(AUTH_TOKEN_KEY, access_token);
    return response.data;
  }

  async logout() {
    try {
      await this.client.post('/auth/logout');
    } finally {
      localStorage.removeItem(AUTH_TOKEN_KEY);
    }
  }

  // Investigations
  async createInvestigation(data: CreateInvestigationRequest): Promise<{ investigation_id: string }> {
    const response = await this.client.post('/api/investigations', data);
    return response.data;
  }

  async listInvestigations(params?: ListInvestigationsRequest): Promise<Investigation[]> {
    const response = await this.client.get('/api/investigations', { params });
    return response.data;
  }

  async getInvestigation(investigationId: string): Promise<Investigation> {
    const response = await this.client.get(`/api/investigations/${investigationId}`);
    return response.data;
  }

  async startInvestigation(investigationId: string): Promise<void> {
    await this.client.post(`/api/investigations/${investigationId}/start`);
  }

  async archiveInvestigation(investigationId: string): Promise<void> {
    await this.client.post(`/api/investigations/${investigationId}/archive`);
  }

  async getInvestigationProgress(investigationId: string): Promise<InvestigationProgress> {
    const response = await this.client.get(`/api/investigations/${investigationId}/progress`);
    return response.data;
  }

  // No addTask endpoint implemented server-side currently.

  async seedDemoTasks(investigationId: string): Promise<any> {
    const response = await this.client.post(`/api/investigations/${investigationId}/demo/seed-tasks`);
    return response.data;
  }

  // AI Analysis
  async analyze(params: { investigation_id: string; analysis_type: string; context?: string; include_raw_data?: boolean }): Promise<AIAnalysisResult> {
    const response = await this.client.post('/api/ai/analyze', params);
    return response.data;
  }

  // Reports
  async generateReport(investigation_id: string, report_type = 'comprehensive', format = 'pdf'): Promise<any> {
    const response = await this.client.post('/api/reports/generate', null, {
      params: { investigation_id, report_type, format }
    });
    return response.data;
  }

  // Search and Discovery
  // searchInvestigations endpoint not implemented in backend currently.

  // System Health
  async getSystemHealth(): Promise<any> {
    const response = await this.client.get('/api/health');
    return response.data;
  }

  // getSystemStats endpoint not implemented in backend.
}

// Create singleton instance
const apiClient = new APIClient();

// Export specific API modules
export const investigationApi = {
  createInvestigation: (data: CreateInvestigationRequest) => apiClient.createInvestigation(data),
  listInvestigations: (params?: ListInvestigationsRequest) => apiClient.listInvestigations(params),
  getInvestigation: (id: string) => apiClient.getInvestigation(id),
  startInvestigation: (id: string) => apiClient.startInvestigation(id),
  archiveInvestigation: (id: string) => apiClient.archiveInvestigation(id),
  getInvestigationProgress: (id: string) => apiClient.getInvestigationProgress(id),
  seedDemoTasks: (id: string) => apiClient.seedDemoTasks(id),
};

export const aiApi = {
  analyze: (params: { investigation_id: string; analysis_type: string; context?: string; include_raw_data?: boolean }) =>
    apiClient.analyze(params),
};

export const reportApi = {
  generate: (investigation_id: string, report_type?: string, format?: string) => 
    apiClient.generateReport(investigation_id, report_type, format),
};

export const authApi = {
  login: (credentials: { username: string; password: string }) => apiClient.login(credentials),
  logout: () => apiClient.logout(),
};

export const systemApi = {
  getHealth: () => apiClient.getSystemHealth(),
};

export { APIClient };
export default apiClient;