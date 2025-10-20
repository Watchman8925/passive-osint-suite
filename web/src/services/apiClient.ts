/**
 * Centralized API Client
 * 
 * Provides a configured axios instance with:
 * - Automatic base URL configuration from VITE_API_URL
 * - Request interceptors for authentication
 * - Response interceptors for error normalization
 * - Consistent error handling across the application
 */

import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig, AxiosResponse } from 'axios';

/**
 * Normalized error structure for consistent error handling
 */
export interface NormalizedError {
  message: string;
  status?: number;
  code?: string;
  details?: any;
}

/**
 * API Client class providing centralized HTTP communication
 */
class APIClient {
  private client: AxiosInstance;

  constructor() {
    // Create axios instance with base configuration
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Setup interceptors
    this.setupRequestInterceptor();
    this.setupResponseInterceptor();
  }

  /**
   * Request interceptor - adds authentication headers
   */
  private setupRequestInterceptor(): void {
    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        // Add authorization token if available
        const token = localStorage.getItem('auth_token');
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error: AxiosError) => {
        return Promise.reject(this.normalizeError(error));
      }
    );
  }

  /**
   * Response interceptor - handles common response scenarios
   */
  private setupResponseInterceptor(): void {
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        // Return successful response as-is
        return response;
      },
      (error: AxiosError) => {
        // Handle 401 Unauthorized - clear token and redirect to login
        if (error.response?.status === 401) {
          localStorage.removeItem('auth_token');
          // Only redirect if not already on login page
          if (!window.location.pathname.includes('/login')) {
            window.location.href = '/login';
          }
        }

        // Return normalized error
        return Promise.reject(this.normalizeError(error));
      }
    );
  }

  /**
   * Normalize errors into a consistent format
   */
  private normalizeError(error: AxiosError): NormalizedError {
    const normalized: NormalizedError = {
      message: 'An unexpected error occurred',
      status: error.response?.status,
      code: error.code,
    };

    // Extract error details from response
    if (error.response?.data) {
      const data = error.response.data as any;
      
      // Handle different API error response formats
      if (typeof data === 'string') {
        normalized.message = data;
      } else if (data.detail) {
        // FastAPI default error format
        normalized.message = typeof data.detail === 'string' 
          ? data.detail 
          : JSON.stringify(data.detail);
        normalized.details = data.detail;
      } else if (data.message) {
        normalized.message = data.message;
        normalized.details = data;
      } else if (data.error) {
        normalized.message = data.error;
        normalized.details = data;
      } else {
        normalized.details = data;
      }
    } else if (error.message) {
      // Network errors or timeouts
      normalized.message = error.message;
    }

    return normalized;
  }

  /**
   * Get the underlying axios instance for direct access if needed
   */
  public getInstance(): AxiosInstance {
    return this.client;
  }

  /**
   * Perform GET request
   */
  public async get<T = any>(url: string, config?: any): Promise<T> {
    const response = await this.client.get<T>(url, config);
    return response.data;
  }

  /**
   * Perform POST request
   */
  public async post<T = any>(url: string, data?: any, config?: any): Promise<T> {
    const response = await this.client.post<T>(url, data, config);
    return response.data;
  }

  /**
   * Perform PUT request
   */
  public async put<T = any>(url: string, data?: any, config?: any): Promise<T> {
    const response = await this.client.put<T>(url, data, config);
    return response.data;
  }

  /**
   * Perform PATCH request
   */
  public async patch<T = any>(url: string, data?: any, config?: any): Promise<T> {
    const response = await this.client.patch<T>(url, data, config);
    return response.data;
  }

  /**
   * Perform DELETE request
   */
  public async delete<T = any>(url: string, config?: any): Promise<T> {
    const response = await this.client.delete<T>(url, config);
    return response.data;
  }
}

// Export singleton instance
export const apiClient = new APIClient();

// Export class for testing purposes
export default APIClient;
