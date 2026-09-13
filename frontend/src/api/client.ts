import axios from 'axios';
import { AuthResponse, DashboardStats, IncidentReport, InvestigationResponse, InvestigationSummaryItem } from '../types';

const API_BASE_URL = '/api';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT token to requests
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('siem_access_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401s
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('siem_access_token');
      localStorage.removeItem('siem_user');
      if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ── Auth APIs ────────────────────────────────────────────────────────────────
export const authApi = {
  login: async (email: string, password: string): Promise<AuthResponse> => {
    const res = await apiClient.post<AuthResponse>('/auth/login', {
      email,
      username: email,
      password,
    });
    return res.data;
  },

  register: async (name: string, email: string, password: string, role: string = 'analyst'): Promise<AuthResponse> => {
    const res = await apiClient.post<AuthResponse>('/auth/register', { name, email, password, role });
    return res.data;
  },

  getMe: async () => {
    const res = await apiClient.get('/auth/me');
    return res.data;
  },
};


// ── Investigation APIs ────────────────────────────────────────────────────────
export const investigationApi = {
  investigate: async (query: string, conversationId?: string): Promise<InvestigationResponse> => {
    const res = await apiClient.post<InvestigationResponse>('/investigate', {
      query,
      conversation_id: conversationId || null,
    });
    return res.data;
  },

  queryNLP: async (query: string, conversationId?: string) => {
    const res = await apiClient.post('/query', {
      query,
      conversation_id: conversationId || null,
    });
    return res.data;
  },

  getLogs: async (params?: {
    source_ip?: string;
    event_action?: string;
    username?: string;
    threat_tag?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }) => {
    const res = await apiClient.get('/logs', { params });
    return res.data;
  },

  getThreats: async (query?: string, limit = 30) => {
    const res = await apiClient.get('/threats', { params: { query, limit } });
    return res.data;
  },

  chat: async (message: string, conversationId?: string): Promise<InvestigationResponse> => {
    const res = await apiClient.post<InvestigationResponse>('/investigate/chat', {
      query: message,
      message,
      conversation_id: conversationId || null,
    });
    return res.data;
  },

  listInvestigations: async (skip = 0, limit = 20): Promise<InvestigationSummaryItem[]> => {
    const res = await apiClient.get<InvestigationSummaryItem[]>('/investigations', {
      params: { skip, limit },
    });
    return res.data;
  },

  getInvestigation: async (id: string): Promise<any> => {
    const res = await apiClient.get(`/investigations/${id}`);
    return res.data;
  },

  agentInvestigate: async (
    query: string,
    conversationId?: string,
  ): Promise<InvestigationResponse> => {
    const res = await apiClient.post<InvestigationResponse>('/investigate', {
      query,
      conversation_id: conversationId || null,
    });
    return res.data;
  },
};

export const knowledgeApi = {
  search: async (query: string, topK = 5, docType?: string) => {
    const res = await apiClient.get('/threats', {
      params: { query, limit: topK },
    });
    return res.data;
  },

  getMitreTechnique: async (techniqueId: string) => {
    const res = await apiClient.get(`/threats`, { params: { query: techniqueId } });
    return res.data;
  },
};

// ── Report APIs ───────────────────────────────────────────────────────────────
export const reportApi = {
  generateReport: async (investigationId: string): Promise<{ report_id: string; report: IncidentReport }> => {
    const res = await apiClient.post(`/reports/generate/${investigationId}`);
    return res.data;
  },

  getReport: async (reportId: string): Promise<IncidentReport> => {
    const res = await apiClient.get<IncidentReport>(`/reports/${reportId}`);
    return res.data;
  },

  downloadPdfUrl: (reportId: string): string => {
    return `${API_BASE_URL}/reports/${reportId}/pdf`;
  },

  downloadPdf: async (reportId: string): Promise<Blob> => {
    const res = await apiClient.get(`/reports/${reportId}/pdf`, {
      responseType: 'blob',
    });
    return res.data;
  },
};

// ── Dashboard APIs ────────────────────────────────────────────────────────────
export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    const res = await apiClient.get<DashboardStats>('/dashboard/stats');
    return res.data;
  },
};
