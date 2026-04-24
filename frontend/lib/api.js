import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// Core
export const scanURL = (url) => api.post('/scan', { url });
export const listURLs = (params) => api.get('/urls', { params });
export const getURL = (id) => api.get(`/urls/${id}`);
export const updateURLStatus = (id, status) => api.patch(`/urls/${id}/status`, { status });

// Dashboard
export const getDashboardStats = () => api.get('/dashboard/stats');
export const getDashboardTrends = (days = 30) => api.get('/dashboard/trends', { params: { days } });
export const getThreatLogs = (params) => api.get('/threat-logs', { params });

// Search
export const atlasSearch = (data) => api.post('/search/atlas', data);
export const vectorSearch = (data) => api.post('/search/vector', data);
export const hybridSearch = (data) => api.post('/search/hybrid', data);
export const unifiedSearch = (data) => api.post('/search/unified', data);
export const getDemoScenarios = () => api.get('/search/demo-scenarios');

// Debug
export const getSearchInfo = () => api.get('/debug/search/info');
export const testAtlasIndex = () => api.post('/debug/search/atlas/test-index');
export const testVectorIndex = () => api.post('/debug/search/vector/test-index');

export default api;
