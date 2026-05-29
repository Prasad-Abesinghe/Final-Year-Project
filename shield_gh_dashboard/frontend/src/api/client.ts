import axios from 'axios'

const api = axios.create({ baseURL: '' })

export const fetchSummary       = () => api.get('/api/system/summary').then(r => r.data)
export const fetchBcRecords     = () => api.get('/api/blockchain/records').then(r => r.data)
export const fetchBcRecord      = (id: number) => api.get(`/api/blockchain/records/${id}`).then(r => r.data)
export const fetchFlScores      = () => api.get('/api/fl/scores').then(r => r.data)
export const fetchFlScore       = (id: number) => api.get(`/api/fl/scores/${id}`).then(r => r.data)
export const fetchRoundLog      = () => api.get('/api/fl/rounds').then(r => r.data)
export const fetchGradientLedger= () => api.get('/api/fl/ledger').then(r => r.data)
export const fetchTopology      = () => api.get('/api/network/topology').then(r => r.data)
export const fetchLlmScores    = () => api.get('/api/llm/scores').then(r => r.data)
export const fetchLlmScore     = (id: number) => api.get(`/api/llm/scores/${id}`).then(r => r.data)
export const fetchLlmSummary   = () => api.get('/api/llm/summary').then(r => r.data)
export const fetchLlmReports   = () => api.get('/api/llm/reports').then(r => r.data)
export const fetchLlmReport    = (id: number) => api.get(`/api/llm/reports/${id}`).then(r => r.data)
