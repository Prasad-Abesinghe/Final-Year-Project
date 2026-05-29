import axios from 'axios'

const api = axios.create({ baseURL: 'http://localhost:8000' })

export const fetchSummary       = () => api.get('/api/system/summary').then(r => r.data)
export const fetchBcRecords     = () => api.get('/api/blockchain/records').then(r => r.data)
export const fetchBcRecord      = (id: number) => api.get(`/api/blockchain/records/${id}`).then(r => r.data)
export const fetchFlScores      = () => api.get('/api/fl/scores').then(r => r.data)
export const fetchFlScore       = (id: number) => api.get(`/api/fl/scores/${id}`).then(r => r.data)
export const fetchRoundLog      = () => api.get('/api/fl/rounds').then(r => r.data)
export const fetchGradientLedger= () => api.get('/api/fl/ledger').then(r => r.data)
export const fetchTopology      = () => api.get('/api/network/topology').then(r => r.data)
