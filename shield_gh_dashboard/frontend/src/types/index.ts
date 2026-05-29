export interface BcRecord {
  record_id: string
  node_id: number
  zkp_valid: boolean
  reputation_score: number
  reputation_deficit: number
  total_interactions: number
  matd_corrected_trust: number
  isolation_status: string
  debsc_triggered: boolean
  timestamp: number
  mitigation: object | null
}

export interface FlScore {
  node_id: number
  malicious_prob: number
  predicted_variant: string
  confidence: number
  round_num: number
  local_accuracy: number
  timestamp: number
}

export interface RoundEntry {
  round: number
  accepted: number
  rejected: number[]
}

export interface LedgerEntry {
  key: string
  hash: string
  full_hash: string
}

export interface Summary {
  total_vehicles_monitored: number
  total_isolated: number
  avg_reputation_score: number
  fl_rounds_completed: number
  fl_avg_accuracy: number
  gradient_commits: number
  gradient_accepted: number
  gradient_rejected: number
  pqc_active: boolean
}

export interface NetworkNode {
  id: string
  type: 'rsu' | 'vehicle'
  node_id?: number
  label: string
  rsu?: string
  isolation_status?: string
  debsc_triggered?: boolean
  reputation_score?: number
  zkp_valid?: boolean
  malicious_prob?: number | null
  local_accuracy?: number | null
  x: number
  y: number
}

export interface NetworkEdge {
  source: string
  target: string
  type: string
}
