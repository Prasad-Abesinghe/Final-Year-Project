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

export interface LlmEvidence {
  zkp_failed: boolean
  reputation_score: number
  reputation_deficit: number
  matd_corrected_trust: number
  malicious_probability: number
  fl_predicted_variant: string
  fl_confidence: number
  fl_local_accuracy: number
  total_interactions: number
  debsc_triggered: boolean
}

export interface LlmReport {
  node_id: number
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  threat_score: number
  attack_variant: string
  attack_plane: string
  attack_pattern_label: string
  narrative: string
  attack_pattern: string
  recommended_action: string
  confidence_assessment: string
  evidence: LlmEvidence
  generated_by: string
  generated_at: string
}

export interface LlmScore {
  node_id: number
  Q_i: number
  label: string
  confidence: number
  tier_used: 'EDGE' | 'CLOUD'
  latency_ms: number
  softmax_probs: Record<string, number>
  window_events: number
  timestamp: number
}

export interface LlmSummary {
  network_status: 'SECURE' | 'COMPROMISED' | 'UNDER ATTACK'
  total_nodes: number
  threats_detected: number
  threat_breakdown: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number }
  attacker_nodes: number[]
  executive_summary: string
  scoring_mode: string
  generated_at: string
}
