import { useEffect, useState } from 'react'
import { Brain, AlertTriangle, ShieldCheck, ShieldAlert, Cpu, ChevronDown, ChevronUp, Zap, Cloud } from 'lucide-react'
import { fetchLlmSummary, fetchLlmReports, fetchLlmScores } from '../api/client'
import type { LlmSummary, LlmReport, LlmScore } from '../types'

// ── Style maps ────────────────────────────────────────────────────────────────

const LEVEL: Record<string, { border: string; bg: string; badge: string; text: string }> = {
  CRITICAL: { border: 'border-red-700',    bg: 'bg-red-900/20',    badge: 'bg-red-600 text-white',    text: 'text-red-400' },
  HIGH:     { border: 'border-orange-700', bg: 'bg-orange-900/20', badge: 'bg-orange-500 text-white', text: 'text-orange-400' },
  MEDIUM:   { border: 'border-yellow-700', bg: 'bg-yellow-900/10', badge: 'bg-yellow-600 text-white', text: 'text-yellow-400' },
  LOW:      { border: 'border-green-800',  bg: 'bg-green-900/10',  badge: 'bg-green-700 text-white',  text: 'text-green-400' },
}

const STATUS: Record<string, { border: string; bg: string; Icon: typeof ShieldAlert; color: string }> = {
  'SECURE':        { border: 'border-green-600',  bg: 'bg-green-900/20',  Icon: ShieldCheck,   color: 'text-green-400' },
  'COMPROMISED':   { border: 'border-orange-600', bg: 'bg-orange-900/20', Icon: ShieldAlert,   color: 'text-orange-400' },
  'UNDER ATTACK':  { border: 'border-red-600',    bg: 'bg-red-900/20',    Icon: AlertTriangle, color: 'text-red-400' },
}

// ── Small helpers ─────────────────────────────────────────────────────────────

function ScoreBar({ value, level, label }: { value: number; level: string; label: string }) {
  const color = level === 'CRITICAL' ? 'bg-red-500' : level === 'HIGH' ? 'bg-orange-500' :
                level === 'MEDIUM'   ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div>
      <div className="flex justify-between text-xs text-slate-500 mb-1">
        <span>{label}</span>
        <span className={LEVEL[level]?.text ?? 'text-slate-300'}>{(value * 100).toFixed(1)}%</span>
      </div>
      <div className="bg-slate-700 rounded-full h-2 overflow-hidden">
        <div className={`h-2 rounded-full ${color}`} style={{ width: `${Math.max(value * 100, 2)}%` }} />
      </div>
    </div>
  )
}

function EvidRow({ label, value, hi }: { label: string; value: string; hi?: string }) {
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-slate-700/40 last:border-0">
      <span className="text-slate-500 text-xs">{label}</span>
      <span className={`text-xs font-mono font-semibold ${hi ?? 'text-slate-300'}`}>{value}</span>
    </div>
  )
}

// ── Q_i Score Panel ────────────────────────────────────────────────────────────

function QiPanel({ score }: { score: LlmScore }) {
  const isAttacker = score.Q_i > 0.5
  const tierIcon   = score.tier_used === 'EDGE' ? <Zap size={12} className="text-yellow-400" /> : <Cloud size={12} className="text-blue-400" />
  const barColor   = isAttacker ? 'bg-red-500' : 'bg-green-500'

  return (
    <div className="bg-slate-900/60 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-slate-400 text-xs uppercase tracking-wide font-semibold flex items-center gap-1">
          <Brain size={12} /> DistilBERT  Q<sub>i</sub>(t)
        </p>
        <div className="flex items-center gap-1 text-xs text-slate-500">
          {tierIcon}
          <span>{score.tier_used} tier</span>
          <span className="text-slate-600">·</span>
          <span>{score.latency_ms.toFixed(0)} ms</span>
        </div>
      </div>

      {/* Q_i bar */}
      <div>
        <div className="flex justify-between text-xs text-slate-500 mb-1">
          <span>Threat probability Q<sub>i</sub>(t)</span>
          <span className={isAttacker ? 'text-red-400' : 'text-green-400'}>
            {(score.Q_i * 100).toFixed(2)}%
          </span>
        </div>
        <div className="bg-slate-700 rounded-full h-3 overflow-hidden">
          <div className={`h-3 rounded-full ${barColor}`} style={{ width: `${Math.max(score.Q_i * 100, 2)}%` }} />
        </div>
      </div>

      {/* Softmax probs */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
        {Object.entries(score.softmax_probs)
          .sort(([, a], [, b]) => b - a)
          .map(([lbl, prob]) => (
            <div key={lbl} className="flex items-center gap-1.5">
              <div className="bg-slate-700 rounded-full h-1 flex-1 overflow-hidden">
                <div className="bg-blue-500 h-1 rounded-full" style={{ width: `${prob * 100}%` }} />
              </div>
              <span className="text-slate-500 text-xs font-mono w-10 text-right">{(prob * 100).toFixed(1)}%</span>
              <span className="text-slate-400 text-xs w-16 truncate">{lbl}</span>
            </div>
          ))}
      </div>

      <p className="text-slate-500 text-xs">
        Predicted: <span className="text-blue-300 font-mono">{score.label}</span>
        {' · '}conf <span className="text-slate-300">{(score.confidence * 100).toFixed(1)}%</span>
        {' · '}{score.window_events} events
      </p>
    </div>
  )
}

// ── Threat card ───────────────────────────────────────────────────────────────

function ThreatCard({ report, qiScore }: { report: LlmReport; qiScore?: LlmScore }) {
  const [open, setOpen] = useState(report.threat_level === 'CRITICAL' || report.threat_level === 'HIGH')
  const s  = LEVEL[report.threat_level] ?? LEVEL.LOW
  const ev = report.evidence

  return (
    <div className={`rounded-xl border ${s.border} ${s.bg} overflow-hidden`}>
      <button className="w-full text-left px-5 py-4 flex items-center gap-4" onClick={() => setOpen(o => !o)}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-white font-bold font-mono text-lg">Node {report.node_id}</span>
            <span className={`px-2 py-0.5 rounded text-xs font-bold tracking-wide ${s.badge}`}>{report.threat_level}</span>
            <span className="bg-slate-700 text-slate-300 px-2 py-0.5 rounded text-xs font-mono">{report.attack_variant}</span>
            {report.attack_plane !== 'n/a' && (
              <span className="bg-slate-800 text-slate-400 px-2 py-0.5 rounded text-xs">{report.attack_plane}-plane</span>
            )}
            {qiScore && (
              <span className={`px-2 py-0.5 rounded text-xs font-mono ${qiScore.Q_i > 0.5 ? 'bg-red-900/50 text-red-300' : 'bg-green-900/50 text-green-300'}`}>
                Q<sub>i</sub>={qiScore.Q_i.toFixed(3)}
              </span>
            )}
          </div>
          <div className="mt-2 space-y-1">
            <ScoreBar value={report.threat_score} level={report.threat_level} label="Fusion threat score" />
          </div>
        </div>
        <div className="flex-shrink-0 text-slate-500">{open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}</div>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-4 border-t border-slate-700/50">
          <p className="text-slate-200 text-sm leading-relaxed pt-4">{report.narrative}</p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* DistilBERT Q_i */}
            {qiScore ? (
              <QiPanel score={qiScore} />
            ) : (
              <div className="bg-slate-900/60 rounded-lg p-4 flex items-center justify-center text-slate-600 text-sm">
                LLM Q_i score not yet generated
              </div>
            )}

            {/* Evidence */}
            <div className="bg-slate-900/60 rounded-lg p-4">
              <p className="text-slate-400 text-xs uppercase tracking-wide font-semibold mb-2">Evidence</p>
              <EvidRow label="ZKP Proof"        value={ev.zkp_failed ? 'FAILED' : 'VALID'} hi={ev.zkp_failed ? 'text-red-400' : 'text-green-400'} />
              <EvidRow label="Reputation"        value={ev.reputation_score.toFixed(4)}      hi={ev.reputation_score < 0.40 ? 'text-red-400' : 'text-green-400'} />
              <EvidRow label="MATD Trust"        value={ev.matd_corrected_trust.toFixed(4)} />
              <EvidRow label="FL Malicious Prob" value={`${(ev.malicious_probability * 100).toFixed(2)}%`} hi={ev.malicious_probability > 0.4 ? 'text-red-400' : 'text-green-400'} />
              <EvidRow label="FL Accuracy"       value={`${(ev.fl_local_accuracy * 100).toFixed(1)}%`}     hi={ev.fl_local_accuracy < 0.6 ? 'text-red-400' : 'text-slate-300'} />
              <EvidRow label="Interactions"      value={String(ev.total_interactions)} />
              <EvidRow label="DEBSC Triggered"   value={ev.debsc_triggered ? 'YES' : 'NO'}  hi={ev.debsc_triggered ? 'text-red-400' : 'text-green-400'} />
            </div>
          </div>

          {/* Attack pattern */}
          <div className="bg-slate-900/60 rounded-lg p-4">
            <p className="text-slate-400 text-xs uppercase tracking-wide font-semibold mb-1">
              Attack Pattern — {report.attack_pattern_label}
            </p>
            <p className="text-slate-300 text-xs leading-relaxed">{report.attack_pattern}</p>
          </div>

          {/* Recommended action */}
          <div className={`rounded-lg border ${s.border} px-4 py-3`}>
            <p className="text-slate-400 text-xs uppercase tracking-wide font-semibold mb-1">Recommended Action</p>
            <p className={`text-sm font-medium ${s.text}`}>{report.recommended_action}</p>
          </div>

          <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600">
            <span>{report.confidence_assessment}</span>
            <span className="ml-auto font-mono">{report.generated_by} · {new Date(report.generated_at).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ThreatIntelligence() {
  const [summary, setSummary]   = useState<LlmSummary | null>(null)
  const [reports, setReports]   = useState<LlmReport[]>([])
  const [qiScores, setQiScores] = useState<LlmScore[]>([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')

  useEffect(() => {
    Promise.allSettled([fetchLlmSummary(), fetchLlmReports(), fetchLlmScores()])
      .then(([s, r, q]) => {
        if (s.status === 'fulfilled') setSummary(s.value)
        if (r.status === 'fulfilled') setReports(r.value.reports)
        if (q.status === 'fulfilled') setQiScores(q.value.scores)
        if (s.status === 'rejected' && r.status === 'rejected')
          setError('No threat reports found. Run the full pipeline to generate them.')
      })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="flex items-center justify-center h-64 text-slate-400">Loading threat intelligence...</div>

  if (error && !summary && reports.length === 0) return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Brain size={22} className="text-purple-400" /> Threat Intelligence
        </h1>
      </div>
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <p className="font-semibold text-white mb-2">No threat reports available</p>
        <p className="text-slate-400 text-sm">{error}</p>
        <p className="text-xs mt-3 font-mono text-slate-500">docker compose run --rm pipeline python create_attacker_demo.py</p>
      </div>
    </div>
  )

  const sorted   = [...reports].sort((a, b) => b.threat_score - a.threat_score)
  const qiById   = Object.fromEntries(qiScores.map(s => [s.node_id, s]))
  const ss       = STATUS[summary?.network_status ?? 'SECURE'] ?? STATUS['SECURE']
  const { Icon } = ss

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Brain size={22} className="text-purple-400" /> Threat Intelligence
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          DistilBERT semantic classifier · Blockchain ZKP · FL reputation fusion
        </p>
      </div>

      {/* Network status banner */}
      {summary && (
        <div className={`rounded-xl border ${ss.border} ${ss.bg} px-6 py-5 flex items-start gap-4`}>
          <Icon size={32} className={`flex-shrink-0 mt-0.5 ${ss.color}`} />
          <div className="flex-1">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className={`text-xl font-bold ${ss.color}`}>NETWORK {summary.network_status}</h2>
              {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(lvl =>
                summary.threat_breakdown[lvl] > 0 && (
                  <span key={lvl} className={`px-2 py-0.5 rounded text-xs font-bold ${LEVEL[lvl].badge}`}>
                    {summary.threat_breakdown[lvl]} {lvl}
                  </span>
                )
              )}
            </div>
            <p className="text-slate-300 text-sm mt-2 leading-relaxed">{summary.executive_summary}</p>
            <div className="flex flex-wrap gap-x-4 mt-3 text-xs text-slate-500">
              <span>{summary.total_nodes} nodes</span>
              <span>{summary.threats_detected} threat(s)</span>
              <span>mode: {summary.scoring_mode}</span>
              {qiScores.length > 0 && <span className="text-purple-400">· DistilBERT Q_i active ({qiScores.length} nodes scored)</span>}
              <span className="ml-auto font-mono">{new Date(summary.generated_at).toLocaleString()}</span>
            </div>
          </div>
        </div>
      )}

      {/* Threat counters */}
      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(lvl => {
            const s2 = LEVEL[lvl]
            return (
              <div key={lvl} className={`rounded-xl border ${s2.border} ${s2.bg} px-4 py-3`}>
                <p className={`text-xs font-bold ${s2.text} uppercase tracking-wide`}>{lvl}</p>
                <p className="text-white text-2xl font-bold mt-1">{summary.threat_breakdown[lvl]}</p>
              </div>
            )
          })}
        </div>
      )}

      {/* Engine info */}
      <div className="flex flex-wrap items-center gap-3 bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm">
        <div className="flex items-center gap-2">
          <Brain size={14} className="text-purple-400" />
          <span className="text-slate-400">LLM:</span>
          <span className="text-white font-medium">DistilBERT fine-tuned classifier (Eq 3.23)</span>
        </div>
        <div className="flex items-center gap-2 ml-auto">
          <Cpu size={14} className="text-blue-400" />
          <span className="text-slate-400">Narratives:</span>
          <span className="text-white font-medium">
            {summary?.scoring_mode === 'llm' ? 'Claude Haiku' : 'Template engine'}
          </span>
        </div>
      </div>

      {/* Per-node threat cards */}
      <div className="space-y-3">
        <h2 className="text-slate-300 font-semibold text-sm uppercase tracking-wide">
          Node Threat Reports — sorted by fusion score
        </h2>
        {sorted.map(r => (
          <ThreatCard key={r.node_id} report={r} qiScore={qiById[r.node_id]} />
        ))}
        {sorted.length === 0 && qiScores.length > 0 && (
          <div className="text-slate-500 text-sm">No threat narratives yet. Run run_mock_llm.py to generate them.</div>
        )}
      </div>

      {/* Q_i-only view if no narratives */}
      {reports.length === 0 && qiScores.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-slate-300 font-semibold text-sm uppercase tracking-wide">DistilBERT Q_i Scores</h2>
          {[...qiScores].sort((a, b) => b.Q_i - a.Q_i).map(s => (
            <div key={s.node_id} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
              <div className="flex items-center gap-3 mb-3">
                <span className="text-white font-bold font-mono text-lg">Node {s.node_id}</span>
                <span className="bg-slate-700 text-slate-300 px-2 py-0.5 rounded text-xs font-mono">{s.label}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-mono ml-auto ${s.Q_i > 0.5 ? 'text-red-400' : 'text-green-400'}`}>
                  Q_i = {s.Q_i.toFixed(4)}
                </span>
              </div>
              <QiPanel score={s} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
