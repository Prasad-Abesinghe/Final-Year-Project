import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Search, ChevronLeft, ChevronRight, Brain, Zap, Cloud } from 'lucide-react'
import StatusBadge from '../components/shared/StatusBadge'
import { fetchBcRecords, fetchFlScores, fetchLlmScores } from '../api/client'
import type { BcRecord, FlScore, LlmScore } from '../types'

export default function NodeInspector() {
  const { id }         = useParams()
  const navigate       = useNavigate()
  const [bcRecords, setBcRecords] = useState<BcRecord[]>([])
  const [flScores, setFlScores]   = useState<FlScore[]>([])
  const [llmScores, setLlmScores] = useState<LlmScore[]>([])
  const [loading, setLoading]     = useState(true)

  useEffect(() => {
    Promise.allSettled([fetchBcRecords(), fetchFlScores(), fetchLlmScores()])
      .then(([bc, fl, llm]) => {
        if (bc.status  === 'fulfilled') setBcRecords(bc.value.records)
        if (fl.status  === 'fulfilled') setFlScores(fl.value.scores)
        if (llm.status === 'fulfilled') setLlmScores(llm.value.scores)
      })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-slate-400">Loading...</div>

  const allNodeIds = [...new Set([...bcRecords.map(r => r.node_id), ...flScores.map(s => s.node_id)])].sort((a, b) => a - b)
  const currentId  = parseInt(id ?? String(allNodeIds[0]))
  const bcRecord   = bcRecords.find(r => r.node_id === currentId)
  const flScore    = flScores.find(s => s.node_id === currentId)
  const llmScore   = llmScores.find(s => s.node_id === currentId)
  const currentIdx = allNodeIds.indexOf(currentId)

  const prev = allNodeIds[currentIdx - 1]
  const next = allNodeIds[currentIdx + 1]

  return (
    <div className="space-y-6">
      {/* Header + navigation */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Search size={22} className="text-blue-400" /> Node Inspector
          </h1>
          <p className="text-slate-400 text-sm mt-1">Full blockchain + FL data for one vehicle node</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => prev != null && navigate(`/node/${prev}`)}
            disabled={prev == null}
            className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white disabled:opacity-30">
            <ChevronLeft size={16} />
          </button>
          <select
            value={currentId}
            onChange={e => navigate(`/node/${e.target.value}`)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white text-sm font-mono">
            {allNodeIds.map(nid => (
              <option key={nid} value={nid}>Node {nid}</option>
            ))}
          </select>
          <button onClick={() => next != null && navigate(`/node/${next}`)}
            disabled={next == null}
            className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white disabled:opacity-30">
            <ChevronRight size={16} />
          </button>
        </div>
      </div>

      {/* Status Banner */}
      {bcRecord && (
        <div className={`rounded-xl px-6 py-4 border flex items-center gap-4 ${
          bcRecord.debsc_triggered
            ? 'bg-red-900/20 border-red-700'
            : 'bg-green-900/20 border-green-700'
        }`}>
          <span className={`text-4xl font-bold font-mono ${bcRecord.debsc_triggered ? 'text-red-400' : 'text-green-400'}`}>
            {currentId}
          </span>
          <div>
            <p className="text-white font-semibold">Node {currentId}</p>
            <StatusBadge status={bcRecord.isolation_status} />
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Blockchain Data */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
          <h2 className="text-blue-400 font-semibold text-sm uppercase tracking-wide">Blockchain Record</h2>
          {bcRecord ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Record ID',       value: bcRecord.record_id },
                  { label: 'Reputation Score',value: bcRecord.reputation_score.toFixed(4) },
                  { label: 'MATD Trust',      value: bcRecord.matd_corrected_trust.toFixed(4) },
                  { label: 'Deficit',         value: bcRecord.reputation_deficit.toFixed(4) },
                  { label: 'Interactions',    value: bcRecord.total_interactions },
                  { label: 'Timestamp',       value: bcRecord.timestamp.toFixed(2) + 's' },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-slate-900 rounded-lg p-3">
                    <p className="text-slate-500 text-xs">{label}</p>
                    <p className="text-white font-mono text-sm mt-0.5">{value}</p>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-900 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">ZKP Proof</p>
                  <p className={`font-mono text-sm font-bold mt-0.5 ${bcRecord.zkp_valid ? 'text-green-400' : 'text-red-400'}`}>
                    {bcRecord.zkp_valid ? 'VALID' : 'FAIL'}
                  </p>
                </div>
                <div className="bg-slate-900 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">DEBSC Triggered</p>
                  <p className={`font-mono text-sm font-bold mt-0.5 ${bcRecord.debsc_triggered ? 'text-red-400' : 'text-green-400'}`}>
                    {bcRecord.debsc_triggered ? 'YES' : 'NO'}
                  </p>
                </div>
              </div>
            </>
          ) : (
            <p className="text-slate-500 text-sm">No blockchain record for this node.</p>
          )}
        </div>

        {/* FL Data */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
          <h2 className="text-green-400 font-semibold text-sm uppercase tracking-wide">Federated Learning Score</h2>
          {flScore ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Malicious Prob',   value: `${(flScore.malicious_prob * 100).toFixed(2)}%`,
                    highlight: flScore.malicious_prob > 0.4 ? 'text-red-400' : 'text-green-400' },
                  { label: 'Prediction',        value: flScore.predicted_variant, highlight: 'text-blue-300' },
                  { label: 'Confidence',        value: `${(flScore.confidence * 100).toFixed(1)}%`, highlight: 'text-white' },
                  { label: 'Local Accuracy',    value: `${(flScore.local_accuracy * 100).toFixed(1)}%`,
                    highlight: flScore.local_accuracy < 0.9 ? 'text-red-400' : 'text-white' },
                  { label: 'FL Round',          value: flScore.round_num, highlight: 'text-white' },
                  { label: 'Timestamp',         value: flScore.timestamp.toFixed(1) + 's', highlight: 'text-white' },
                ].map(({ label, value, highlight }) => (
                  <div key={label} className="bg-slate-900 rounded-lg p-3">
                    <p className="text-slate-500 text-xs">{label}</p>
                    <p className={`font-mono text-sm mt-0.5 font-bold ${highlight}`}>{value}</p>
                  </div>
                ))}
              </div>

              {/* Malicious probability bar */}
              <div className="bg-slate-900 rounded-lg p-3">
                <p className="text-slate-500 text-xs mb-2">Malicious Probability</p>
                <div className="bg-slate-700 rounded-full h-4 overflow-hidden">
                  <div
                    className={`h-4 rounded-full transition-all ${flScore.malicious_prob > 0.4 ? 'bg-red-500' : 'bg-green-500'}`}
                    style={{ width: `${Math.max(flScore.malicious_prob * 100, 1)}%` }}
                  />
                </div>
                <p className="text-slate-400 text-xs mt-1">{(flScore.malicious_prob * 100).toFixed(3)}%</p>
              </div>
            </>
          ) : (
            <p className="text-slate-500 text-sm">No FL score for this node.</p>
          )}
        </div>
      </div>

      {/* LLM Q_i Score */}
      {llmScore && (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
          <h2 className="text-purple-400 font-semibold text-sm uppercase tracking-wide flex items-center gap-2">
            <Brain size={14} /> DistilBERT LLM Score — Q<sub>i</sub>(t) (Eq 3.23)
          </h2>
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Q_i Threat Score', value: llmScore.Q_i.toFixed(4),
                highlight: llmScore.Q_i > 0.5 ? 'text-red-400' : 'text-green-400' },
              { label: 'Predicted Label',  value: llmScore.label,    highlight: 'text-blue-300' },
              { label: 'Confidence',       value: `${(llmScore.confidence * 100).toFixed(1)}%`, highlight: 'text-white' },
              { label: 'Inference Tier',   value: llmScore.tier_used,
                highlight: llmScore.tier_used === 'EDGE' ? 'text-yellow-400' : 'text-blue-400' },
              { label: 'Latency',          value: `${llmScore.latency_ms.toFixed(0)} ms`, highlight: 'text-white' },
              { label: 'Window Events',    value: String(llmScore.window_events), highlight: 'text-white' },
            ].map(({ label, value, highlight }) => (
              <div key={label} className="bg-slate-900 rounded-lg p-3">
                <p className="text-slate-500 text-xs">{label}</p>
                <p className={`font-mono text-sm mt-0.5 font-bold ${highlight}`}>{value}</p>
              </div>
            ))}
          </div>
          {/* Q_i bar */}
          <div className="bg-slate-900 rounded-lg p-3">
            <p className="text-slate-500 text-xs mb-2">Q<sub>i</sub>(t) — Semantic Threat Probability</p>
            <div className="bg-slate-700 rounded-full h-4 overflow-hidden">
              <div className={`h-4 rounded-full ${llmScore.Q_i > 0.5 ? 'bg-red-500' : 'bg-green-500'}`}
                   style={{ width: `${Math.max(llmScore.Q_i * 100, 1)}%` }} />
            </div>
            <p className="text-slate-400 text-xs mt-1">{(llmScore.Q_i * 100).toFixed(3)}% — 1 - P(BENIGN)</p>
          </div>
          {/* Softmax breakdown */}
          <div className="bg-slate-900 rounded-lg p-3">
            <p className="text-slate-500 text-xs mb-2">Softmax Probabilities (all 7 classes)</p>
            <div className="space-y-1.5">
              {Object.entries(llmScore.softmax_probs).sort(([, a], [, b]) => b - a).map(([lbl, p]) => (
                <div key={lbl} className="flex items-center gap-2">
                  <span className="text-slate-400 text-xs font-mono w-14 text-right flex-shrink-0">{lbl}</span>
                  <div className="flex-1 bg-slate-700 rounded-full h-2 overflow-hidden">
                    <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${p * 100}%` }} />
                  </div>
                  <span className="text-slate-400 text-xs font-mono w-12">{(p * 100).toFixed(1)}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Raw JSON */}
      {(bcRecord || flScore) && (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <h2 className="text-slate-400 font-semibold text-sm uppercase tracking-wide mb-3">Raw Data</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {bcRecord && (
              <div>
                <p className="text-blue-400 text-xs mb-2 font-mono">bc_record_{currentId}.json</p>
                <pre className="text-xs font-mono text-slate-400 bg-slate-900 rounded-lg p-3 overflow-x-auto max-h-48">
                  {JSON.stringify(bcRecord, null, 2)}
                </pre>
              </div>
            )}
            {flScore && (
              <div>
                <p className="text-green-400 text-xs mb-2 font-mono">fl_score_{currentId}.json</p>
                <pre className="text-xs font-mono text-slate-400 bg-slate-900 rounded-lg p-3 overflow-x-auto max-h-48">
                  {JSON.stringify(flScore, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
