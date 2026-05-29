import { useEffect, useState } from 'react'
import { Shield, AlertTriangle, BrainCircuit, CheckCircle, Database, Activity } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts'
import SummaryCard from '../components/shared/SummaryCard'
import StatusBadge from '../components/shared/StatusBadge'
import { fetchSummary, fetchBcRecords, fetchRoundLog } from '../api/client'
import type { Summary, BcRecord, RoundEntry } from '../types'

export default function Dashboard() {
  const [summary, setSummary]   = useState<Summary | null>(null)
  const [records, setRecords]   = useState<BcRecord[]>([])
  const [rounds, setRounds]     = useState<RoundEntry[]>([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')

  useEffect(() => {
    Promise.all([fetchSummary(), fetchBcRecords(), fetchRoundLog()])
      .then(([s, bc, rl]) => {
        setSummary(s)
        setRecords(bc.records)
        setRounds(rl.rounds)
      })
      .catch(() => setError('Cannot connect to backend. Start the API server first.'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="flex items-center justify-center h-64 text-slate-400">Loading...</div>
  if (error)   return (
    <div className="bg-red-900/30 border border-red-700 rounded-xl p-6 text-red-300">
      <p className="font-bold mb-1">Connection Error</p>
      <p className="text-sm">{error}</p>
      <p className="text-xs mt-2 text-red-400">Run: <code className="font-mono bg-red-950 px-1 rounded">uvicorn main:app --reload --port 8000</code> in the backend folder.</p>
    </div>
  )

  const isolated = records.filter(r => r.debsc_triggered)

  // Build chart data — simulate round-by-round loss for visual (use round acceptance as proxy)
  const chartData = rounds.map(r => ({
    round: r.round,
    accepted: r.accepted,
    rejected_count: r.rejected.length,
  }))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-slate-400 text-sm mt-1">SHIELD-GH system overview — Blockchain + Federated Learning</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <SummaryCard title="Vehicles Monitored" value={summary!.total_vehicles_monitored}
          sub="blockchain records" icon={Shield} color="blue" />
        <SummaryCard title="Nodes Isolated" value={summary!.total_isolated}
          sub="DEBSC triggered" icon={AlertTriangle} color="red" />
        <SummaryCard title="FL Rounds" value={summary!.fl_rounds_completed}
          sub={`avg accuracy ${(summary!.fl_avg_accuracy * 100).toFixed(1)}%`} icon={BrainCircuit} color="green" />
        <SummaryCard title="Gradient Commits" value={summary!.gradient_commits}
          sub={`${summary!.gradient_accepted} accepted · ${summary!.gradient_rejected} rejected`} icon={Database} color="yellow" />
      </div>

      {/* System Status */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
        <h2 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
          <Activity size={16} /> System Status
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { label: 'Blockchain Module',  detail: `${summary!.total_vehicles_monitored} records · ${summary!.total_isolated} isolated`, ok: true },
            { label: 'FL Module',          detail: `${summary!.fl_rounds_completed} rounds · ${summary!.gradient_commits} gradients verified`, ok: true },
            { label: 'PQC Mitigation',     detail: 'Dilithium + Kyber active', ok: summary!.pqc_active },
          ].map(({ label, detail, ok }) => (
            <div key={label} className="flex items-start gap-3 bg-slate-900 rounded-lg p-3">
              <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${ok ? 'bg-green-400' : 'bg-red-400'}`} />
              <div>
                <p className="text-white text-sm font-medium">{label}</p>
                <p className="text-slate-500 text-xs">{detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Isolation Events */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <h2 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle size={16} className="text-red-400" /> Isolation Events
          </h2>
          {isolated.length === 0 ? (
            <p className="text-slate-500 text-sm">No nodes isolated.</p>
          ) : (
            <div className="space-y-3">
              {isolated.map(r => (
                <div key={r.node_id} className="flex items-center justify-between bg-red-900/20 border border-red-800/40 rounded-lg px-4 py-3">
                  <div>
                    <p className="text-white text-sm font-mono font-semibold">Node {r.node_id}</p>
                    <p className="text-red-400 text-xs mt-0.5">
                      ZKP {r.zkp_valid ? 'VALID' : 'FAIL'} · Rep {r.reputation_score.toFixed(3)} · Deficit {r.reputation_deficit.toFixed(3)}
                    </p>
                  </div>
                  <StatusBadge status={r.isolation_status} small />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* FL Round Log Chart */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <h2 className="text-slate-300 font-semibold mb-4 flex items-center gap-2">
            <CheckCircle size={16} className="text-green-400" /> FL Gradient Verification per Round
          </h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="round" stroke="#64748b" tick={{ fontSize: 11 }} label={{ value: 'Round', position: 'insideBottom', offset: -2, fill: '#64748b', fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line type="monotone" dataKey="accepted" name="Accepted" stroke="#22c55e" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="rejected_count" name="Rejected" stroke="#ef4444" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
