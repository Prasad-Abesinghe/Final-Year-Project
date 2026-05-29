import { useEffect, useState } from 'react'
import { BrainCircuit, Database } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts'
import { fetchFlScores, fetchRoundLog, fetchGradientLedger } from '../api/client'
import type { FlScore, RoundEntry, LedgerEntry } from '../types'

const NODE_COLORS = ['#22c55e','#3b82f6','#a78bfa','#f59e0b','#06b6d4','#ec4899','#84cc16','#ef4444']

export default function FLDashboard() {
  const [scores, setScores]   = useState<FlScore[]>([])
  const [rounds, setRounds]   = useState<RoundEntry[]>([])
  const [ledger, setLedger]   = useState<LedgerEntry[]>([])
  const [search, setSearch]   = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([fetchFlScores(), fetchRoundLog(), fetchGradientLedger()])
      .then(([fl, rl, lg]) => {
        setScores(fl.scores)
        setRounds(rl.rounds)
        setLedger(lg.entries)
      })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-slate-400">Loading...</div>

  // Build multi-line chart data: one data point per round, accepted count
  const chartData = rounds.map(r => ({ round: r.round, accepted: r.accepted, rejected: r.rejected.length }))

  // Accuracy bar data
  const accData = scores.map(s => ({ node: `N${s.node_id}`, acc: s.local_accuracy, mal: s.malicious_prob }))

  const filtered = ledger.filter(e => search === '' || e.key.includes(search) || e.hash.includes(search))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <BrainCircuit size={22} className="text-green-400" /> Federated Learning
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          {rounds.length} rounds · {scores.length} clients · {ledger.length} gradient commits
        </p>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Accepted per round */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <h2 className="text-slate-300 font-semibold mb-4">Client Acceptance per Round</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="round" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line type="monotone" dataKey="accepted" stroke="#22c55e" strokeWidth={2} dot={false} name="Accepted" />
              <Line type="monotone" dataKey="rejected" stroke="#ef4444" strokeWidth={2} dot={false} name="Rejected" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Per-node local accuracy */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <h2 className="text-slate-300 font-semibold mb-4">Per-Node Local Accuracy</h2>
          <div className="space-y-2">
            {accData.map((d, i) => (
              <div key={d.node} className="flex items-center gap-3">
                <span className="text-xs font-mono text-slate-400 w-8">{d.node}</span>
                <div className="flex-1 bg-slate-700 rounded-full h-3">
                  <div
                    className="h-3 rounded-full transition-all"
                    style={{ width: `${d.acc * 100}%`, background: NODE_COLORS[i % NODE_COLORS.length] }}
                  />
                </div>
                <span className="text-xs font-mono text-white w-12 text-right">{(d.acc * 100).toFixed(1)}%</span>
                {d.acc < 0.9 && <span className="text-xs text-red-400">LOW</span>}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* FL Scores Table */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700">
          <h2 className="text-slate-300 font-semibold">FL Scores — Round {scores[0]?.round_num}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-xs uppercase">
              <tr>
                <th className="px-4 py-3 text-left">Node</th>
                <th className="px-4 py-3 text-left">Malicious Prob</th>
                <th className="px-4 py-3 text-left">Prediction</th>
                <th className="px-4 py-3 text-left">Confidence</th>
                <th className="px-4 py-3 text-left">Local Accuracy</th>
                <th className="px-4 py-3 text-left">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {scores.map(s => {
                const isLow = s.local_accuracy < 0.9
                return (
                  <tr key={s.node_id} className={isLow ? 'bg-red-900/10' : ''}>
                    <td className="px-4 py-3 font-mono font-bold text-white">{s.node_id}</td>
                    <td className="px-4 py-3 font-mono">
                      <span className={s.malicious_prob > 0.4 ? 'text-red-400' : 'text-green-400'}>
                        {(s.malicious_prob * 100).toFixed(2)}%
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-blue-300">{s.predicted_variant}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{(s.confidence * 100).toFixed(1)}%</td>
                    <td className="px-4 py-3 font-mono">
                      <span className={s.local_accuracy < 0.9 ? 'text-red-400' : 'text-slate-300'}>
                        {(s.local_accuracy * 100).toFixed(1)}%
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {isLow
                        ? <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-red-900 text-red-300">LOW ACC</span>
                        : <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-green-900 text-green-300">OK</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Gradient Ledger */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700 flex items-center justify-between">
          <h2 className="text-slate-300 font-semibold flex items-center gap-2">
            <Database size={16} /> Blockchain Gradient Ledger ({ledger.length} entries)
          </h2>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by key or hash..."
            className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-300 w-56 focus:outline-none focus:border-blue-500"
          />
        </div>
        <div className="max-h-64 overflow-y-auto">
          <table className="w-full text-xs font-mono">
            <thead className="bg-slate-900 text-slate-500 uppercase sticky top-0">
              <tr>
                <th className="px-4 py-2 text-left">Key</th>
                <th className="px-4 py-2 text-left">Hash (truncated)</th>
                <th className="px-4 py-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {filtered.slice(0, 60).map(e => (
                <tr key={e.key} className="hover:bg-slate-700/30">
                  <td className="px-4 py-1.5 text-blue-300">{e.key}</td>
                  <td className="px-4 py-1.5 text-slate-400">{e.hash}</td>
                  <td className="px-4 py-1.5 text-green-400">Verified</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
