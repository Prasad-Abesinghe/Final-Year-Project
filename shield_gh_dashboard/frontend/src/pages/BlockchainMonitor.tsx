import { useEffect, useState } from 'react'
import { Link as LinkIcon, ChevronDown, ChevronUp } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, ReferenceLine, Cell } from 'recharts'
import StatusBadge from '../components/shared/StatusBadge'
import { fetchBcRecords } from '../api/client'
import type { BcRecord } from '../types'

type SortKey = 'node_id' | 'reputation_score' | 'matd_corrected_trust' | 'reputation_deficit'

export default function BlockchainMonitor() {
  const [records, setRecords] = useState<BcRecord[]>([])
  const [sortKey, setSortKey] = useState<SortKey>('node_id')
  const [sortAsc, setSortAsc] = useState(true)
  const [selected, setSelected] = useState<BcRecord | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchBcRecords()
      .then(d => setRecords(d.records))
      .finally(() => setLoading(false))
  }, [])

  const sorted = [...records].sort((a, b) => {
    const av = a[sortKey] as number, bv = b[sortKey] as number
    return sortAsc ? av - bv : bv - av
  })

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(v => !v)
    else { setSortKey(key); setSortAsc(true) }
  }

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k ? (sortAsc ? <ChevronUp size={13} /> : <ChevronDown size={13} />) : null

  const barData = [...records]
    .sort((a, b) => a.node_id - b.node_id)
    .map(r => ({ name: `V${r.node_id}`, rep: r.reputation_score, isolated: r.debsc_triggered }))

  if (loading) return <div className="text-slate-400">Loading...</div>

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <LinkIcon size={22} className="text-blue-400" /> Blockchain Monitor
        </h1>
        <p className="text-slate-400 text-sm mt-1">{records.length} bc_record files · DEBSC isolation decisions</p>
      </div>

      {/* Reputation Bar Chart */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
        <h2 className="text-slate-300 font-semibold mb-4">Reputation Scores</h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={barData} margin={{ top: 5, right: 10, bottom: 5, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 12 }} />
            <YAxis stroke="#64748b" tick={{ fontSize: 12 }} domain={[0, 1]} />
            <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
              formatter={(v: unknown) => typeof v === 'number' ? v.toFixed(4) : String(v)} />
            <ReferenceLine y={0.60} stroke="#eab308" strokeDasharray="5 5"
              label={{ value: 'Threshold 0.60', position: 'right', fill: '#eab308', fontSize: 11 }} />
            <Bar dataKey="rep" name="Reputation" radius={[4, 4, 0, 0]}>
              {barData.map((entry, i) => (
                <Cell key={i} fill={entry.isolated ? '#ef4444' : '#22c55e'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <p className="text-slate-600 text-xs mt-2">Red bars = ISOLATED nodes (below threshold + ZKP fail)</p>
      </div>

      {/* Records Table */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-700">
          <h2 className="text-slate-300 font-semibold">Blockchain Records</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-xs uppercase">
              <tr>
                {([
                  ['node_id', 'Node'],
                  ['reputation_score', 'Reputation'],
                  ['matd_corrected_trust', 'MATD Trust'],
                  ['reputation_deficit', 'Deficit'],
                ] as [SortKey, string][]).map(([k, label]) => (
                  <th key={k} className="px-4 py-3 text-left cursor-pointer hover:text-white select-none"
                    onClick={() => toggleSort(k)}>
                    <span className="flex items-center gap-1">{label}<SortIcon k={k} /></span>
                  </th>
                ))}
                <th className="px-4 py-3 text-left">ZKP</th>
                <th className="px-4 py-3 text-left">Decision</th>
                <th className="px-4 py-3 text-left">Interactions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {sorted.map(r => (
                <tr key={r.node_id}
                  className={`cursor-pointer transition-colors ${selected?.node_id === r.node_id ? 'bg-blue-900/20' : 'hover:bg-slate-700/50'}`}
                  onClick={() => setSelected(selected?.node_id === r.node_id ? null : r)}>
                  <td className="px-4 py-3 font-mono font-semibold text-white">{r.node_id}</td>
                  <td className="px-4 py-3">
                    <span className={r.reputation_score < 0.6 ? 'text-red-400 font-mono' : 'text-green-400 font-mono'}>
                      {r.reputation_score.toFixed(4)}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-300">{r.matd_corrected_trust.toFixed(4)}</td>
                  <td className="px-4 py-3 font-mono text-slate-300">{r.reputation_deficit.toFixed(4)}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-mono px-2 py-0.5 rounded-full ${r.zkp_valid ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'}`}>
                      {r.zkp_valid ? 'VALID' : 'FAIL'}
                    </span>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={r.isolation_status} small /></td>
                  <td className="px-4 py-3 text-slate-400">{r.total_interactions}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="bg-slate-800 border border-blue-700 rounded-xl p-5">
          <h2 className="text-slate-300 font-semibold mb-4">Record Detail — Node {selected.node_id}</h2>
          <pre className="text-xs font-mono text-slate-300 bg-slate-900 rounded-lg p-4 overflow-x-auto">
            {JSON.stringify(selected, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
