import { useEffect, useState } from 'react'
import { Network, X } from 'lucide-react'
import StatusBadge from '../components/shared/StatusBadge'
import { fetchTopology } from '../api/client'
import type { NetworkNode, NetworkEdge } from '../types'

const NODE_COLORS: Record<string, string> = {
  BENIGN:   '#22c55e',
  ISOLATED: '#ef4444',
  RATE_LIMIT:'#eab308',
  UNKNOWN:  '#64748b',
}

const RSU_COLOR = '#3b82f6'

export default function NetworkTopology() {
  const [nodes, setNodes]     = useState<NetworkNode[]>([])
  const [edges, setEdges]     = useState<NetworkEdge[]>([])
  const [selected, setSelected] = useState<NetworkNode | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchTopology()
      .then(d => { setNodes(d.nodes); setEdges(d.edges) })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-slate-400">Loading...</div>

  const width  = 1000
  const height = 500

  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Network size={22} className="text-blue-400" /> Network Topology
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          SDVN — Software Defined Vehicular Network · Click a node to inspect
        </p>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-sm">
        {[
          { color: '#22c55e', label: 'BENIGN' },
          { color: '#ef4444', label: 'ISOLATED' },
          { color: '#eab308', label: 'SUSPICIOUS' },
          { color: '#3b82f6', label: 'RSU' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full" style={{ background: color }} />
            <span className="text-slate-400">{label}</span>
          </div>
        ))}
      </div>

      {/* SVG topology */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full"
          style={{ maxHeight: 500 }}
        >
          {/* Edges */}
          {edges.map((e, i) => {
            const src = nodeById[e.source]
            const tgt = nodeById[e.target]
            if (!src || !tgt) return null
            return (
              <line key={i}
                x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                stroke={e.type === 'rsu-rsu' ? '#3b82f6' : '#334155'}
                strokeWidth={e.type === 'rsu-rsu' ? 2 : 1}
                strokeDasharray={e.type === 'rsu-rsu' ? '6 3' : undefined}
                opacity={0.6}
              />
            )
          })}

          {/* Nodes */}
          {nodes.map(n => {
            const isRSU  = n.type === 'rsu'
            const color  = isRSU ? RSU_COLOR : (NODE_COLORS[n.isolation_status ?? 'UNKNOWN'] ?? NODE_COLORS.UNKNOWN)
            const isSelected = selected?.id === n.id
            const r = isRSU ? 18 : 14

            return (
              <g key={n.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(selected?.id === n.id ? null : n)}>
                {isSelected && (
                  <circle cx={n.x} cy={n.y} r={r + 8} fill="none" stroke="#facc15" strokeWidth={2} opacity={0.7} />
                )}
                {isRSU ? (
                  <rect x={n.x - r} y={n.y - r} width={r * 2} height={r * 2} rx={4}
                    fill={color} opacity={0.85} />
                ) : (
                  <circle cx={n.x} cy={n.y} r={r} fill={color} opacity={0.85} />
                )}
                {/* Pulse ring for isolated nodes */}
                {n.debsc_triggered && (
                  <circle cx={n.x} cy={n.y} r={r + 4} fill="none" stroke="#ef4444" strokeWidth={1.5} opacity={0.4} />
                )}
                <text x={n.x} y={n.y + r + 14} textAnchor="middle" fontSize={11}
                  fill={isRSU ? '#93c5fd' : '#e2e8f0'} fontFamily="monospace">
                  {n.label}
                </text>
              </g>
            )
          })}
        </svg>
      </div>

      {/* Node inspector panel */}
      {selected && (
        <div className="bg-slate-800 border border-blue-700 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-white font-semibold">
              {selected.type === 'rsu' ? 'RSU' : 'Vehicle'} — {selected.label}
            </h2>
            <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white">
              <X size={18} />
            </button>
          </div>

          {selected.type === 'rsu' ? (
            <p className="text-slate-400 text-sm">Road-Side Unit — connects vehicles to SDVN backbone</p>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Node ID',        value: selected.node_id },
                { label: 'DEBSC Status',   value: <StatusBadge status={selected.isolation_status ?? 'UNKNOWN'} small /> },
                { label: 'Reputation',     value: selected.reputation_score?.toFixed(4) ?? 'N/A' },
                { label: 'ZKP',
                  value: selected.zkp_valid != null
                    ? <span className={selected.zkp_valid ? 'text-green-400' : 'text-red-400'}>
                        {selected.zkp_valid ? 'VALID' : 'FAIL'}
                      </span>
                    : 'N/A'
                },
                { label: 'Malicious Prob', value: selected.malicious_prob != null ? `${(selected.malicious_prob * 100).toFixed(2)}%` : 'N/A' },
                { label: 'Local Accuracy', value: selected.local_accuracy != null ? `${(selected.local_accuracy * 100).toFixed(1)}%` : 'N/A' },
                { label: 'RSU',            value: selected.rsu ?? 'N/A' },
                { label: 'Isolated',       value: selected.debsc_triggered
                  ? <span className="text-red-400">YES</span>
                  : <span className="text-green-400">NO</span>
                },
              ].map(({ label, value }) => (
                <div key={label} className="bg-slate-900 rounded-lg p-3">
                  <p className="text-slate-500 text-xs">{label}</p>
                  <p className="text-white text-sm font-mono mt-1">{value}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
