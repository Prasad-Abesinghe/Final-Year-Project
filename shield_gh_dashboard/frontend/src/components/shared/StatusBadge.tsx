interface Props { status: string; small?: boolean }

const map: Record<string, string> = {
  BENIGN:                'bg-green-900 text-green-300 border border-green-700',
  ISOLATED:              'bg-red-900 text-red-300 border border-red-700',
  RATE_LIMIT:            'bg-yellow-900 text-yellow-300 border border-yellow-700',
  REQUIRE_ZKP_PER_BATCH: 'bg-orange-900 text-orange-300 border border-orange-700',
  FALSE_POSITIVE_BLOCKED:'bg-blue-900 text-blue-300 border border-blue-700',
  UNKNOWN:               'bg-slate-800 text-slate-400 border border-slate-600',
}

export default function StatusBadge({ status, small }: Props) {
  const cls = map[status] ?? map.UNKNOWN
  return (
    <span className={`${cls} ${small ? 'text-xs px-2 py-0.5' : 'text-sm px-3 py-1'} rounded-full font-mono font-medium`}>
      {status}
    </span>
  )
}
