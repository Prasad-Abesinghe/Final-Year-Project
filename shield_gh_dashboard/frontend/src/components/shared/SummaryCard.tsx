import type { LucideIcon } from 'lucide-react'

interface Props {
  title: string
  value: string | number
  sub?: string
  icon: LucideIcon
  color?: 'blue' | 'red' | 'green' | 'yellow'
}

const colorMap = {
  blue:   'text-blue-400 bg-blue-900/30',
  red:    'text-red-400 bg-red-900/30',
  green:  'text-green-400 bg-green-900/30',
  yellow: 'text-yellow-400 bg-yellow-900/30',
}

export default function SummaryCard({ title, value, sub, icon: Icon, color = 'blue' }: Props) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-slate-400 text-sm">{title}</p>
          <p className="text-3xl font-bold text-white mt-1">{value}</p>
          {sub && <p className="text-slate-500 text-xs mt-1">{sub}</p>}
        </div>
        <div className={`p-2 rounded-lg ${colorMap[color]}`}>
          <Icon size={22} className={colorMap[color].split(' ')[0]} />
        </div>
      </div>
    </div>
  )
}
