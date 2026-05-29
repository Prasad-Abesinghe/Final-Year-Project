import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Network, Link, BrainCircuit, Search, Shield } from 'lucide-react'

const links = [
  { to: '/',            icon: LayoutDashboard, label: 'Dashboard'     },
  { to: '/network',     icon: Network,         label: 'Network'       },
  { to: '/blockchain',  icon: Link,            label: 'Blockchain'    },
  { to: '/fl',          icon: BrainCircuit,    label: 'Federated L.'  },
  { to: '/node/1',      icon: Search,          label: 'Node Inspector'},
]

export default function Sidebar() {
  return (
    <aside className="w-56 min-h-screen bg-slate-900 border-r border-slate-700 flex flex-col">
      <div className="px-4 py-5 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <Shield className="text-blue-400" size={22} />
          <span className="font-bold text-white text-sm tracking-wide">SHIELD-GH</span>
        </div>
        <p className="text-slate-500 text-xs mt-1">Security Dashboard</p>
      </div>
      <nav className="flex-1 px-2 py-4 space-y-1">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-white'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-slate-700 text-xs text-slate-600">
        FYP · EG/2021/4377
      </div>
    </aside>
  )
}
