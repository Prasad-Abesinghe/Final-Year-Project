import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import Dashboard from './pages/Dashboard'
import NetworkTopology from './pages/NetworkTopology'
import BlockchainMonitor from './pages/BlockchainMonitor'
import FLDashboard from './pages/FLDashboard'
import NodeInspector from './pages/NodeInspector'
import ThreatIntelligence from './pages/ThreatIntelligence'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-slate-950">
        <Sidebar />
        <main className="flex-1 p-6 overflow-auto">
          <Routes>
            <Route path="/"           element={<Dashboard />} />
            <Route path="/network"    element={<NetworkTopology />} />
            <Route path="/blockchain" element={<BlockchainMonitor />} />
            <Route path="/fl"         element={<FLDashboard />} />
            <Route path="/node/:id"   element={<NodeInspector />} />
            <Route path="/threat"     element={<ThreatIntelligence />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
