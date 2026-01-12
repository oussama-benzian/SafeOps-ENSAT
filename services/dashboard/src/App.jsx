import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, Lock, RefreshCw, AlertTriangle, Activity, Clock } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Vulnerabilities from './pages/Vulnerabilities'
import Pipelines from './pages/Pipelines'
import Anomalies from './pages/Anomalies'

// Sidebar Navigation
function Sidebar() {
    const location = useLocation()

    const navItems = [
        { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
        { path: '/vulnerabilities', icon: Lock, label: 'Vulnerabilities' },
        { path: '/pipelines', icon: RefreshCw, label: 'Pipelines' },
        { path: '/anomalies', icon: AlertTriangle, label: 'Anomalies' },
    ]

    return (
        <aside className="fixed left-0 top-0 h-full w-72 p-4 bg-slate-900 border-r border-slate-700">
            {/* Logo */}
            <div className="flex items-center gap-4 mb-10 px-2">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-indigo-600">
                    <Shield className="w-6 h-6 text-white" />
                </div>
                <div>
                    <h1 className="text-xl font-bold text-white">SafeOps</h1>
                    <p className="text-xs text-slate-400">CI/CD Security Platform</p>
                </div>
            </div>

            {/* Navigation */}
            <nav className="space-y-2">
                {navItems.map(item => {
                    const Icon = item.icon
                    const isActive = location.pathname === item.path
                    return (
                        <Link
                            key={item.path}
                            to={item.path}
                            className={`flex items-center gap-4 px-4 py-3.5 rounded-lg transition-all duration-200 ${isActive
                                    ? 'bg-indigo-600 text-white'
                                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                                }`}
                        >
                            <Icon className="w-5 h-5" />
                            <span className="font-medium">{item.label}</span>
                        </Link>
                    )
                })}
            </nav>

            {/* System Status Card */}
            <div className="absolute bottom-4 left-4 right-4">
                <div className="rounded-lg p-4 bg-slate-800 border border-slate-700">
                    <div className="flex items-center gap-3 mb-2">
                        <Activity className="w-4 h-4 text-emerald-400" />
                        <span className="text-sm font-medium text-slate-300">System Status</span>
                    </div>
                    <p className="text-xs text-slate-500">All services operational</p>
                </div>
            </div>
        </aside>
    )
}

// Header
function Header() {
    const [time, setTime] = useState(new Date())

    useEffect(() => {
        const timer = setInterval(() => setTime(new Date()), 1000)
        return () => clearInterval(timer)
    }, [])

    return (
        <header className="px-8 py-5 flex items-center justify-between bg-slate-900/50 border-b border-slate-800">
            <div>
                <h2 className="text-xl font-bold text-white">Security Overview</h2>
                <p className="text-sm text-slate-400">Monitor your CI/CD pipeline security in real-time</p>
            </div>

            <div className="flex items-center gap-6">
                {/* Time Display */}
                <div className="flex items-center gap-3 text-right">
                    <Clock className="w-5 h-5 text-slate-400" />
                    <div>
                        <p className="text-sm font-medium text-slate-200">
                            {time.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' })}
                        </p>
                        <p className="text-xs text-slate-400">
                            {time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                        </p>
                    </div>
                </div>
            </div>
        </header>
    )
}

function App() {
    return (
        <Router>
            <div className="flex min-h-screen bg-slate-950">
                <Sidebar />
                <div className="flex-1 ml-72">
                    <Header />
                    <main className="p-8">
                        <Routes>
                            <Route path="/" element={<Dashboard />} />
                            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                            <Route path="/pipelines" element={<Pipelines />} />
                            <Route path="/anomalies" element={<Anomalies />} />
                        </Routes>
                    </main>
                </div>
            </div>
        </Router>
    )
}

export default App
