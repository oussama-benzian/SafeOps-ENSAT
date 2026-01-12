import { useState, useEffect } from 'react'
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    Filler
} from 'chart.js'
import { Line } from 'react-chartjs-2'
import { RefreshCw, BarChart3, Clock, Brain, CheckCircle } from 'lucide-react'

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    Filler
)

const API_BASE = '/api/v1'

function SeverityBadge({ severity }) {
    const badges = {
        CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/30',
        HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
        MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
        LOW: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
    }

    return (
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${badges[severity] || 'bg-slate-500/20 text-slate-400 border border-slate-500/30'}`}>
            {severity}
        </span>
    )
}

function AnomalyCard({ anomaly }) {
    return (
        <div className="card animate-fade-in">
            <div className="flex items-start justify-between">
                <div className="flex-1">
                    <div className="flex items-center gap-2 mb-3">
                        <SeverityBadge severity={anomaly.severity} />
                        <span className="text-xs text-slate-500 px-2 py-0.5 rounded-lg bg-slate-800 border border-slate-700">
                            {anomaly.anomaly_type}
                        </span>
                    </div>

                    <h3 className="text-lg font-semibold text-white mb-2">
                        {anomaly.title}
                    </h3>

                    <p className="text-sm text-slate-400 mb-4">
                        {anomaly.description}
                    </p>

                    <div className="flex items-center gap-4 text-xs text-slate-500">
                        <span className="flex items-center gap-1.5">
                            <RefreshCw className="w-3 h-3" />
                            {anomaly.pipeline_id}
                        </span>
                        <span className="flex items-center gap-1.5">
                            <BarChart3 className="w-3 h-3" />
                            {anomaly.metric_name}
                        </span>
                        <span className="flex items-center gap-1.5">
                            <Clock className="w-3 h-3" />
                            {new Date(anomaly.detected_at).toLocaleString()}
                        </span>
                    </div>
                </div>

            </div>
        </div>
    )
}

function AnomalyTrendChart({ anomalies }) {
    const dates = [...new Set(anomalies.map(a =>
        new Date(a.detected_at).toLocaleDateString()
    ))].slice(-7)

    const countsByDate = dates.map(date =>
        anomalies.filter(a => new Date(a.detected_at).toLocaleDateString() === date).length
    )

    const data = {
        labels: dates,
        datasets: [{
            label: 'Anomalies Detected',
            data: countsByDate,
            borderColor: '#6366f1',
            backgroundColor: 'rgba(99, 102, 241, 0.1)',
            fill: true,
            tension: 0.4,
            pointBackgroundColor: '#6366f1',
            pointBorderColor: '#6366f1',
            pointRadius: 4,
            pointHoverRadius: 6
        }]
    }

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: { color: '#334155' },
                ticks: { color: '#94a3b8' }
            },
            x: {
                grid: { display: false },
                ticks: { color: '#94a3b8' }
            }
        }
    }

    return (
        <div className="card animate-fade-in">
            <h3 className="text-lg font-semibold text-white mb-6">Anomaly Trend (Last 7 Days)</h3>
            <div className="h-64">
                <Line data={data} options={options} />
            </div>
        </div>
    )
}

export default function Anomalies() {
    const [anomalies, setAnomalies] = useState([])
    const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 })
    const [loading, setLoading] = useState(true)
    const [filter, setFilter] = useState('')

    useEffect(() => {
        fetchData()
    }, [])

    const fetchData = async () => {
        try {
            const anomalyRes = await fetch(`${API_BASE}/anomaly/anomalies?limit=100`)
            if (anomalyRes.ok) {
                const data = await anomalyRes.json()
                if (data.success) {
                    setAnomalies(data.data || [])
                }
            }

            const statsRes = await fetch(`${API_BASE}/anomaly/stats`)
            if (statsRes.ok) {
                const data = await statsRes.json()
                if (data.success) {
                    setStats(data.data || { total: 0, critical: 0, high: 0, medium: 0, low: 0 })
                }
            }
        } catch (error) {
            console.error('Error fetching anomalies:', error)
        } finally {
            setLoading(false)
        }
    }

    const handleTrainModel = async () => {
        if (!confirm('This will retrain the ML model with historical data. Continue?')) return

        try {
            const res = await fetch(`${API_BASE}/anomaly/train`, { method: 'POST' })
            if (res.ok) {
                const data = await res.json()
                if (data.success) {
                    alert('Model trained successfully!')
                } else {
                    alert('Training failed: ' + (data.error || 'Unknown error'))
                }
            }
        } catch (error) {
            console.error('Training error:', error)
            alert('Training failed')
        }
    }

    const filteredAnomalies = filter
        ? anomalies.filter(a => a.severity === filter)
        : anomalies

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="w-12 h-12 rounded-full border-4 border-indigo-500/30 border-t-indigo-500 animate-spin"></div>
            </div>
        )
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white">Anomaly Detection</h1>
                    <p className="text-slate-400">ML-powered behavioral analysis of your pipelines</p>
                </div>

                <button onClick={fetchData} className="btn btn-secondary flex items-center gap-2">
                    <RefreshCw className="w-4 h-4" /> Refresh
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="card p-4">
                    <p className="text-sm text-slate-400">Total (7 days)</p>
                    <p className="text-2xl font-bold text-white">{stats.total || 0}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-critical">
                    <p className="text-sm text-red-400">Critical</p>
                    <p className="text-2xl font-bold text-red-300">{stats.critical || 0}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-high">
                    <p className="text-sm text-orange-400">High</p>
                    <p className="text-2xl font-bold text-orange-300">{stats.high || 0}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-medium">
                    <p className="text-sm text-yellow-400">Medium</p>
                    <p className="text-2xl font-bold text-yellow-300">{stats.medium || 0}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-low">
                    <p className="text-sm text-emerald-400">Low</p>
                    <p className="text-2xl font-bold text-emerald-300">{stats.low || 0}</p>
                </div>
            </div>

            {/* Trend Chart */}
            {anomalies.length > 0 && <AnomalyTrendChart anomalies={anomalies} />}

            {/* Filter */}
            <div className="flex gap-4 items-center">
                <span className="text-sm text-slate-500">Filter by severity:</span>
                <div className="flex gap-2">
                    <button
                        onClick={() => setFilter('')}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${filter === ''
                            ? 'bg-indigo-600 text-white'
                            : 'bg-slate-800 text-slate-400 border border-slate-700 hover:text-white'
                            }`}
                    >
                        All
                    </button>
                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                        <button
                            key={sev}
                            onClick={() => setFilter(sev)}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${filter === sev
                                ? 'bg-indigo-600 text-white'
                                : 'bg-slate-800 text-slate-400 border border-slate-700 hover:text-white'
                                }`}
                        >
                            {sev}
                        </button>
                    ))}
                </div>
            </div>

            {/* Anomaly List */}
            <div className="space-y-4">
                {filteredAnomalies.length === 0 ? (
                    <div className="text-center py-16 card">
                        <CheckCircle className="w-12 h-12 text-emerald-400 mx-auto" />
                        <p className="mt-4 text-lg font-semibold text-white">No anomalies detected</p>
                        <p className="text-slate-400">Your pipelines are behaving normally</p>
                    </div>
                ) : (
                    filteredAnomalies.map((anomaly, index) => (
                        <AnomalyCard key={anomaly.id || index} anomaly={anomaly} />
                    ))
                )}
            </div>
        </div>
    )
}
