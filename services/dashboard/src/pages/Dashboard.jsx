import { useState, useEffect } from 'react'
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    BarElement,
    Title,
    Tooltip,
    Legend,
    ArcElement,
    PointElement,
    LineElement
} from 'chart.js'
import { Doughnut } from 'react-chartjs-2'
import { Lock, RefreshCw, Search, FileText, Settings, ArrowRight } from 'lucide-react'

ChartJS.register(
    CategoryScale,
    LinearScale,
    BarElement,
    Title,
    Tooltip,
    Legend,
    ArcElement,
    PointElement,
    LineElement
)

const API_BASE = '/api/v1'

// Stats Card Component
function StatsCard({ icon: Icon, label, value, change, changeType = 'neutral' }) {
    const changeColors = {
        positive: 'text-emerald-400 bg-emerald-500/10',
        negative: 'text-red-400 bg-red-500/10',
        neutral: 'text-slate-400 bg-slate-500/10'
    }

    return (
        <div className="card animate-fade-in">
            <div className="flex items-center justify-between">
                <div>
                    <p className="text-sm font-medium text-slate-400">{label}</p>
                    <p className="mt-2 text-4xl font-bold text-white">{value}</p>
                    {change && (
                        <span className={`inline-flex items-center px-2.5 py-1 mt-3 rounded-lg text-xs font-medium ${changeColors[changeType]}`}>
                            {change}
                        </span>
                    )}
                </div>
                <div className="opacity-60">
                    <Icon className="w-12 h-12 text-indigo-400" />
                </div>
            </div>
        </div>
    )
}

// Vulnerability Distribution Chart
function VulnDistributionChart({ data = {} }) {
    const chartData = {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [data?.critical || 0, data?.high || 0, data?.medium || 0, data?.low || 0],
            backgroundColor: [
                '#dc2626',
                '#ea580c',
                '#ca8a04',
                '#22c55e'
            ],
            borderColor: [
                '#dc2626',
                '#ea580c',
                '#ca8a04',
                '#22c55e'
            ],
            borderWidth: 2,
            hoverOffset: 10
        }]
    }

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    padding: 20,
                    usePointStyle: true,
                    color: '#94a3b8',
                    font: {
                        size: 12,
                        weight: '500'
                    }
                }
            }
        },
        cutout: '65%'
    }

    return (
        <div className="card animate-fade-in">
            <h3 className="text-lg font-semibold text-white mb-6">Vulnerability Distribution</h3>
            <div className="h-64">
                <Doughnut data={chartData} options={options} />
            </div>
        </div>
    )
}

// Recent Vulnerabilities List
function RecentVulnerabilities({ vulnerabilities = [] }) {
    const getSeverityBadge = (severity) => {
        const badges = {
            CRITICAL: 'badge-critical',
            HIGH: 'badge-high',
            MEDIUM: 'badge-medium',
            LOW: 'badge-low'
        }
        return badges[severity] || 'badge-info'
    }

    return (
        <div className="card animate-fade-in">
            <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold text-white">Recent Vulnerabilities</h3>
                <a href="/vulnerabilities" className="flex items-center gap-1 text-sm text-indigo-400 hover:text-indigo-300 font-medium transition-colors">
                    View all <ArrowRight className="w-4 h-4" />
                </a>
            </div>

            <div className="space-y-3">
                {vulnerabilities.length === 0 ? (
                    <p className="text-slate-400 text-center py-6">No vulnerabilities detected</p>
                ) : (
                    vulnerabilities.slice(0, 5).map((vuln, index) => (
                        <div key={index} className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                            <span className={`badge ${getSeverityBadge(vuln.severity)}`}>
                                {vuln.severity}
                            </span>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium text-slate-200 truncate">{vuln.title}</p>
                                <p className="text-xs text-slate-500 truncate">{vuln.pipeline_id}</p>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    )
}

// Main Dashboard Page
export default function Dashboard() {
    const [stats, setStats] = useState({
        vulnerabilities: { total: 0, critical: 0, high: 0, medium: 0, low: 0, open: 0, fixed: 0 },
        pipelines: { total: 0 },
        fixes: { total: 0, applied: 0 }
    })
    const [vulnerabilities, setVulnerabilities] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchData()
    }, [])

    const fetchData = async () => {
        try {
            // Fetch stats
            const statsRes = await fetch(`${API_BASE}/report/stats`)
            if (statsRes.ok) {
                const statsData = await statsRes.json()
                if (statsData.success && statsData.data) {
                    setStats(prev => ({
                        vulnerabilities: {
                            ...prev.vulnerabilities,
                            ...(statsData.data.vulnerabilities || {})
                        },
                        pipelines: {
                            ...prev.pipelines,
                            ...(statsData.data.pipelines || {})
                        },
                        fixes: {
                            ...prev.fixes,
                            ...(statsData.data.fixes || {})
                        }
                    }))
                }
            }

            // Fetch recent vulnerabilities
            const vulnRes = await fetch(`${API_BASE}/scan/vulnerabilities?limit=10`)
            if (vulnRes.ok) {
                const vulnData = await vulnRes.json()
                if (vulnData.success) {
                    setVulnerabilities(vulnData.data || [])
                }
            }
        } catch (error) {
            console.error('Error fetching data:', error)
        } finally {
            setLoading(false)
        }
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="w-12 h-12 rounded-full border-4 border-indigo-500/30 border-t-indigo-500 animate-spin"></div>
            </div>
        )
    }

    return (
        <div className="space-y-8">
            {/* Stats Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <StatsCard
                    icon={Lock}
                    label="Total Vulnerabilities"
                    value={stats.vulnerabilities?.total || 0}
                    change={`${stats.vulnerabilities?.open || 0} open`}
                    changeType={(stats.vulnerabilities?.open || 0) > 0 ? 'negative' : 'positive'}
                />
                <StatsCard
                    icon={RefreshCw}
                    label="Pipelines"
                    value={stats.pipelines?.total || 0}
                    change="Monitored"
                    changeType="neutral"
                />
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <VulnDistributionChart data={stats.vulnerabilities} />
                <RecentVulnerabilities vulnerabilities={vulnerabilities} />
            </div>

            {/* Quick Actions */}
            <div className="card animate-fade-in">
                <h3 className="text-lg font-semibold text-white mb-6">Quick Actions</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <a href="/vulnerabilities" className="p-5 rounded-lg bg-slate-800 border border-slate-700 hover:border-indigo-500 transition-colors group">
                        <Search className="w-8 h-8 text-red-400" />
                        <p className="mt-3 font-semibold text-slate-200 group-hover:text-white">Scan Logs</p>
                        <p className="text-sm text-slate-500">Analyze new pipeline logs</p>
                    </a>
                    <a href="/pipelines" className="p-5 rounded-lg bg-slate-800 border border-slate-700 hover:border-indigo-500 transition-colors group">
                        <FileText className="w-8 h-8 text-indigo-400" />
                        <p className="mt-3 font-semibold text-slate-200 group-hover:text-white">View Reports</p>
                        <p className="text-sm text-slate-500">Generate security reports</p>
                    </a>
                    <a href="/anomalies" className="p-5 rounded-lg bg-slate-800 border border-slate-700 hover:border-indigo-500 transition-colors group">
                        <Settings className="w-8 h-8 text-amber-400" />
                        <p className="mt-3 font-semibold text-slate-200 group-hover:text-white">Check Anomalies</p>
                        <p className="text-sm text-slate-500">Review unusual behavior</p>
                    </a>
                </div>
            </div>
        </div>
    )
}
