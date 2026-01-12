import { useState, useEffect } from 'react'
import { RefreshCw, Folder, Clock, Eye, CheckCircle, Lightbulb, X } from 'lucide-react'

const API_BASE = '/api/v1'

function SeverityBadge({ severity }) {
    const badges = {
        CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/30',
        HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
        MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
        LOW: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
        INFO: 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30'
    }

    return (
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${badges[severity] || badges.INFO}`}>
            {severity}
        </span>
    )
}

function StatusBadge({ status }) {
    const badges = {
        OPEN: 'bg-red-500/10 text-red-400 border border-red-500/20',
        FIXED: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
        IGNORED: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
        FALSE_POSITIVE: 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
    }

    return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-lg text-xs font-medium ${badges[status] || badges.OPEN}`}>
            {status}
        </span>
    )
}

function VulnerabilityCard({ vulnerability, onViewDetails }) {
    return (
        <div className="card hover:border-indigo-500 transition-all animate-fade-in">
            <div className="flex items-start justify-between">
                <div className="flex-1">
                    <div className="flex items-center gap-2 mb-3">
                        <SeverityBadge severity={vulnerability.severity} />
                        <StatusBadge status={vulnerability.status} />
                        <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-lg">{vulnerability.vulnerability_type}</span>
                    </div>

                    <h3 className="text-lg font-semibold text-white mb-2">
                        {vulnerability.title}
                    </h3>

                    <p className="text-sm text-slate-400 mb-4 line-clamp-2">
                        {vulnerability.description}
                    </p>

                    <div className="flex items-center gap-4 text-xs text-slate-500">
                        <span className="flex items-center gap-1.5">
                            <RefreshCw className="w-3 h-3" />
                            {vulnerability.pipeline_id}
                        </span>
                        <span className="flex items-center gap-1.5">
                            <Folder className="w-3 h-3" />
                            {vulnerability.source}
                        </span>
                        <span className="flex items-center gap-1.5">
                            <Clock className="w-3 h-3" />
                            {new Date(vulnerability.detected_at).toLocaleDateString()}
                        </span>
                    </div>
                </div>

                <button
                    onClick={() => onViewDetails(vulnerability)}
                    className="btn btn-secondary text-sm flex items-center gap-2"
                >
                    <Eye className="w-4 h-4" />
                    View Details
                </button>
            </div>

            {vulnerability.evidence && (
                <div className="mt-4 p-4 rounded-lg bg-slate-800 border border-slate-700">
                    <p className="text-xs font-medium text-slate-500 mb-2">Evidence</p>
                    <code className="text-xs text-slate-300 block overflow-x-auto font-mono">
                        {vulnerability.evidence.substring(0, 200)}
                        {vulnerability.evidence.length > 200 && '...'}
                    </code>
                </div>
            )}
        </div>
    )
}

function VulnerabilityModal({ vulnerability, onClose, onApplyFix }) {
    if (!vulnerability) return null

    return (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 bg-black/70">
            <div className="rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700">
                <div className="p-6 border-b border-slate-700">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <SeverityBadge severity={vulnerability.severity} />
                            <StatusBadge status={vulnerability.status} />
                        </div>
                        <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-slate-700">
                            <X className="w-6 h-6" />
                        </button>
                    </div>
                    <h2 className="text-xl font-bold text-white mt-4">{vulnerability.title}</h2>
                </div>

                <div className="p-6 space-y-5">
                    <div>
                        <h4 className="text-sm font-medium text-slate-500 mb-2">Description</h4>
                        <p className="text-slate-300">{vulnerability.description}</p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 rounded-lg bg-slate-800 border border-slate-700">
                            <h4 className="text-sm font-medium text-slate-500 mb-1">Pipeline</h4>
                            <p className="text-slate-200">{vulnerability.pipeline_id}</p>
                        </div>
                        <div className="p-4 rounded-lg bg-slate-800 border border-slate-700">
                            <h4 className="text-sm font-medium text-slate-500 mb-1">Source</h4>
                            <p className="text-slate-200">{vulnerability.source}</p>
                        </div>
                        <div className="p-4 rounded-lg bg-slate-800 border border-slate-700">
                            <h4 className="text-sm font-medium text-slate-500 mb-1">Category</h4>
                            <p className="text-slate-200">{vulnerability.vulnerability_type}</p>
                        </div>
                        <div className="p-4 rounded-lg bg-slate-800 border border-slate-700">
                            <h4 className="text-sm font-medium text-slate-500 mb-1">Detected</h4>
                            <p className="text-slate-200">{new Date(vulnerability.detected_at).toLocaleString()}</p>
                        </div>
                    </div>

                    {vulnerability.evidence && (
                        <div>
                            <h4 className="text-sm font-medium text-slate-500 mb-2">Evidence</h4>
                            <pre className="p-4 rounded-lg overflow-x-auto text-sm font-mono text-slate-300 bg-slate-800 border border-slate-700">
                                {vulnerability.evidence}
                            </pre>
                        </div>
                    )}

                    {vulnerability.remediation && (
                        <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                            <div className="flex items-center gap-2 mb-2">
                                <Lightbulb className="w-4 h-4 text-emerald-400" />
                                <h4 className="text-sm font-semibold text-emerald-400">Recommended Fix</h4>
                            </div>
                            <p className="text-emerald-300 text-sm">{vulnerability.remediation}</p>
                        </div>
                    )}
                </div>

                <div className="p-6 flex gap-3 justify-end border-t border-slate-700">
                    <button onClick={onClose} className="btn btn-secondary">
                        Close
                    </button>
                    {vulnerability.status === 'OPEN' && (
                        <button onClick={() => onApplyFix(vulnerability)} className="btn btn-primary">
                            Generate Fix
                        </button>
                    )}
                </div>
            </div>
        </div>
    )
}

export default function Vulnerabilities() {
    const [vulnerabilities, setVulnerabilities] = useState([])
    const [loading, setLoading] = useState(true)
    const [selectedVuln, setSelectedVuln] = useState(null)
    const [filter, setFilter] = useState({ severity: '', status: '' })

    useEffect(() => {
        fetchVulnerabilities()
    }, [])

    const fetchVulnerabilities = async () => {
        try {
            const res = await fetch(`${API_BASE}/scan/vulnerabilities?limit=100`)
            if (res.ok) {
                const data = await res.json()
                if (data.success) {
                    setVulnerabilities(data.data || [])
                }
            }
        } catch (error) {
            console.error('Error fetching vulnerabilities:', error)
        } finally {
            setLoading(false)
        }
    }

    const handleApplyFix = async (vulnerability) => {
        try {
            const res = await fetch(`${API_BASE}/fix/fix`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ vulnerability_id: vulnerability.id })
            })
            if (res.ok) {
                alert('Fix generated successfully!')
                fetchVulnerabilities()
            }
        } catch (error) {
            console.error('Error generating fix:', error)
            alert('Failed to generate fix')
        }
        setSelectedVuln(null)
    }

    const filteredVulns = vulnerabilities.filter(v => {
        if (filter.severity && v.severity !== filter.severity) return false
        if (filter.status && v.status !== filter.status) return false
        return true
    })

    const stats = {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: vulnerabilities.filter(v => v.severity === 'LOW').length,
        open: vulnerabilities.filter(v => v.status === 'OPEN').length
    }

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
                    <h1 className="text-2xl font-bold text-white">Vulnerabilities</h1>
                    <p className="text-slate-400">View and manage detected security issues</p>
                </div>

                <button onClick={fetchVulnerabilities} className="btn btn-primary flex items-center gap-2">
                    <RefreshCw className="w-4 h-4" /> Refresh
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
                <div className="card p-4">
                    <p className="text-sm text-slate-400">Total</p>
                    <p className="text-2xl font-bold text-white">{stats.total}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-critical">
                    <p className="text-sm text-red-400">Critical</p>
                    <p className="text-2xl font-bold text-red-300">{stats.critical}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-high">
                    <p className="text-sm text-orange-400">High</p>
                    <p className="text-2xl font-bold text-orange-300">{stats.high}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-medium">
                    <p className="text-sm text-yellow-400">Medium</p>
                    <p className="text-2xl font-bold text-yellow-300">{stats.medium}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-low">
                    <p className="text-sm text-emerald-400">Low</p>
                    <p className="text-2xl font-bold text-emerald-300">{stats.low}</p>
                </div>
                <div className="rounded-xl p-4 stat-card-info">
                    <p className="text-sm text-indigo-400">Open</p>
                    <p className="text-2xl font-bold text-indigo-300">{stats.open}</p>
                </div>
            </div>

            {/* Filters */}
            <div className="flex gap-4">
                <select
                    value={filter.severity}
                    onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
                    className="px-4 py-2.5 rounded-lg text-sm"
                >
                    <option value="">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                </select>

                <select
                    value={filter.status}
                    onChange={(e) => setFilter({ ...filter, status: e.target.value })}
                    className="px-4 py-2.5 rounded-lg text-sm"
                >
                    <option value="">All Statuses</option>
                    <option value="OPEN">Open</option>
                    <option value="FIXED">Fixed</option>
                    <option value="IGNORED">Ignored</option>
                </select>
            </div>

            {/* Vulnerability List */}
            <div className="space-y-4">
                {filteredVulns.length === 0 ? (
                    <div className="text-center py-16 card">
                        <CheckCircle className="w-12 h-12 text-emerald-400 mx-auto" />
                        <p className="mt-4 text-lg font-semibold text-white">No vulnerabilities found</p>
                        <p className="text-slate-400">Your pipelines are looking secure!</p>
                    </div>
                ) : (
                    filteredVulns.map((vuln, index) => (
                        <VulnerabilityCard
                            key={vuln.id || index}
                            vulnerability={vuln}
                            onViewDetails={setSelectedVuln}
                        />
                    ))
                )}
            </div>

            {/* Modal */}
            <VulnerabilityModal
                vulnerability={selectedVuln}
                onClose={() => setSelectedVuln(null)}
                onApplyFix={handleApplyFix}
            />
        </div>
    )
}
