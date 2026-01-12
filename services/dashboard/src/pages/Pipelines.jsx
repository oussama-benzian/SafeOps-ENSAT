import { useState, useEffect } from 'react'
import { RefreshCw, Folder, Clock, GitBranch, Play, FileText, Link2, Upload, X, Plus, FolderOpen, CircleCheck, CircleAlert, Info } from 'lucide-react'

const API_BASE = '/api/v1'

function StatusBadge({ status }) {
    const statusConfig = {
        PENDING: { color: 'bg-amber-500/20 text-amber-400 border border-amber-500/30', label: 'Pending' },
        PARSED: { color: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30', label: 'Parsed' },
        FAILED: { color: 'bg-red-500/20 text-red-400 border border-red-500/30', label: 'Failed' },
    }
    const config = statusConfig[status] || { color: 'bg-slate-500/20 text-slate-400 border border-slate-500/30', label: status }

    return (
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${config.color}`}>
            {config.label}
        </span>
    )
}

function PipelineCard({ pipeline, onGenerateReport, onTriggerParse }) {
    return (
        <div className="card animate-fade-in hover:border-indigo-500 transition-all">
            <div className="flex items-start justify-between">
                <div className="flex-1">
                    <div className="flex items-center gap-3 mb-3">
                        <h3 className="text-lg font-semibold text-white">{pipeline.pipelineId}</h3>
                        <StatusBadge status={pipeline.status} />
                    </div>

                    {pipeline.repository && (
                        <p className="text-sm text-slate-400 mb-3 flex items-center gap-2">
                            <Folder className="w-4 h-4" />
                            {pipeline.repository}
                        </p>
                    )}

                    <div className="flex items-center gap-4 text-sm">
                        <span className="flex items-center gap-1.5 text-slate-500">
                            <RefreshCw className="w-4 h-4 text-indigo-400" />
                            {pipeline.source}
                        </span>
                        {pipeline.branch && (
                            <span className="flex items-center gap-1.5 text-slate-500">
                                <GitBranch className="w-4 h-4" />
                                {pipeline.branch}
                            </span>
                        )}
                        {pipeline.uploadedAt && (
                            <span className="flex items-center gap-1.5 text-slate-500">
                                <Clock className="w-4 h-4" />
                                {new Date(pipeline.uploadedAt).toLocaleString()}
                            </span>
                        )}
                    </div>
                </div>

                <div className="flex gap-2">
                    {pipeline.status === 'PENDING' && (
                        <button
                            onClick={() => onTriggerParse()}
                            className="btn btn-secondary text-sm flex items-center gap-2"
                        >
                            <Play className="w-4 h-4" /> Parse
                        </button>
                    )}
                    <button
                        onClick={() => onGenerateReport(pipeline.pipelineId)}
                        className="btn btn-primary text-sm flex items-center gap-2"
                    >
                        <FileText className="w-4 h-4" /> Report
                    </button>
                </div>
            </div>

            {/* Status Info */}
            <div className="mt-4 pt-4 border-t border-slate-700">
                <div className="flex items-center gap-4">
                    <span className="text-sm text-slate-500">Log ID:</span>
                    <code className="text-xs px-3 py-1.5 rounded-lg font-mono text-slate-300 bg-slate-800 border border-slate-700">{pipeline.logId}</code>
                    {pipeline.parseError && (
                        <span className="text-xs text-red-400">Error: {pipeline.parseError}</span>
                    )}
                </div>
            </div>
        </div>
    )
}

function UploadLogModal({ isOpen, onClose, onUpload }) {
    const [githubUrl, setGithubUrl] = useState('')
    const [logFile, setLogFile] = useState(null)
    const [logContent, setLogContent] = useState('')
    const [uploading, setUploading] = useState(false)
    const [status, setStatus] = useState(null)
    const [results, setResults] = useState({ workflow: null, logs: null })

    if (!isOpen) return null

    const handleFileChange = (e) => {
        const file = e.target.files[0]
        if (file) {
            setLogFile(file)
            const reader = new FileReader()
            reader.onload = (event) => {
                setLogContent(event.target.result)
            }
            reader.readAsText(file)
        }
    }

    const handleAnalyze = async () => {
        if (!githubUrl && !logContent) {
            setStatus({ type: 'error', text: 'Please enter a GitHub URL or select a log file (or both)' })
            return
        }

        setUploading(true)
        setStatus({ type: 'info', text: 'Analyzing pipeline...' })
        setResults({ workflow: null, logs: null })

        let workflowResult = null
        let logsResult = null

        if (githubUrl) {
            try {
                setStatus({ type: 'info', text: 'Fetching workflow from GitHub...' })
                const res = await fetch(`${API_BASE}/collector/logs/github/workflow`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ githubUrl })
                })

                const data = await res.json()
                if (data.success) {
                    workflowResult = { success: true, name: data.data.workflowName, repo: data.data.repository }
                } else {
                    workflowResult = { success: false, error: data.error }
                }
            } catch (error) {
                workflowResult = { success: false, error: 'Failed to fetch workflow' }
            }
        }

        if (logContent) {
            try {
                setStatus({ type: 'info', text: 'Uploading execution logs...' })

                let pipelineId = 'manual-upload-' + Date.now()
                let repository = ''

                if (githubUrl) {
                    const match = githubUrl.match(/github\.com\/([^\/]+)\/([^\/]+)\/actions\/runs\/(\d+)/)
                    if (match) {
                        const [, owner, repo, runId] = match
                        pipelineId = `${repo}-logs-${runId}`
                        repository = `${owner}/${repo}`
                    }
                }

                const res = await fetch(`${API_BASE}/collector/logs/upload`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        pipelineId,
                        source: 'GitHub',
                        repository,
                        rawLog: logContent
                    })
                })

                const data = await res.json()
                if (data.success) {
                    logsResult = { success: true, pipelineId }
                    await fetch(`${API_BASE}/parser/parse`, { method: 'POST' })
                } else {
                    logsResult = { success: false, error: data.error }
                }
            } catch (error) {
                logsResult = { success: false, error: 'Failed to upload logs' }
            }
        }

        setResults({ workflow: workflowResult, logs: logsResult })

        const workflowOk = !githubUrl || workflowResult?.success
        const logsOk = !logContent || logsResult?.success

        if (workflowOk && logsOk) {
            setStatus({ type: 'success', text: 'Pipeline analysis complete!' })
            onUpload()
        } else {
            setStatus({ type: 'error', text: 'Some items failed. See details below.' })
        }

        setUploading(false)
    }

    return (
        <div className="fixed inset-0 flex items-center justify-center z-50 p-4 bg-black/70">
            <div className="rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700">
                <div className="p-6 border-b border-slate-700">
                    <div className="flex items-center justify-between">
                        <h2 className="text-xl font-bold text-white flex items-center gap-3">
                            <Upload className="w-6 h-6 text-indigo-400" />
                            Analyze CI/CD Pipeline
                        </h2>
                        <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-slate-700">
                            <X className="w-6 h-6" />
                        </button>
                    </div>
                </div>

                <div className="p-6 space-y-6">
                    <div>
                        <label className="flex items-center gap-2 text-sm font-medium text-slate-300 mb-2">
                            <Link2 className="w-4 h-4" />
                            GitHub Actions URL <span className="text-slate-500">(for vulnerability scan)</span>
                        </label>
                        <input
                            type="url"
                            value={githubUrl}
                            onChange={(e) => setGithubUrl(e.target.value)}
                            className="w-full"
                            placeholder="https://github.com/owner/repo/actions/runs/123456789"
                            disabled={uploading}
                        />
                    </div>

                    <div>
                        <label className="flex items-center gap-2 text-sm font-medium text-slate-300 mb-2">
                            <FileText className="w-4 h-4" />
                            Execution Log File <span className="text-slate-500">(for anomaly detection)</span>
                        </label>
                        <label className="cursor-pointer block">
                            <div className={`border-2 border-dashed rounded-lg p-8 text-center transition-all ${logFile ? 'border-emerald-500 bg-emerald-500/5' : 'border-slate-600 hover:border-indigo-500'}`}>
                                <input
                                    type="file"
                                    accept=".txt,.log,.json,.zip"
                                    onChange={handleFileChange}
                                    className="hidden"
                                    disabled={uploading}
                                />
                                {logFile ? (
                                    <div className="text-emerald-400">
                                        <FileText className="w-10 h-10 mx-auto" />
                                        <p className="font-medium mt-3">{logFile.name}</p>
                                        <p className="text-sm text-slate-500">{(logFile.size / 1024).toFixed(1)} KB</p>
                                    </div>
                                ) : (
                                    <div className="text-slate-400">
                                        <FolderOpen className="w-10 h-10 mx-auto" />
                                        <p className="mt-3">Click to select log file</p>
                                        <p className="text-sm text-slate-600">(.txt, .log, .json)</p>
                                    </div>
                                )}
                            </div>
                        </label>
                    </div>

                    {status && (
                        <div className={`p-4 rounded-lg flex items-center gap-3 ${status.type === 'success' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                            status.type === 'error' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                                'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'
                            }`}>
                            {status.type === 'success' ? <CircleCheck className="w-5 h-5" /> :
                                status.type === 'error' ? <CircleAlert className="w-5 h-5" /> :
                                    <RefreshCw className="w-5 h-5 animate-spin" />}
                            {status.text}
                        </div>
                    )}

                    {(results.workflow || results.logs) && (
                        <div className="space-y-2 text-sm">
                            {results.workflow && (
                                <div className={`p-3 rounded-lg flex items-center gap-2 ${results.workflow.success ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                                    {results.workflow.success ? <CircleCheck className="w-4 h-4" /> : <CircleAlert className="w-4 h-4" />}
                                    {results.workflow.success
                                        ? `Workflow "${results.workflow.name}" from ${results.workflow.repo}`
                                        : `Workflow: ${results.workflow.error}`}
                                </div>
                            )}
                            {results.logs && (
                                <div className={`p-3 rounded-lg flex items-center gap-2 ${results.logs.success ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                                    {results.logs.success ? <CircleCheck className="w-4 h-4" /> : <CircleAlert className="w-4 h-4" />}
                                    {results.logs.success
                                        ? `Logs uploaded as ${results.logs.pipelineId}`
                                        : `Logs: ${results.logs.error}`}
                                </div>
                            )}
                        </div>
                    )}

                    <div className="rounded-lg p-4 text-sm text-slate-400 flex gap-3 bg-slate-800 border border-slate-700">
                        <Info className="w-5 h-5 flex-shrink-0 text-slate-500" />
                        <div>
                            <p><strong className="text-slate-300">How to get execution logs:</strong></p>
                            <p>Go to your GitHub Actions run → Click the menu → "View raw logs" or download zip</p>
                        </div>
                    </div>
                </div>

                <div className="p-6 flex justify-between border-t border-slate-700">
                    <button onClick={onClose} className="btn btn-secondary">
                        Close
                    </button>
                    <button
                        onClick={handleAnalyze}
                        disabled={uploading || (!githubUrl && !logFile)}
                        className="btn btn-primary disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                        {uploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                        {uploading ? 'Analyzing...' : 'Analyze Pipeline'}
                    </button>
                </div>
            </div>
        </div>
    )
}

export default function Pipelines() {
    const [pipelines, setPipelines] = useState([])
    const [loading, setLoading] = useState(true)
    const [showUploadModal, setShowUploadModal] = useState(false)

    useEffect(() => {
        fetchPipelines()
    }, [])

    const fetchPipelines = async () => {
        try {
            const res = await fetch(`${API_BASE}/collector/logs`)
            if (res.ok) {
                const data = await res.json()
                if (data.success) {
                    setPipelines(data.data || [])
                }
            }
        } catch (error) {
            console.error('Error fetching pipelines:', error)
        } finally {
            setLoading(false)
        }
    }

    const handleGenerateReport = (pipelineId) => {
        window.open(`${API_BASE}/report/report/${pipelineId}`, '_blank')
    }

    const handleTriggerParser = async () => {
        try {
            const res = await fetch(`${API_BASE}/parser/parse`, { method: 'POST' })
            if (res.ok) {
                alert('Parser triggered successfully!')
                setTimeout(fetchPipelines, 2000)
            }
        } catch (error) {
            console.error('Error triggering parser:', error)
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
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white">Pipelines</h1>
                    <p className="text-slate-400">Manage and analyze your CI/CD pipelines</p>
                </div>

                <div className="flex gap-3">
                    <button onClick={handleTriggerParser} className="btn btn-secondary flex items-center gap-2">
                        <RefreshCw className="w-4 h-4" /> Run Parser
                    </button>
                    <button onClick={() => setShowUploadModal(true)} className="btn btn-primary flex items-center gap-2">
                        <Plus className="w-4 h-4" /> Upload Log
                    </button>
                </div>
            </div>

            <div className="space-y-4">
                {pipelines.length === 0 ? (
                    <div className="text-center py-16 card">
                        <FolderOpen className="w-12 h-12 text-slate-500 mx-auto" />
                        <p className="mt-4 text-lg font-semibold text-white">No pipelines found</p>
                        <p className="text-slate-400 mb-6">Upload a CI/CD log to get started</p>
                        <button onClick={() => setShowUploadModal(true)} className="btn btn-primary inline-flex items-center gap-2">
                            <Upload className="w-4 h-4" /> Upload Your First Log
                        </button>
                    </div>
                ) : (
                    pipelines.map((pipeline, index) => (
                        <PipelineCard
                            key={pipeline._id || pipeline.logId || index}
                            pipeline={pipeline}
                            onGenerateReport={handleGenerateReport}
                            onTriggerParse={handleTriggerParser}
                        />
                    ))
                )}
            </div>

            <UploadLogModal
                isOpen={showUploadModal}
                onClose={() => setShowUploadModal(false)}
                onUpload={fetchPipelines}
            />
        </div>
    )
}
