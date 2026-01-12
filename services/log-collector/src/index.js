const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ===========================================
// MIDDLEWARE
// ===========================================
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(morgan('combined'));

// ===========================================
// MONGODB CONNECTION
// ===========================================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/safeops';

mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// ===========================================
// MONGOOSE SCHEMA
// ===========================================
const rawLogSchema = new mongoose.Schema({
    logId: { type: String, required: true, unique: true, index: true },
    pipelineId: { type: String, required: true, index: true },
    source: {
        type: String,
        required: true,
        enum: ['GitHub', 'GitLab', 'Jenkins'],
        index: true
    },
    repository: { type: String },
    branch: { type: String },
    workflowName: { type: String },
    runNumber: { type: Number },
    runId: { type: String },
    author: { type: String },
    commitSha: { type: String },
    rawLog: { type: String, required: true },
    metadata: { type: mongoose.Schema.Types.Mixed },
    status: {
        type: String,
        enum: ['PENDING', 'PARSED', 'FAILED'],
        default: 'PENDING',
        index: true
    },
    uploadedAt: { type: Date, default: Date.now, index: true },
    parsedAt: { type: Date }
});

const RawLog = mongoose.model('RawLog', rawLogSchema, 'raw_logs');

// ===========================================
// VALIDATION MIDDLEWARE
// ===========================================
const uploadValidation = [
    body('pipelineId').notEmpty().withMessage('pipelineId is required'),
    body('source').isIn(['GitHub', 'GitLab', 'Jenkins']).withMessage('source must be GitHub, GitLab, or Jenkins'),
    body('rawLog').notEmpty().withMessage('rawLog content is required')
];

// ===========================================
// API ENDPOINTS
// ===========================================

// Health Check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'log-collector',
        timestamp: new Date().toISOString()
    });
});

// Upload Raw Log
app.post('/logs/upload', uploadValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }

        const {
            pipelineId,
            source,
            repository,
            branch,
            workflowName,
            runNumber,
            runId,
            author,
            commitSha,
            rawLog,
            metadata
        } = req.body;

        const logId = uuidv4();

        const newLog = new RawLog({
            logId,
            pipelineId,
            source,
            repository,
            branch,
            workflowName,
            runNumber,
            runId,
            author,
            commitSha,
            rawLog,
            metadata,
            status: 'PENDING'
        });

        await newLog.save();

        console.log(`📥 Log received: ${logId} from ${source} - Pipeline: ${pipelineId}`);

        res.status(201).json({
            success: true,
            message: 'Log uploaded successfully',
            data: {
                logId,
                pipelineId,
                source,
                status: 'PENDING',
                uploadedAt: newLog.uploadedAt
            }
        });
    } catch (error) {
        console.error('Error uploading log:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to upload log',
            message: error.message
        });
    }
});

// Fetch workflow from GitHub Actions URL
app.post('/logs/github/workflow', async (req, res) => {
    try {
        const { githubUrl } = req.body;

        if (!githubUrl) {
            return res.status(400).json({
                success: false,
                error: 'githubUrl is required'
            });
        }

        // Parse GitHub Actions URL
        // Format: https://github.com/{owner}/{repo}/actions/runs/{runId}
        // Or: https://github.com/{owner}/{repo}/actions/runs/{runId}/job/{jobId}
        const urlPattern = /github\.com\/([^\/]+)\/([^\/]+)\/actions\/runs\/(\d+)/;
        const match = githubUrl.match(urlPattern);

        if (!match) {
            return res.status(400).json({
                success: false,
                error: 'Invalid GitHub Actions URL format. Expected: https://github.com/{owner}/{repo}/actions/runs/{runId}'
            });
        }

        const [, owner, repo, runId] = match;
        console.log(`📥 Fetching workflow for ${owner}/${repo} run ${runId}`);

        let workflowContent = null;
        let workflowName = null;
        let headBranch = null;

        // Step 1: Use GitHub Actions API to get the workflow path and branch
        try {
            const runApiUrl = `https://api.github.com/repos/${owner}/${repo}/actions/runs/${runId}`;
            console.log(`Fetching run info from: ${runApiUrl}`);

            const runResponse = await fetch(runApiUrl, {
                headers: { 'Accept': 'application/vnd.github.v3+json' }
            });

            if (runResponse.ok) {
                const runData = await runResponse.json();
                const workflowPath = runData.path; // e.g., ".github/workflows/node.yml"
                headBranch = runData.head_branch; // e.g., "hardhat/contract"
                const headSha = runData.head_sha;

                console.log(`Found workflow path: ${workflowPath}, branch: ${headBranch}, sha: ${headSha}`);

                // Step 2: Fetch the workflow file from the commit SHA (most reliable)
                if (workflowPath && headSha) {
                    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${headSha}/${workflowPath}`;
                    console.log(`Fetching workflow from SHA: ${rawUrl}`);

                    const fileResponse = await fetch(rawUrl);
                    if (fileResponse.ok) {
                        workflowContent = await fileResponse.text();
                        workflowName = workflowPath.split('/').pop();
                        console.log(`Successfully fetched workflow: ${workflowName}`);
                    }
                }

                // Fallback to branch if SHA failed or missing
                if (!workflowContent && workflowPath && headBranch) {
                    console.log(`SHA fetch failed, trying branch: ${headBranch}`);
                    // URL-encode the branch name to handle slashes (e.g., "hardhat/contract")
                    const encodedBranch = encodeURIComponent(headBranch);
                    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${encodedBranch}/${workflowPath}`;

                    const fileResponse = await fetch(rawUrl);
                    if (fileResponse.ok) {
                        workflowContent = await fileResponse.text();
                        workflowName = workflowPath.split('/').pop();
                        console.log(`Successfully fetched workflow (encoded branch): ${workflowName}`);
                    } else {
                        // Try without encoding as last resort
                        const rawUrl2 = `https://raw.githubusercontent.com/${owner}/${repo}/${headBranch}/${workflowPath}`;
                        const fileResponse2 = await fetch(rawUrl2);
                        if (fileResponse2.ok) {
                            workflowContent = await fileResponse2.text();
                            workflowName = workflowPath.split('/').pop();
                            console.log(`Successfully fetched workflow (unencoded): ${workflowName}`);
                        }
                    }
                }
            }
        } catch (e) {
            console.log(`GitHub Actions API failed: ${e.message}`);
        }

        // Fallback: Try common locations if Actions API didn't work
        if (!workflowContent) {
            console.log('Trying fallback locations...');
            const branches = ['main', 'master', headBranch].filter(Boolean);
            const workflowNames = ['node.yml', 'ci.yml', 'build.yml', 'test.yml', 'main.yml'];

            for (const branch of branches) {
                for (const wfName of workflowNames) {
                    try {
                        const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/.github/workflows/${wfName}`;
                        const response = await fetch(url);
                        if (response.ok) {
                            workflowContent = await response.text();
                            workflowName = wfName;
                            console.log(`Found workflow via fallback: ${wfName} on ${branch}`);
                            break;
                        }
                    } catch (e) {
                        // Continue to next URL
                    }
                }
                if (workflowContent) break;
            }
        }

        if (!workflowContent) {
            return res.status(404).json({
                success: false,
                error: 'Could not find workflow file. The repository may not have any workflow files or they may be in a non-standard location.'
            });
        }

        // Save workflow as a log for vulnerability scanning
        const logId = uuidv4();
        const pipelineId = `${repo}-workflow-${runId}`;

        const newLog = new RawLog({
            logId,
            pipelineId,
            source: 'GitHub',
            repository: `${owner}/${repo}`,
            runId: runId,
            workflowName: workflowName,
            rawLog: workflowContent,
            metadata: {
                type: 'workflow',
                fetchedFrom: githubUrl,
                owner,
                repo,
                runId
            },
            status: 'PENDING'
        });

        await newLog.save();

        console.log(`📥 Workflow saved: ${logId} from ${owner}/${repo}`);

        res.status(201).json({
            success: true,
            message: 'Workflow fetched and uploaded successfully',
            data: {
                logId,
                pipelineId,
                workflowName,
                repository: `${owner}/${repo}`,
                runId,
                status: 'PENDING',
                note: 'Workflow will be scanned for vulnerabilities. Upload execution logs separately for anomaly detection.'
            }
        });

    } catch (error) {
        console.error('Error fetching GitHub workflow:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch workflow',
            message: error.message
        });
    }
});

// Legacy endpoint for backward compatibility
app.get('/logs/github', async (req, res) => {
    res.json({
        success: true,
        message: 'Use POST /logs/github/workflow with { "githubUrl": "https://github.com/..." } to fetch workflows'
    });
});

// Get all logs (with pagination)
app.get('/logs', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const status = req.query.status;
        const source = req.query.source;

        const query = {};
        if (status) query.status = status;
        if (source) query.source = source;

        const logs = await RawLog
            .find(query)
            .select('-rawLog') // Exclude large rawLog field
            .sort({ uploadedAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit);

        const total = await RawLog.countDocuments(query);

        res.json({
            success: true,
            data: logs,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Error fetching logs:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch logs'
        });
    }
});

// Get single log by ID
app.get('/logs/:logId', async (req, res) => {
    try {
        const log = await RawLog.findOne({ logId: req.params.logId });

        if (!log) {
            return res.status(404).json({
                success: false,
                error: 'Log not found'
            });
        }

        res.json({
            success: true,
            data: log
        });
    } catch (error) {
        console.error('Error fetching log:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch log'
        });
    }
});

// Get statistics
app.get('/stats', async (req, res) => {
    try {
        const stats = await RawLog.aggregate([
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    pending: {
                        $sum: { $cond: [{ $eq: ['$status', 'PENDING'] }, 1, 0] }
                    },
                    parsed: {
                        $sum: { $cond: [{ $eq: ['$status', 'PARSED'] }, 1, 0] }
                    },
                    failed: {
                        $sum: { $cond: [{ $eq: ['$status', 'FAILED'] }, 1, 0] }
                    }
                }
            }
        ]);

        const sourceStats = await RawLog.aggregate([
            {
                $group: {
                    _id: '$source',
                    count: { $sum: 1 }
                }
            }
        ]);

        res.json({
            success: true,
            data: {
                totals: stats[0] || { total: 0, pending: 0, parsed: 0, failed: 0 },
                bySource: sourceStats.reduce((acc, s) => {
                    acc[s._id] = s.count;
                    return acc;
                }, {})
            }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch statistics'
        });
    }
});

// ===========================================
// START SERVER
// ===========================================
app.listen(PORT, () => {
    console.log(`LogCollector service running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
