const express = require('express');
const { Pool } = require('pg');
const PDFDocument = require('pdfkit');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ===========================================
// MIDDLEWARE
// ===========================================
app.use(cors());
app.use(express.json());

// ===========================================
// DATABASE CONNECTION
// ===========================================
const pool = new Pool({
    connectionString: process.env.POSTGRES_URI || 'postgresql://safeops:safeops_secret@localhost:5432/safeops'
});

pool.on('connect', () => {
    console.log('Connected to PostgreSQL');
});

pool.on('error', (err) => {
    console.error('PostgreSQL error:', err);
});

// ===========================================
// HELPER FUNCTIONS
// ===========================================
async function getPipelineData(pipelineId) {
    const pipeline = await pool.query(
        `SELECT * FROM pipelines WHERE pipeline_id = $1`,
        [pipelineId]
    );
    return pipeline.rows[0];
}

async function getVulnerabilities(pipelineId) {
    const result = await pool.query(
        `SELECT dv.*, sr.name as rule_name, sr.category, sr.remediation
     FROM detected_vulns dv
     LEFT JOIN security_rules sr ON dv.rule_id = sr.id
     WHERE dv.pipeline_id = $1
     ORDER BY 
       CASE dv.severity 
         WHEN 'CRITICAL' THEN 1 
         WHEN 'HIGH' THEN 2 
         WHEN 'MEDIUM' THEN 3 
         ELSE 4 
       END,
       dv.detected_at DESC`,
        [pipelineId]
    );
    return result.rows;
}

async function getFixSuggestions(pipelineId) {
    const result = await pool.query(
        `SELECT fs.*, dv.title as vuln_title, dv.severity
     FROM fix_suggestions fs
     JOIN detected_vulns dv ON fs.vulnerability_id = dv.id
     WHERE dv.pipeline_id = $1
     ORDER BY fs.created_at DESC`,
        [pipelineId]
    );
    return result.rows;
}

async function getScanHistory(pipelineId) {
    const result = await pool.query(
        `SELECT * FROM scan_history
     WHERE pipeline_id = $1
     ORDER BY started_at DESC
     LIMIT 10`,
        [pipelineId]
    );
    return result.rows;
}

function calculateSecurityScore(vulns) {
    if (!vulns || vulns.length === 0) return 100;

    const weights = {
        CRITICAL: 25,
        HIGH: 15,
        MEDIUM: 8,
        LOW: 3,
        INFO: 1
    };

    let totalDeduction = 0;
    for (const vuln of vulns) {
        totalDeduction += weights[vuln.severity] || 5;
    }

    return Math.max(0, 100 - totalDeduction);
}

function getScoreGrade(score) {
    if (score >= 90) return { grade: 'A', color: '#22c55e' };
    if (score >= 80) return { grade: 'B', color: '#84cc16' };
    if (score >= 70) return { grade: 'C', color: '#eab308' };
    if (score >= 60) return { grade: 'D', color: '#f97316' };
    return { grade: 'F', color: '#ef4444' };
}

function getSeverityColor(severity) {
    const colors = {
        CRITICAL: '#dc2626',
        HIGH: '#ea580c',
        MEDIUM: '#ca8a04',
        LOW: '#65a30d',
        INFO: '#0284c7'
    };
    return colors[severity] || '#6b7280';
}

// ===========================================
// PDF GENERATION
// ===========================================
function generatePDFReport(doc, data) {
    const { pipeline, vulnerabilities, fixes, securityScore, scoreGrade } = data;

    // Header
    doc.fontSize(24)
        .fillColor('#1e3a8a')
        .text('SafeOps Security Report', { align: 'center' });

    doc.moveDown(0.5);
    doc.fontSize(12)
        .fillColor('#6b7280')
        .text(`Generated: ${new Date().toISOString()}`, { align: 'center' });

    doc.moveDown(2);





    // Vulnerability Summary
    doc.fontSize(18)
        .fillColor('#1f2937')
        .text('Vulnerability Summary');

    doc.moveDown(0.5);

    const vulnCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
    };

    const groupedVulns = {};

    for (const vuln of vulnerabilities) {
        if (vulnCounts[vuln.severity] !== undefined) {
            vulnCounts[vuln.severity]++;
        }

        // Group by rule
        const ruleName = vuln.rule_name || vuln.vulnerability_type || 'Unknown Rule';
        if (!groupedVulns[ruleName]) {
            groupedVulns[ruleName] = {
                details: vuln,
                instances: []
            };
        }
        groupedVulns[ruleName].instances.push(vuln);
    }

    doc.fontSize(11)
        .fillColor('#374151');

    doc.fillColor(getSeverityColor('CRITICAL'))
        .text(`Critical: ${vulnCounts.CRITICAL}`, { continued: true });
    doc.fillColor('#374151').text('   |   ', { continued: true });
    doc.fillColor(getSeverityColor('HIGH'))
        .text(`High: ${vulnCounts.HIGH}`, { continued: true });
    doc.fillColor('#374151').text('   |   ', { continued: true });
    doc.fillColor(getSeverityColor('MEDIUM'))
        .text(`Medium: ${vulnCounts.MEDIUM}`, { continued: true });
    doc.fillColor('#374151').text('   |   ', { continued: true });
    doc.fillColor(getSeverityColor('LOW'))
        .text(`Low: ${vulnCounts.LOW}`);

    doc.moveDown(2);

    // Detailed Vulnerabilities with Fix Guidance (Grouped)
    const ruleNames = Object.keys(groupedVulns);

    if (ruleNames.length > 0) {
        doc.fontSize(18)
            .fillColor('#1f2937')
            .text('Detected Vulnerabilities by Rule');

        doc.moveDown(0.5);

        let ruleIndex = 1;
        for (const ruleName of ruleNames) {
            const group = groupedVulns[ruleName];
            const sampleVuln = group.details;
            const count = group.instances.length;

            // Check page break
            if (doc.y > 650) {
                doc.addPage();
            }

            // Rule Header
            doc.fontSize(14)
                .fillColor(getSeverityColor(sampleVuln.severity))
                .text(`${ruleIndex}. ${ruleName} (${count} occurrences)`);

            doc.fontSize(10)
                .fillColor('#6b7280')
                .text(`Severity: ${sampleVuln.severity}`);

            doc.moveDown(0.5);

            // Description
            if (sampleVuln.description) {
                doc.fontSize(10)
                    .fillColor('#374151')
                    .text(sampleVuln.description.substring(0, 300) + (sampleVuln.description.length > 300 ? '...' : ''));
            }

            doc.moveDown(0.5);

            // Occurrences List
            doc.fontSize(10).fillColor('#1f2937').text('Affected Locations:', { underline: true });
            doc.moveDown(0.3);

            for (const instance of group.instances) {
                if (doc.y > 700) doc.addPage();

                let locText = '';
                if (instance.file_path && instance.line_number) {
                    locText = `File: ${instance.file_path}, Line ${instance.line_number}`;
                } else if (instance.file_path) {
                    locText = `File: ${instance.file_path}`;
                } else if (instance.line_number) {
                    locText = `Line ${instance.line_number}`;
                } else {
                    locText = 'Location: Workflow configuration';
                }

                doc.fontSize(9).fillColor('#374151').text(`- ${locText}`);

                if (instance.evidence) {
                    const cleanEvidence = instance.evidence.substring(0, 120).replace(/\n/g, ' ').trim();
                    doc.fontSize(8).fillColor('#6b7280')
                        .text(`  Code: ${cleanEvidence}`, { indent: 12 });
                }
                doc.moveDown(0.15);
            }

            doc.moveDown(0.5);

            // Remediation
            doc.fontSize(10)
                .fillColor('#059669')
                .text('Remediation:', { underline: true });

            doc.moveDown(0.2);
            const remediation = sampleVuln.remediation || getDefaultRemediation(sampleVuln);
            doc.fontSize(9)
                .fillColor('#374151')
                .text(remediation);

            doc.moveDown(1);

            // Separator
            doc.strokeColor('#e5e7eb')
                .lineWidth(0.5)
                .moveTo(50, doc.y)
                .lineTo(545, doc.y)
                .stroke();

            doc.moveDown(1);

            ruleIndex++;
        }
    } else {
        doc.fontSize(12)
            .fillColor('#22c55e')
            .text('No vulnerabilities detected.');
    }

    // Footer
    doc.moveDown(3);
    doc.fontSize(9)
        .fillColor('#9ca3af')
        .text('This report was generated by SafeOps - CI/CD Security Analysis Platform', { align: 'center' });
    doc.text('Standards: OWASP, SLSA, CIS', { align: 'center' });
}

// Default remediation suggestions based on vulnerability type
function getDefaultRemediation(vuln) {
    const remediations = {
        'SECRET_LEAK': 'Remove the exposed secret from your code. Use environment variables or a secrets manager (GitHub Secrets, HashiCorp Vault). Rotate any compromised credentials immediately.',
        'UNPINNED_ACTION': 'Pin GitHub Actions to a specific commit SHA instead of a mutable tag. Example: uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 instead of @v4',
        'EXCESSIVE_PERMISSIONS': 'Apply least-privilege principle. Replace "permissions: write-all" with specific permissions like "contents: read" and "pull-requests: write".',
        'SCRIPT_INJECTION': 'Never use untrusted input directly in scripts. Assign inputs to environment variables first: env: TITLE: ${{ github.event.issue.title }} then use $TITLE in scripts.',
        'HARDCODED_CREDENTIAL': 'Remove hardcoded credentials. Use secrets: ${{ secrets.MY_SECRET }} or environment variables instead.',
        'UNPINNED_DOCKER': 'Pin Docker images to specific digests: image: node@sha256:abc123... instead of image: node:latest',
        'SELF_HOSTED_RUNNER': 'Limit self-hosted runner usage to private repositories. Use ephemeral runners and network isolation.',
        'DEBUG_LOGGING': 'Disable debug logging (ACTIONS_RUNNER_DEBUG, ACTIONS_STEP_DEBUG) in production workflows.',
    };

    return remediations[vuln.vulnerability_type] ||
        'Review the detected issue and apply appropriate security best practices. Consult OWASP, SLSA, or CIS guidelines for detailed remediation steps.';
}

// ===========================================
// API ENDPOINTS
// ===========================================

// Health Check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'report-generator',
        timestamp: new Date().toISOString()
    });
});

// Generate PDF Report
app.get('/report/:pipelineId', async (req, res) => {
    try {
        const { pipelineId } = req.params;

        console.log(`Requested pipelineId: "${pipelineId}"`);

        // Fetch all data
        const [pipeline, vulnerabilities, fixes] = await Promise.all([
            getPipelineData(pipelineId),
            getVulnerabilities(pipelineId),
            getFixSuggestions(pipelineId)
        ]);

        console.log(`Found ${vulnerabilities.length} vulnerabilities for pipeline "${pipelineId}"`);
        if (vulnerabilities.length > 0) {
            console.log(`   First vuln pipeline_id: "${vulnerabilities[0].pipeline_id}"`);
        }

        const securityScore = calculateSecurityScore(vulnerabilities);
        const scoreGrade = getScoreGrade(securityScore);

        // Create PDF
        const doc = new PDFDocument({
            size: 'A4',
            margins: { top: 50, bottom: 50, left: 50, right: 50 }
        });

        // Set response headers
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=safeops-report-${pipelineId}.pdf`);

        // Pipe PDF to response
        doc.pipe(res);

        // Generate report content
        generatePDFReport(doc, {
            pipeline,
            vulnerabilities,
            fixes,
            securityScore,
            scoreGrade
        });

        // Finalize PDF
        doc.end();

        console.log(`Generated report for pipeline: ${pipelineId}`);

    } catch (error) {
        console.error('Error generating report:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to generate report',
            message: error.message
        });
    }
});

// Get Report Data (JSON)
app.get('/report/:pipelineId/json', async (req, res) => {
    try {
        const { pipelineId } = req.params;

        const [pipeline, vulnerabilities, fixes, scanHistory] = await Promise.all([
            getPipelineData(pipelineId),
            getVulnerabilities(pipelineId),
            getFixSuggestions(pipelineId),
            getScanHistory(pipelineId)
        ]);

        const securityScore = calculateSecurityScore(vulnerabilities);
        const scoreGrade = getScoreGrade(securityScore);

        const vulnSummary = {
            total: vulnerabilities.length,
            critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
            high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
            medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
            low: vulnerabilities.filter(v => v.severity === 'LOW').length,
            open: vulnerabilities.filter(v => v.status === 'OPEN').length,
            fixed: vulnerabilities.filter(v => v.status === 'FIXED').length
        };

        res.json({
            success: true,
            data: {
                pipeline,
                securityScore,
                scoreGrade: scoreGrade.grade,
                summary: vulnSummary,
                vulnerabilities,
                fixes: {
                    total: fixes.length,
                    autoApplicable: fixes.filter(f => f.auto_applicable).length,
                    applied: fixes.filter(f => f.applied).length,
                    items: fixes
                },
                scanHistory,
                generatedAt: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Error fetching report data:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch report data'
        });
    }
});

// List all pipelines with reports
app.get('/pipelines', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT p.*, 
        (SELECT COUNT(*) FROM detected_vulns dv WHERE dv.pipeline_id = p.pipeline_id) as vuln_count
       FROM pipelines p
       ORDER BY p.last_scan_at DESC
       LIMIT 100`
        );

        res.json({
            success: true,
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching pipelines:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch pipelines' });
    }
});

// Get overall statistics
app.get('/stats', async (req, res) => {
    try {
        const [vulnStats, pipelineStats, fixStats] = await Promise.all([
            pool.query(`
        SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
          SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
          SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
          SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
          SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open,
          SUM(CASE WHEN status = 'FIXED' THEN 1 ELSE 0 END) as fixed
        FROM detected_vulns
      `),
            pool.query(`SELECT COUNT(*) as total FROM pipelines`),
            pool.query(`
        SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN applied = true THEN 1 ELSE 0 END) as applied
        FROM fix_suggestions
      `)
        ]);

        res.json({
            success: true,
            data: {
                vulnerabilities: vulnStats.rows[0],
                pipelines: pipelineStats.rows[0],
                fixes: fixStats.rows[0]
            }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch stats' });
    }
});

// ===========================================
// START SERVER
// ===========================================
app.listen(PORT, () => {
    console.log(`ReportGenerator service running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
