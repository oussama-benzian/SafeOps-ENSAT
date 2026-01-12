import os
import re
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

import pika
import psycopg2
from psycopg2.extras import RealDictCursor
from jinja2 import Environment, FileSystemLoader
from flask import Flask, jsonify, request
from dotenv import load_dotenv

load_dotenv()

# ===========================================
# LOGGING CONFIGURATION
# ===========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('FixSuggester')

# ===========================================
# CONFIGURATION
# ===========================================
POSTGRES_URI = os.getenv('POSTGRES_URI', 'postgresql://safeops:safeops_secret@localhost:5432/safeops')
RABBITMQ_URL = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672/')
TEMPLATES_DIR = os.getenv('TEMPLATES_DIR', '/app/templates')

# ===========================================
# DATA CLASSES
# ===========================================
@dataclass
class FixSuggestion:
    fix_id: str
    vulnerability_id: str
    fix_type: str
    title: str
    description: str
    original_code: Optional[str]
    suggested_code: str
    diff_patch: str
    confidence_score: float
    auto_applicable: bool

# ===========================================
# TEMPLATE ENGINE
# ===========================================
class FixTemplateEngine:
    """Jinja2-based template engine for generating fix suggestions."""
    
    TEMPLATE_MAPPING = {
        'SLSA-001': 'pin_action.yaml.j2',
        'SLSA-002': 'generic_fix.yaml.j2',
        'SLSA-003': 'generic_fix.yaml.j2',
        'OWASP-001': 'use_secrets.yaml.j2',
        'OWASP-002': 'use_secrets.yaml.j2',
        'OWASP-003': 'use_secrets.yaml.j2',
        'OWASP-004': 'use_secrets.yaml.j2',
        'OWASP-005': 'use_secrets.yaml.j2',
        'OWASP-006': 'sanitize_input.yaml.j2',
        'OWASP-007': 'generic_fix.yaml.j2',
        'CIS-001': 'restrict_permissions.yaml.j2',
        'CIS-002': 'restrict_permissions.yaml.j2',
        'CIS-003': 'generic_fix.yaml.j2',
        'CIS-004': 'generic_fix.yaml.j2',
        'CIS-005': 'generic_fix.yaml.j2',
        'CIS-006': 'pin_docker.yaml.j2',
        'CIS-007': 'generic_fix.yaml.j2',
    }
    
    def __init__(self, templates_dir: str):
        self.templates_dir = Path(templates_dir)
        if self.templates_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(self.templates_dir)),
                autoescape=False
            )
            logger.info(f"Loaded templates from {templates_dir}")
        else:
            logger.warning(f"Templates directory not found: {templates_dir}")
            self.env = None
    
    def generate_fix(self, vulnerability: Dict) -> FixSuggestion:
        """Generate a fix suggestion for a vulnerability."""
        
        rule_id = vulnerability.get('rule_id', 'UNKNOWN')
        template_name = self.TEMPLATE_MAPPING.get(rule_id, 'generic_fix.yaml.j2')
        
        # Prepare template context
        context = self._prepare_context(vulnerability)
        
        # Render template
        suggested_code = self._render_template(template_name, context)
        
        # Generate diff
        original_code = vulnerability.get('evidence', '')
        diff_patch = self._generate_diff(original_code, suggested_code)
        
        # Determine confidence and auto-applicability
        confidence_score, auto_applicable = self._assess_fix(rule_id, vulnerability)
        
        return FixSuggestion(
            fix_id=str(uuid.uuid4()),
            vulnerability_id=str(vulnerability.get('id', 'unknown')),
            fix_type=self._get_fix_type(rule_id),
            title=f"Fix for {vulnerability.get('title', 'Unknown Issue')}",
            description=self._generate_description(vulnerability),
            original_code=original_code[:1000] if original_code else None,
            suggested_code=suggested_code,
            diff_patch=diff_patch,
            confidence_score=confidence_score,
            auto_applicable=auto_applicable
        )
    
    def _prepare_context(self, vulnerability: Dict) -> Dict:
        """Prepare context for template rendering."""
        evidence = vulnerability.get('evidence', '') or ''
        rule_id = vulnerability.get('rule_id', '') or ''  # Ensure not None
        
        context = {
            'rule_id': rule_id,
            'severity': vulnerability.get('severity', 'UNKNOWN'),
            'description': vulnerability.get('description', ''),
            'evidence': evidence,
            'affected_component': vulnerability.get('affected_component', ''),
            'category': vulnerability.get('vulnerability_type', ''),
            'remediation': vulnerability.get('remediation', ''),
        }
        
        # Extract specific data based on rule type
        if rule_id and 'SLSA-001' in rule_id:
            # Extract action name and version
            match = re.search(r'uses:\s*([\w\-]+/[\w\-]+)@(\w+)', evidence)
            if match:
                context['action_name'] = match.group(1)
                context['original_version'] = match.group(2)
                context['recommended_sha'] = self._get_recommended_sha(match.group(1))
        
        elif rule_id and ('OWASP-001' in rule_id or 'OWASP-002' in rule_id):
            # Extract credential info
            match = re.search(r'(\w+)[=:]\s*["\']?([^"\']+)', evidence)
            if match:
                context['credential_name'] = match.group(1)
                context['masked_value'] = '***REDACTED***'
                context['secret_name'] = match.group(1).upper()
        
        elif rule_id and 'OWASP-006' in rule_id:
            # Extract input source
            match = re.search(r'github\.event\.(\w+)\.(\w+)', evidence)
            if match:
                context['input_source'] = match.group(1)
                context['input_field'] = match.group(2)
        
        elif rule_id and ('CIS-001' in rule_id or 'CIS-002' in rule_id):
            context['needs_packages'] = False
            context['needs_issues'] = False
            context['needs_pr'] = False
        
        elif rule_id and 'CIS-006' in rule_id:
            # Extract Docker image info
            match = re.search(r'([\w\-/]+):(latest|\w+)', evidence)
            if match:
                context['image_name'] = match.group(1)
                context['tag'] = match.group(2)
        
        return context
    
    def _get_recommended_sha(self, action_name: str) -> str:
        """Get recommended SHA for common actions (simplified lookup)."""
        # In production, this would query GitHub API or a maintained database
        known_shas = {
            'actions/checkout': 'b4ffde65f46336ab88eb53be808477a3936bae11',
            'actions/setup-node': '0a44ba7841725637a19e28fa30b79a866c81b0a6',
            'actions/setup-python': '0a5c61591373683505ea898e09a3ea4f39ef2b9c',
            'actions/cache': 'v3',  # Would be SHA in production
            'actions/upload-artifact': '5d5d22a31266ced268874388b861e4b58bb5c2f3',
        }
        return known_shas.get(action_name, 'COMMIT_SHA_HERE')
    
    def _render_template(self, template_name: str, context: Dict) -> str:
        """Render a Jinja2 template."""
        if self.env is None:
            return self._generate_fallback_fix(context)
        
        try:
            template = self.env.get_template(template_name)
            return template.render(**context)
        except Exception as e:
            logger.warning(f"Template rendering failed: {e}")
            return self._generate_fallback_fix(context)
    
    def _generate_fallback_fix(self, context: Dict) -> str:
        """Generate a basic fix when templates are unavailable."""
        return f"""# Security Fix Required
# Rule: {context.get('rule_id', 'Unknown')}
# Severity: {context.get('severity', 'Unknown')}

## Issue
{context.get('description', 'Security vulnerability detected')}

## Recommendation
{context.get('remediation', 'Please review and fix the identified issue.')}

## Evidence
{context.get('evidence', 'N/A')[:500]}
"""
    
    def _generate_diff(self, original: str, suggested: str) -> str:
        """Generate a simple diff representation."""
        if not original:
            return f"+++ Suggested Fix +++\n{suggested[:1000]}"
        
        lines = []
        lines.append("--- Original")
        lines.append("+++ Suggested")
        lines.append("@@ Fix Required @@")
        
        for line in original.split('\n')[:10]:
            lines.append(f"- {line}")
        
        lines.append("...")
        lines.append("+++ See suggested_code for complete fix +++")
        
        return '\n'.join(lines)
    
    def _assess_fix(self, rule_id: str, vulnerability: Dict) -> tuple:
        """Assess fix confidence and auto-applicability."""
        # High confidence, auto-applicable fixes
        high_confidence_rules = ['SLSA-001', 'CIS-001', 'CIS-002', 'CIS-006']
        
        if rule_id in high_confidence_rules:
            return 0.85, True
        
        # Medium confidence
        medium_confidence_rules = ['OWASP-006', 'CIS-007']
        if rule_id in medium_confidence_rules:
            return 0.65, False
        
        # Critical issues need manual review
        if vulnerability.get('severity') == 'CRITICAL':
            return 0.50, False
        
        return 0.60, False
    
    def _get_fix_type(self, rule_id: str) -> str:
        """Determine fix type from rule ID."""
        if not rule_id:
            return 'general_fix'
        if rule_id.startswith('SLSA'):
            return 'supply_chain_fix'
        elif rule_id.startswith('OWASP'):
            return 'security_fix'
        elif rule_id.startswith('CIS'):
            return 'config_fix'
        return 'general_fix'
    
    def _generate_description(self, vulnerability: Dict) -> str:
        """Generate fix description."""
        return f"""This fix addresses the {vulnerability.get('severity', 'Unknown')} severity issue: {vulnerability.get('title', 'Unknown')}.

{vulnerability.get('remediation', 'Please review and apply the suggested changes.')}

Category: {vulnerability.get('vulnerability_type', 'Unknown')}
Rule: {vulnerability.get('rule_id', 'Unknown')}"""

# ===========================================
# DATABASE MANAGER
# ===========================================
class PostgresManager:
    def __init__(self):
        self.conn = psycopg2.connect(POSTGRES_URI)
        self.conn.autocommit = True
        logger.info("Connected to PostgreSQL")
    
    def get_vulnerability(self, vuln_id: str) -> Optional[Dict]:
        """Get vulnerability by ID."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT dv.*, sr.rule_id, sr.remediation
                FROM detected_vulns dv
                LEFT JOIN security_rules sr ON dv.rule_id = sr.id
                WHERE dv.id = %s
            """, (vuln_id,))
            return cur.fetchone()
    
    def get_pending_vulnerabilities(self, limit: int = 50) -> List[Dict]:
        """Get vulnerabilities without fix suggestions."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT dv.*, sr.rule_id, sr.remediation
                FROM detected_vulns dv
                LEFT JOIN security_rules sr ON dv.rule_id = sr.id
                LEFT JOIN fix_suggestions fs ON dv.id = fs.vulnerability_id
                WHERE fs.id IS NULL AND dv.status = 'OPEN'
                ORDER BY 
                    CASE dv.severity 
                        WHEN 'CRITICAL' THEN 1 
                        WHEN 'HIGH' THEN 2 
                        WHEN 'MEDIUM' THEN 3 
                        ELSE 4 
                    END
                LIMIT %s
            """, (limit,))
            return cur.fetchall()
    
    def save_fix_suggestion(self, fix: FixSuggestion) -> str:
        """Save fix suggestion to database."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO fix_suggestions (
                    id, vulnerability_id, fix_type, title, description,
                    original_code, suggested_code, diff_patch,
                    confidence_score, auto_applicable
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                fix.fix_id, fix.vulnerability_id, fix.fix_type,
                fix.title, fix.description, fix.original_code,
                fix.suggested_code, fix.diff_patch,
                fix.confidence_score, fix.auto_applicable
            ))
            return cur.fetchone()[0]
    
    def get_fix_suggestions(self, vulnerability_id: str = None, limit: int = 50) -> List[Dict]:
        """Get fix suggestions."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            if vulnerability_id:
                cur.execute("""
                    SELECT * FROM fix_suggestions
                    WHERE vulnerability_id = %s
                    ORDER BY created_at DESC
                """, (vulnerability_id,))
            else:
                cur.execute("""
                    SELECT fs.*, dv.pipeline_id, dv.severity, dv.title as vuln_title
                    FROM fix_suggestions fs
                    JOIN detected_vulns dv ON fs.vulnerability_id = dv.id
                    ORDER BY fs.created_at DESC
                    LIMIT %s
                """, (limit,))
            return cur.fetchall()
    
    def mark_fix_applied(self, fix_id: str):
        """Mark a fix as applied."""
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE fix_suggestions
                SET applied = true, applied_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (fix_id,))
            
            # Also update the vulnerability status
            cur.execute("""
                UPDATE detected_vulns
                SET status = 'FIXED', updated_at = CURRENT_TIMESTAMP
                WHERE id = (SELECT vulnerability_id FROM fix_suggestions WHERE id = %s)
            """, (fix_id,))

# ===========================================
# MESSAGE QUEUE
# ===========================================
class MessageQueue:
    def __init__(self):
        self.connection = None
        self.channel = None
        self._connect()
    
    def _connect(self):
        """Establish RabbitMQ connection."""
        try:
            params = pika.URLParameters(RABBITMQ_URL)
            self.connection = pika.BlockingConnection(params)
            self.channel = self.connection.channel()
            
            # Declare exchange and queue
            self.channel.exchange_declare(
                exchange='vulnerability_detected',
                exchange_type='fanout',
                durable=True
            )
            
            self.channel.queue_declare(queue='fix_suggester_queue', durable=True)
            self.channel.queue_bind(
                exchange='vulnerability_detected',
                queue='fix_suggester_queue'
            )
            
            logger.info("Connected to RabbitMQ")
        except Exception as e:
            logger.error(f"RabbitMQ connection failed: {e}")
            raise

# ===========================================
# MAIN SERVICE
# ===========================================
app = Flask(__name__)
postgres = None
mq = None
template_engine = None


def init_services():
    """Initialize all service connections."""
    global postgres, mq, template_engine
    postgres = PostgresManager()
    mq = MessageQueue()
    template_engine = FixTemplateEngine(TEMPLATES_DIR)


def process_message(ch, method, properties, body):
    """Process incoming vulnerability message."""
    global postgres, template_engine
    
    try:
        message = json.loads(body)
        vuln_id = message.get('vuln_id')
        
        logger.info(f"Processing vulnerability: {vuln_id}")
        
        # Fetch vulnerability details
        vulnerability = postgres.get_vulnerability(vuln_id)
        if not vulnerability:
            logger.warning(f"Vulnerability {vuln_id} not found")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return
        
        # Convert UUID objects to strings
        vuln_dict = dict(vulnerability)
        for key in vuln_dict:
            if isinstance(vuln_dict[key], uuid.UUID):
                vuln_dict[key] = str(vuln_dict[key])
        
        # Generate fix suggestion
        fix = template_engine.generate_fix(vuln_dict)
        
        # Save to database
        postgres.save_fix_suggestion(fix)
        
        logger.info(f"Generated fix {fix.fix_id} for vulnerability {vuln_id}")
        logger.info(f"   Type: {fix.fix_type}, Confidence: {fix.confidence_score:.2f}")
        
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)


def start_consumer():
    """Start consuming messages from RabbitMQ."""
    global mq
    
    logger.info("Starting FixSuggester consumer...")
    
    mq.channel.basic_qos(prefetch_count=1)
    mq.channel.basic_consume(
        queue='fix_suggester_queue',
        on_message_callback=process_message
    )
    
    logger.info("FixSuggester consumer started. Waiting for messages...")
    mq.channel.start_consuming()


@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'fix-suggester',
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/fix', methods=['POST'])
def generate_fix():
    """Manually generate a fix for a vulnerability."""
    global postgres, template_engine
    
    try:
        data = request.json
        vuln_id = data.get('vulnerability_id')
        
        if not vuln_id:
            return jsonify({'success': False, 'error': 'vulnerability_id required'}), 400
        
        vulnerability = postgres.get_vulnerability(vuln_id)
        if not vulnerability:
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
        
        # Convert to dict
        vuln_dict = dict(vulnerability)
        for key in vuln_dict:
            if isinstance(vuln_dict[key], uuid.UUID):
                vuln_dict[key] = str(vuln_dict[key])
        
        fix = template_engine.generate_fix(vuln_dict)
        postgres.save_fix_suggestion(fix)
        
        return jsonify({
            'success': True,
            'data': asdict(fix)
        })
        
    except Exception as e:
        logger.error(f"Manual fix generation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/fixes')
def list_fixes():
    """List fix suggestions."""
    global postgres
    
    vuln_id = request.args.get('vulnerability_id')
    limit = int(request.args.get('limit', 50))
    
    fixes = postgres.get_fix_suggestions(vuln_id, limit)
    
    # Convert UUID and datetime objects
    for f in fixes:
        for key in f:
            if isinstance(f[key], uuid.UUID):
                f[key] = str(f[key])
            elif hasattr(f[key], 'isoformat'):
                f[key] = f[key].isoformat()
    
    return jsonify({'success': True, 'data': fixes})


@app.route('/fixes/<fix_id>/apply', methods=['POST'])
def apply_fix(fix_id):
    """Mark a fix as applied."""
    global postgres
    
    try:
        postgres.mark_fix_applied(fix_id)
        return jsonify({
            'success': True,
            'message': f'Fix {fix_id} marked as applied'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    import threading
    
    init_services()
    
    # Start RabbitMQ consumer in a separate thread
    consumer_thread = threading.Thread(target=start_consumer, daemon=True)
    consumer_thread.start()
    
    # Run Flask app
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
