import os
import re
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

import pika
from pymongo import MongoClient
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()

# ===========================================
# LOGGING CONFIGURATION
# ===========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('LogParser')

# ===========================================
# CONFIGURATION
# ===========================================
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/safeops')
RABBITMQ_URL = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672/')
PARSE_INTERVAL_SECONDS = int(os.getenv('PARSE_INTERVAL', '30'))

# ===========================================
# DATA CLASSES
# ===========================================
@dataclass
class ParsedEvent:
    event_id: str
    log_id: str
    pipeline_id: str
    source: str
    event_type: str  # 'job_start', 'job_end', 'step', 'error', 'warning', 'secret_leak', 'artifact'
    timestamp: Optional[str]
    job_name: Optional[str]
    step_name: Optional[str]
    status: Optional[str]
    duration_seconds: Optional[float]
    output_lines: int
    details: Dict[str, Any]
    warnings: List[str]
    errors: List[str]
    secrets_detected: List[str]
    artifacts: List[str]
    raw_content: str

# ===========================================
# LOG PARSING PATTERNS
# ===========================================
class LogPatterns:
    # GitHub Actions patterns
    GITHUB_JOB_START = re.compile(r'##\[group\](.*?)$', re.MULTILINE)
    GITHUB_JOB_END = re.compile(r'##\[endgroup\]')
    GITHUB_ERROR = re.compile(r'##\[error\](.*?)$', re.MULTILINE)
    GITHUB_WARNING = re.compile(r'##\[warning\](.*?)$', re.MULTILINE)
    GITHUB_SET_OUTPUT = re.compile(r'::set-output name=(\w+)::(.*)')
    
    # GitLab CI patterns
    GITLAB_SECTION_START = re.compile(r'section_start:\d+:(\w+)')
    GITLAB_SECTION_END = re.compile(r'section_end:\d+:(\w+)')
    GITLAB_JOB_STATUS = re.compile(r'Job succeeded|Job failed')
    
    # Jenkins patterns
    JENKINS_STAGE = re.compile(r'\[Pipeline\] stage\s*\n\[Pipeline\] \{ \((\w+)\)')
    JENKINS_STEP = re.compile(r'\[Pipeline\] (\w+)')
    
    # Common patterns (security-related)
    SECRET_PATTERNS = [
        re.compile(r'(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', re.IGNORECASE),
        re.compile(r'(secret|password|token|credential)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,})', re.IGNORECASE),
        re.compile(r'(ghp_[A-Za-z0-9]{36})', re.IGNORECASE),  # GitHub personal token
        re.compile(r'(gho_[A-Za-z0-9]{36})', re.IGNORECASE),  # GitHub OAuth token
        re.compile(r'(glpat-[A-Za-z0-9\-]{20,})', re.IGNORECASE),  # GitLab token
        re.compile(r'(AKIA[A-Z0-9]{16})', re.IGNORECASE),  # AWS Access Key
        re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', re.IGNORECASE),
    ]
    
    # Error patterns
    ERROR_PATTERNS = [
        re.compile(r'error[:\s]+(.{10,100})', re.IGNORECASE),
        re.compile(r'failed[:\s]+(.{10,100})', re.IGNORECASE),
        re.compile(r'exception[:\s]+(.{10,100})', re.IGNORECASE),
        re.compile(r'exit code[:\s]*(\d+)', re.IGNORECASE),
    ]
    
    # Artifact patterns
    ARTIFACT_PATTERNS = [
        re.compile(r'Uploading artifact[:\s]*([\w\-\.]+)', re.IGNORECASE),
        re.compile(r'artifact[:\s]*([\w\-\.]+\.(?:jar|zip|tar|gz|war|exe|dll))', re.IGNORECASE),
    ]
    
    # Action usage patterns
    ACTION_USAGE = re.compile(r'uses:\s*([\w\-]+/[\w\-]+)@(\w+)')
    
    # Duration patterns
    DURATION_PATTERN = re.compile(r'(?:took|duration|elapsed)[:\s]*(\d+(?:\.\d+)?)\s*(s|seconds?|ms|milliseconds?|m|minutes?)', re.IGNORECASE)

# ===========================================
# LOG PARSER CLASS
# ===========================================
class CICDLogParser:
    def __init__(self):
        self.patterns = LogPatterns()
    
    def parse(self, raw_log: str, source: str, log_id: str, pipeline_id: str) -> ParsedEvent:
        """Parse raw CI/CD log into structured event."""
        
        event_id = str(uuid.uuid4())
        
        # Initialize parsed data
        warnings = []
        errors = []
        secrets_detected = []
        artifacts = []
        jobs = []
        steps = []
        details = {}
        
        # Detect secrets
        for pattern in self.patterns.SECRET_PATTERNS:
            matches = pattern.findall(raw_log)
            for match in matches:
                if isinstance(match, tuple):
                    secrets_detected.append(f"{match[0]}=***REDACTED***")
                else:
                    secrets_detected.append("***REDACTED_SECRET***")
        
        # Detect errors
        for pattern in self.patterns.ERROR_PATTERNS:
            matches = pattern.findall(raw_log)
            errors.extend(matches[:10])  # Limit to 10 errors
        
        # Detect warnings based on source
        if source == 'GitHub':
            warnings = self.patterns.GITHUB_WARNING.findall(raw_log)
            errors.extend(self.patterns.GITHUB_ERROR.findall(raw_log))
            jobs = self.patterns.GITHUB_JOB_START.findall(raw_log)
            
            # Detect action usage
            action_matches = self.patterns.ACTION_USAGE.findall(raw_log)
            details['actions_used'] = [
                {'name': m[0], 'version': m[1]} for m in action_matches
            ]
        
        elif source == 'GitLab':
            section_starts = self.patterns.GITLAB_SECTION_START.findall(raw_log)
            jobs = section_starts
        
        elif source == 'Jenkins':
            stages = self.patterns.JENKINS_STAGE.findall(raw_log)
            steps = self.patterns.JENKINS_STEP.findall(raw_log)
            jobs = stages
        
        # Detect artifacts
        for pattern in self.patterns.ARTIFACT_PATTERNS:
            artifacts.extend(pattern.findall(raw_log))
        
        # Detect duration
        duration_match = self.patterns.DURATION_PATTERN.search(raw_log)
        duration_seconds = None
        if duration_match:
            value = float(duration_match.group(1))
            unit = duration_match.group(2).lower()
            if 'ms' in unit or 'milli' in unit:
                duration_seconds = value / 1000
            elif 'm' in unit and 'minute' in unit:
                duration_seconds = value * 60
            else:
                duration_seconds = value
        
        # Fallback: Calculate from timestamps if regex failed
        if duration_seconds is None:
            # Find all ISO timestamps
            timestamps = re.findall(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', raw_log)
            if len(timestamps) >= 2:
                try:
                    # Clean timestamps (remove Z for simple parsing if needed, but fromisoformat handles it mostly)
                    # Simple ISO parsing
                    t_start = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                    t_end = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                    duration_seconds = (t_end - t_start).total_seconds()
                except Exception as e:
                    logging.warning(f"Failed to calculate duration from timestamps: {e}")

        # Determine event type
        event_type = 'log_analysis'
        if secrets_detected:
            event_type = 'security_alert'
        elif errors:
            event_type = 'error_detected'
        elif warnings:
            event_type = 'warning_detected'
        
        # Build details
        details.update({
            'jobs_detected': jobs[:50],  # Increased limit to 50 to capture more steps
            'steps_detected': steps[:50],  # Limit to 50
            'line_count': len(raw_log.splitlines()),
            'character_count': len(raw_log)
        })
        
        return ParsedEvent(
            event_id=event_id,
            log_id=log_id,
            pipeline_id=pipeline_id,
            source=source,
            event_type=event_type,
            timestamp=datetime.utcnow().isoformat(),
            job_name=jobs[0] if jobs else None,
            step_name=steps[0] if steps else None,
            status='COMPLETED' if not errors else 'FAILED',
            duration_seconds=duration_seconds,
            output_lines=len(raw_log.splitlines()),
            details=details,
            warnings=warnings[:10],
            errors=list(set(errors))[:10],
            secrets_detected=secrets_detected,
            artifacts=list(set(artifacts)),
            raw_content=raw_log[:5000]  # Store first 5000 chars for reference
        )

# ===========================================
# DATABASE & MESSAGING
# ===========================================
class DatabaseManager:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client.get_default_database()
        self.raw_logs = self.db['raw_logs']
        self.parsed_events = self.db['parsed_events']
        logger.info("Connected to MongoDB")
    
    def get_pending_logs(self, limit: int = 50) -> List[Dict]:
        """Fetch logs that haven't been parsed yet."""
        return list(self.raw_logs.find(
            {'status': 'PENDING'},
            limit=limit
        ).sort('uploadedAt', 1))
    
    def mark_log_parsed(self, log_id: str):
        """Update log status to PARSED."""
        self.raw_logs.update_one(
            {'logId': log_id},
            {'$set': {'status': 'PARSED', 'parsedAt': datetime.utcnow()}}
        )
    
    def mark_log_failed(self, log_id: str, error: str):
        """Update log status to FAILED."""
        self.raw_logs.update_one(
            {'logId': log_id},
            {'$set': {'status': 'FAILED', 'parseError': error}}
        )
    
    def save_parsed_event(self, event: ParsedEvent):
        """Save parsed event to MongoDB."""
        self.parsed_events.insert_one(asdict(event))
    
    def get_parsed_event(self, event_id: str) -> Optional[Dict]:
        """Get parsed event by ID."""
        return self.parsed_events.find_one({'event_id': event_id})


class MessageQueue:
    def __init__(self):
        self.connection = None
        self.channel = None
    
    def _connect(self):
        """Establish RabbitMQ connection with heartbeat."""
        try:
            # Close existing connection if any
            if self.connection and not self.connection.is_closed:
                try:
                    self.connection.close()
                except Exception:
                    pass
            
            params = pika.URLParameters(RABBITMQ_URL)
            params.heartbeat = 600  # 10 minute heartbeat
            params.blocked_connection_timeout = 300
            
            self.connection = pika.BlockingConnection(params)
            self.channel = self.connection.channel()
            
            # Declare exchange for parsed logs
            self.channel.exchange_declare(
                exchange='logs_parsed',
                exchange_type='fanout',
                durable=True
            )
            logger.info("Connected to RabbitMQ")
        except Exception as e:
            logger.error(f"RabbitMQ connection failed: {e}")
            self.connection = None
            self.channel = None
            raise
    
    def _ensure_connection(self):
        """Ensure connection is active, reconnect if needed."""
        try:
            if self.connection is None or self.connection.is_closed:
                self._connect()
            elif self.channel is None or self.channel.is_closed:
                self._connect()
        except Exception as e:
            logger.warning(f"Reconnection attempt: {e}")
            self._connect()
    
    def publish_parsed_event(self, event: ParsedEvent):
        """Publish parsed event to RabbitMQ with retry."""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                self._ensure_connection()
                
                message = json.dumps({
                    'event_id': event.event_id,
                    'log_id': event.log_id,
                    'pipeline_id': event.pipeline_id,
                    'source': event.source,
                    'event_type': event.event_type,
                    'has_secrets': len(event.secrets_detected) > 0,
                    'has_errors': len(event.errors) > 0,
                    'timestamp': event.timestamp
                })
                
                self.channel.basic_publish(
                    exchange='logs_parsed',
                    routing_key='',  # Fanout ignores routing key
                    body=message,
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # Persistent
                        content_type='application/json'
                    )
                )
                logger.info(f"Published event {event.event_id} to logs_parsed exchange")
                return  # Success, exit the loop
                
            except Exception as e:
                logger.warning(f"Publish attempt {attempt + 1} failed: {e}")
                self.connection = None  # Force reconnection
                if attempt == max_retries - 1:
                    logger.error(f"Failed to publish after {max_retries} attempts: {e}")
                    raise

# ===========================================
# MAIN SERVICE
# ===========================================
app = Flask(__name__)
db = None
mq = None
parser = CICDLogParser()
scheduler = BackgroundScheduler()


def process_pending_logs():
    """Background job to process pending logs."""
    global db, mq
    
    try:
        if db is None:
            db = DatabaseManager()
        if mq is None:
            mq = MessageQueue()
        
        pending_logs = db.get_pending_logs(limit=20)
        logger.info(f"Found {len(pending_logs)} pending logs to parse")
        
        for log_doc in pending_logs:
            try:
                log_id = log_doc['logId']
                raw_log = log_doc['rawLog']
                source = log_doc['source']
                pipeline_id = log_doc['pipelineId']
                
                # Parse the log
                parsed_event = parser.parse(raw_log, source, log_id, pipeline_id)
                
                # Save to MongoDB
                db.save_parsed_event(parsed_event)
                
                # Publish to RabbitMQ
                mq.publish_parsed_event(parsed_event)
                
                # Mark as parsed
                db.mark_log_parsed(log_id)
                
                logger.info(f"Parsed log {log_id}: {parsed_event.event_type}")
                
            except Exception as e:
                logger.error(f"Error parsing log {log_doc.get('logId')}: {e}")
                db.mark_log_failed(log_doc.get('logId', 'unknown'), str(e))
                
    except Exception as e:
        logger.error(f"Error in process_pending_logs: {e}")


@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'log-parser',
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/parse', methods=['POST'])
def trigger_parse():
    """Manually trigger log parsing."""
    try:
        process_pending_logs()
        return jsonify({
            'success': True,
            'message': 'Parse job triggered successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/events/<event_id>')
def get_event(event_id):
    """Get a parsed event by ID."""
    global db
    if db is None:
        db = DatabaseManager()
    
    event = db.get_parsed_event(event_id)
    if event:
        event['_id'] = str(event['_id'])
        return jsonify({'success': True, 'data': event})
    return jsonify({'success': False, 'error': 'Event not found'}), 404


@app.route('/events')
def list_events():
    """List parsed events."""
    global db
    if db is None:
        db = DatabaseManager()
    
    limit = int(request.args.get('limit', 50))
    events = list(db.parsed_events.find(
        {},
        {'raw_content': 0}  # Exclude large field
    ).sort('timestamp', -1).limit(limit))
    
    for e in events:
        e['_id'] = str(e['_id'])
    
    return jsonify({'success': True, 'data': events})


def init_services():
    """Initialize database and message queue connections."""
    global db, mq
    try:
        db = DatabaseManager()
        mq = MessageQueue()
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")


if __name__ == '__main__':
    # Initialize connections
    init_services()
    
    # Start background scheduler
    scheduler.add_job(
        process_pending_logs,
        'interval',
        seconds=PARSE_INTERVAL_SECONDS,
        id='parse_logs_job'
    )
    scheduler.start()
    logger.info(f"Scheduler started - parsing every {PARSE_INTERVAL_SECONDS} seconds")
    
    # Run Flask app
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
