import os
import re
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

import yaml
import pika
import psycopg2
from psycopg2.extras import RealDictCursor
from pymongo import MongoClient
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
logger = logging.getLogger('VulnDetector')

# ===========================================
# CONFIGURATION
# ===========================================
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/safeops')
POSTGRES_URI = os.getenv('POSTGRES_URI', 'postgresql://safeops:safeops_secret@localhost:5432/safeops')
RABBITMQ_URL = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672/')
RULES_FILE = os.getenv('RULES_FILE', '/app/config/rules.yaml')

# ===========================================
# DATA CLASSES
# ===========================================
@dataclass
class Vulnerability:
  vuln_id: str
  pipeline_id: str
  parsed_event_id: str
  rule_id: str
  vulnerability_type: str
  severity: str
  title: str
  description: str
  affected_component: str
  evidence: str
  line_number: Optional[int]
  file_path: Optional[str]
  source: str
  detected_at: str

# ===========================================
# DATABASE MANAGERS
# ===========================================
class MongoManager:
  def __init__(self):
    self.client = MongoClient(MONGODB_URI)
    self.db = self.client.get_default_database()
    self.parsed_events = self.db['parsed_events']
    logger.info("Connected to MongoDB")
  
  def get_parsed_event(self, event_id: str) -> Optional[Dict]:
    return self.parsed_events.find_one({'event_id': event_id})


class PostgresManager:
  def __init__(self):
    self.conn = psycopg2.connect(POSTGRES_URI)
    self.conn.autocommit = True
    logger.info("Connected to PostgreSQL")
  
  def get_security_rules(self) -> List[Dict]:
    """Fetch enabled security rules from database."""
    with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
      cur.execute("""
        SELECT id, rule_id, name, description, category, severity, 
            pattern, rule_type, remediation
        FROM security_rules
        WHERE enabled = true
      """)
      return cur.fetchall()
  
  def save_vulnerability(self, vuln: Vulnerability) -> str:
    """Save detected vulnerability to database."""
    with self.conn.cursor() as cur:
      cur.execute("""
        INSERT INTO detected_vulns (
          id, pipeline_id, parsed_event_id, rule_id, 
          vulnerability_type, severity, title, description,
          affected_component, evidence, line_number, file_path,
          source, status, detected_at
        ) VALUES (
          %s, %s, %s, 
          (SELECT id FROM security_rules WHERE rule_id = %s),
          %s, %s, %s, %s, %s, %s, %s, %s, %s, 'OPEN', %s
        )
        RETURNING id
      """, (
        vuln.vuln_id, vuln.pipeline_id, vuln.parsed_event_id,
        vuln.rule_id, vuln.vulnerability_type, vuln.severity,
        vuln.title, vuln.description, vuln.affected_component,
        vuln.evidence[:1000] if vuln.evidence else None, # Limit evidence length
        vuln.line_number, vuln.file_path, vuln.source,
        vuln.detected_at
      ))
      return cur.fetchone()[0]
  
  def get_vulnerabilities(self, pipeline_id: str = None, limit: int = 50) -> List[Dict]:
    """Get detected vulnerabilities."""
    with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
      if pipeline_id:
        cur.execute("""
          SELECT dv.*, sr.name as rule_name, sr.remediation
          FROM detected_vulns dv
          LEFT JOIN security_rules sr ON dv.rule_id = sr.id
          WHERE dv.pipeline_id = %s
          ORDER BY dv.detected_at DESC
          LIMIT %s
        """, (pipeline_id, limit))
      else:
        cur.execute("""
          SELECT dv.*, sr.name as rule_name, sr.remediation
          FROM detected_vulns dv
          LEFT JOIN security_rules sr ON dv.rule_id = sr.id
          ORDER BY dv.detected_at DESC
          LIMIT %s
        """, (limit,))
      return cur.fetchall()
  
  def update_pipeline_stats(self, pipeline_id: str):
    """Update pipeline security statistics."""
    with self.conn.cursor() as cur:
      cur.execute("""
        INSERT INTO pipelines (pipeline_id, last_scan_at, 
          total_vulnerabilities, critical_count, high_count, 
          medium_count, low_count)
        SELECT 
          %s,
          CURRENT_TIMESTAMP,
          COUNT(*),
          SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END),
          SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END),
          SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END),
          SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END)
        FROM detected_vulns
        WHERE pipeline_id = %s AND status = 'OPEN'
        ON CONFLICT (pipeline_id) DO UPDATE SET
          last_scan_at = CURRENT_TIMESTAMP,
          total_vulnerabilities = EXCLUDED.total_vulnerabilities,
          critical_count = EXCLUDED.critical_count,
          high_count = EXCLUDED.high_count,
          medium_count = EXCLUDED.medium_count,
          low_count = EXCLUDED.low_count,
          updated_at = CURRENT_TIMESTAMP
      """, (pipeline_id, pipeline_id))


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
      
      # Declare exchanges and queues
      self.channel.exchange_declare(
        exchange='logs_parsed',
        exchange_type='fanout',
        durable=True
      )
      self.channel.exchange_declare(
        exchange='vulnerability_detected',
        exchange_type='fanout',
        durable=True
      )
      
      # Queue for VulnDetector
      self.channel.queue_declare(queue='vuln_detector_queue', durable=True)
      self.channel.queue_bind(
        exchange='logs_parsed',
        queue='vuln_detector_queue'
      )
      
      logger.info("Connected to RabbitMQ")
    except Exception as e:
      logger.error(f"RabbitMQ connection failed: {e}")
      raise
  
  def publish_vulnerability(self, vuln: Vulnerability):
    """Publish detected vulnerability to RabbitMQ."""
    try:
      if not self.connection or self.connection.is_closed:
        self._connect()
      
      message = json.dumps({
        'vuln_id': vuln.vuln_id,
        'pipeline_id': vuln.pipeline_id,
        'rule_id': vuln.rule_id,
        'severity': vuln.severity,
        'vulnerability_type': vuln.vulnerability_type,
        'title': vuln.title,
        'timestamp': vuln.detected_at
      })
      
      self.channel.basic_publish(
        exchange='vulnerability_detected',
        routing_key='',
        body=message,
        properties=pika.BasicProperties(
          delivery_mode=2,
          content_type='application/json'
        )
      )
      logger.info(f"Published vulnerability {vuln.vuln_id}")
    except Exception as e:
      logger.error(f"Failed to publish vulnerability: {e}")

# ===========================================
# VULNERABILITY DETECTOR ENGINE
# ===========================================
class VulnDetectorEngine:
  def __init__(self, postgres: PostgresManager):
    self.postgres = postgres
    self.rules = self._load_rules()
  
  def _load_rules(self) -> List[Dict]:
    """Load rules from database and YAML file."""
    rules = []
    
    # Load from database
    try:
      db_rules = self.postgres.get_security_rules()
      rules.extend(db_rules)
      logger.info(f"Loaded {len(db_rules)} rules from database")
    except Exception as e:
      logger.warning(f"Could not load rules from database: {e}")
    
    # Load from YAML file as fallback/supplement
    try:
      if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
          yaml_rules = yaml.safe_load(f)
          if yaml_rules and 'rules' in yaml_rules:
            for rule in yaml_rules['rules']:
              # Only add if not already in DB rules
              if not any(r.get('rule_id') == rule['id'] for r in rules):
                rules.append({
                  'rule_id': rule['id'],
                  'name': rule['name'],
                  'description': rule['description'],
                  'category': rule['category'],
                  'severity': rule['severity'],
                  'pattern': rule['pattern'],
                  'rule_type': rule['rule_type'],
                  'remediation': rule.get('remediation', '')
                })
        logger.info(f"Total rules loaded: {len(rules)}")
    except Exception as e:
      logger.warning(f"Could not load YAML rules: {e}")
    
    return rules
  
  def scan(self, parsed_event: Dict) -> List[Vulnerability]:
    """Scan parsed event for vulnerabilities."""
    vulnerabilities = []
    content_to_scan = self._prepare_content(parsed_event)
    
    for rule in self.rules:
      try:
        pattern = rule.get('pattern', '')
        if not pattern:
          continue
        
        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        matches = regex.finditer(content_to_scan)
        
        for match in matches:
          vuln = Vulnerability(
            vuln_id=str(uuid.uuid4()),
            pipeline_id=parsed_event.get('pipeline_id', 'unknown'),
            parsed_event_id=parsed_event.get('event_id', 'unknown'),
            rule_id=rule.get('rule_id', 'UNKNOWN'),
            vulnerability_type=rule.get('category', 'CUSTOM'),
            severity=rule.get('severity', 'MEDIUM'),
            title=rule.get('name', 'Unknown Vulnerability'),
            description=rule.get('description', ''),
            affected_component=self._find_component(match, content_to_scan),
            evidence=match.group(0)[:500],
            line_number=self._get_line_number(content_to_scan, match.start()),
            file_path=parsed_event.get('file_path'),
            source=parsed_event.get('source', 'Unknown'),
            detected_at=datetime.utcnow().isoformat()
          )
          vulnerabilities.append(vuln)
          
      except re.error as e:
        logger.warning(f"Invalid regex pattern in rule {rule.get('rule_id')}: {e}")
      except Exception as e:
        logger.error(f"Error applying rule {rule.get('rule_id')}: {e}")
    
    # Also check pre-detected issues from parser
    if parsed_event.get('secrets_detected'):
      for secret in parsed_event['secrets_detected']:
        vuln = Vulnerability(
          vuln_id=str(uuid.uuid4()),
          pipeline_id=parsed_event.get('pipeline_id', 'unknown'),
          parsed_event_id=parsed_event.get('event_id', 'unknown'),
          rule_id='PARSER-SECRET',
          vulnerability_type='OWASP',
          severity='CRITICAL',
          title='Secret Detected by Parser',
          description='The log parser detected a potential secret or credential',
          affected_component='Pipeline Logs',
          evidence=secret,
          line_number=None,
          file_path=None,
          source=parsed_event.get('source', 'Unknown'),
          detected_at=datetime.utcnow().isoformat()
        )
        vulnerabilities.append(vuln)
    
    return vulnerabilities
  
  def _prepare_content(self, parsed_event: Dict) -> str:
    """Prepare content for scanning."""
    parts = []
    
    if parsed_event.get('raw_content'):
      parts.append(parsed_event['raw_content'])
    
    # Include details that might contain security issues
    details = parsed_event.get('details', {})
    if details.get('actions_used'):
      for action in details['actions_used']:
        parts.append(f"uses: {action['name']}@{action['version']}")
    
    return '\n'.join(parts)
  
  def _find_component(self, match: re.Match, content: str) -> str:
    """Try to find which component/job the vulnerability is in."""
    # Get context around the match
    start = max(0, match.start() - 100)
    end = min(len(content), match.end() + 50)
    context = content[start:end]
    
    # Try to find job or step name
    job_match = re.search(r'(?:job|step|stage)[:\s]*([^\n]+)', context, re.IGNORECASE)
    if job_match:
      return job_match.group(1).strip()[:100]
    
    return "Pipeline Configuration"
  
  def _get_line_number(self, content: str, position: int) -> int:
    """Get line number from character position."""
    return content[:position].count('\n') + 1

# ===========================================
# MAIN SERVICE
# ===========================================
app = Flask(__name__)
mongo = None
postgres = None
mq = None
engine = None


def init_services():
  """Initialize all service connections."""
  global mongo, postgres, mq, engine
  mongo = MongoManager()
  postgres = PostgresManager()
  mq = MessageQueue()
  engine = VulnDetectorEngine(postgres)


def process_message(ch, method, properties, body):
  """Process incoming parsed log message."""
  global mongo, postgres, mq, engine
  
  try:
    message = json.loads(body)
    event_id = message.get('event_id')
    
    logger.info(f"Processing event: {event_id}")
    
    # Fetch full parsed event from MongoDB
    parsed_event = mongo.get_parsed_event(event_id)
    if not parsed_event:
      logger.warning(f"Event {event_id} not found in MongoDB")
      ch.basic_ack(delivery_tag=method.delivery_tag)
      return
    
    # Scan for vulnerabilities
    vulnerabilities = engine.scan(parsed_event)
    
    logger.info(f"Found {len(vulnerabilities)} vulnerabilities in event {event_id}")
    
    # Save and publish each vulnerability
    for vuln in vulnerabilities:
      try:
        postgres.save_vulnerability(vuln)
        mq.publish_vulnerability(vuln)
        logger.info(f"  {vuln.severity}: {vuln.title}")
      except Exception as e:
        logger.error(f"Error saving vulnerability: {e}")
    
    # Update pipeline statistics
    pipeline_id = parsed_event.get('pipeline_id')
    if pipeline_id:
      postgres.update_pipeline_stats(pipeline_id)
    
    ch.basic_ack(delivery_tag=method.delivery_tag)
    
  except Exception as e:
    logger.error(f"Error processing message: {e}")
    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)


def start_consumer():
  """Start consuming messages from RabbitMQ."""
  global mq
  
  logger.info("Starting VulnDetector consumer...")
  
  mq.channel.basic_qos(prefetch_count=1)
  mq.channel.basic_consume(
    queue='vuln_detector_queue',
    on_message_callback=process_message
  )
  
  logger.info("VulnDetector consumer started. Waiting for messages...")
  mq.channel.start_consuming()


@app.route('/health')
def health():
  return jsonify({
    'status': 'healthy',
    'service': 'vuln-detector',
    'timestamp': datetime.utcnow().isoformat()
  })


@app.route('/scan', methods=['POST'])
def manual_scan():
  """Manually trigger vulnerability scan on an event."""
  global mongo, engine, postgres, mq
  
  try:
    data = request.json
    event_id = data.get('event_id')
    
    if not event_id:
      return jsonify({'success': False, 'error': 'event_id required'}), 400
    
    parsed_event = mongo.get_parsed_event(event_id)
    if not parsed_event:
      return jsonify({'success': False, 'error': 'Event not found'}), 404
    
    vulnerabilities = engine.scan(parsed_event)
    
    for vuln in vulnerabilities:
      postgres.save_vulnerability(vuln)
      mq.publish_vulnerability(vuln)
    
    return jsonify({
      'success': True,
      'vulnerabilities_found': len(vulnerabilities),
      'data': [asdict(v) for v in vulnerabilities]
    })
    
  except Exception as e:
    logger.error(f"Manual scan error: {e}")
    return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/vulnerabilities')
def list_vulnerabilities():
  """List detected vulnerabilities."""
  global postgres
  
  pipeline_id = request.args.get('pipeline_id')
  limit = int(request.args.get('limit', 50))
  
  vulns = postgres.get_vulnerabilities(pipeline_id, limit)
  
  # Convert UUID and datetime objects to strings
  for v in vulns:
    for key in v:
      if isinstance(v[key], (uuid.UUID,)):
        v[key] = str(v[key])
      elif hasattr(v[key], 'isoformat'):
        v[key] = v[key].isoformat()
  
  return jsonify({'success': True, 'data': vulns})


@app.route('/rules')
def list_rules():
  """List security rules."""
  global engine
  return jsonify({
    'success': True,
    'data': engine.rules
  })


@app.route('/stats')
def get_stats():
  """Get vulnerability statistics."""
  global postgres
  
  with postgres.conn.cursor(cursor_factory=RealDictCursor) as cur:
    cur.execute("""
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open,
        SUM(CASE WHEN status = 'FIXED' THEN 1 ELSE 0 END) as fixed
      FROM detected_vulns
    """)
    stats = cur.fetchone()
  
  return jsonify({'success': True, 'data': dict(stats) if stats else {}})


if __name__ == '__main__':
  import threading
  
  init_services()
  
  # Start RabbitMQ consumer in a separate thread
  consumer_thread = threading.Thread(target=start_consumer, daemon=True)
  consumer_thread.start()
  
  # Run Flask app
  port = int(os.getenv('PORT', 5000))
  app.run(host='0.0.0.0', port=port, debug=False)
