import os
import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

import numpy as np
import pandas as pd
import pika
import psycopg2
from psycopg2.extras import RealDictCursor
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
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
logger = logging.getLogger('AnomalyDetector')

# ===========================================
# CONFIGURATION
# ===========================================
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/safeops')
TIMESCALEDB_URI = os.getenv('TIMESCALEDB_URI', 'postgresql://safeops:safeops_secret@localhost:5433/safeops_metrics')
RABBITMQ_URL = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672/')
MODEL_PATH = os.getenv('MODEL_PATH', '/app/models')
ANOMALY_THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', '-0.3'))
MIN_SAMPLES_FOR_TRAINING = int(os.getenv('MIN_SAMPLES_FOR_TRAINING', '50'))

# ===========================================
# DATA CLASSES
# ===========================================
@dataclass
class PipelineMetric:
    pipeline_id: str
    job_name: Optional[str]
    job_duration_seconds: float
    step_count: int
    output_size_bytes: int
    artifact_count: int
    exit_code: int
    source: str
    timestamp: datetime

@dataclass
class Anomaly:
    anomaly_id: str
    pipeline_id: str
    anomaly_type: str
    severity: str
    title: str
    description: str
    metric_name: str
    expected_value: float
    actual_value: float
    deviation_score: float
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


class TimescaleManager:
    def __init__(self):
        self.conn = psycopg2.connect(TIMESCALEDB_URI)
        self.conn.autocommit = True
        logger.info("Connected to TimescaleDB")
    
    def save_metric(self, metric: PipelineMetric):
        """Save pipeline metric to TimescaleDB."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO pipeline_metrics (
                    time, pipeline_id, job_name, job_duration_seconds,
                    step_count, output_size_bytes, artifact_count,
                    exit_code, source
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                metric.timestamp, metric.pipeline_id, metric.job_name,
                metric.job_duration_seconds, metric.step_count,
                metric.output_size_bytes, metric.artifact_count,
                metric.exit_code, metric.source
            ))
    
    def get_historical_metrics(self, pipeline_id: str, days: int = 30) -> pd.DataFrame:
        """Get historical metrics for training."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    time,
                    job_duration_seconds,
                    step_count,
                    output_size_bytes,
                    artifact_count,
                    exit_code
                FROM pipeline_metrics
                WHERE pipeline_id = %s
                    AND time > NOW() - INTERVAL '%s days'
                ORDER BY time DESC
            """, (pipeline_id, days))
            rows = cur.fetchall()
        
        if not rows:
            return pd.DataFrame()
        
        return pd.DataFrame(rows)
    
    def get_all_metrics(self, days: int = 30, limit: int = 10000) -> pd.DataFrame:
        """Get all metrics for model training."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    pipeline_id,
                    job_duration_seconds,
                    step_count,
                    output_size_bytes,
                    artifact_count,
                    exit_code
                FROM pipeline_metrics
                WHERE time > NOW() - INTERVAL '%s days'
                ORDER BY time DESC
                LIMIT %s
            """, (days, limit))
            rows = cur.fetchall()
        
        if not rows:
            return pd.DataFrame()
        
        return pd.DataFrame(rows)
    
    def save_anomaly(self, anomaly: Anomaly):
        """Save detected anomaly."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO anomalies (
                    id, pipeline_id, detected_at, anomaly_type, severity,
                    title, description, metric_name, expected_value,
                    actual_value, deviation_score
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                anomaly.anomaly_id, anomaly.pipeline_id, anomaly.detected_at,
                anomaly.anomaly_type, anomaly.severity, anomaly.title,
                anomaly.description, anomaly.metric_name, anomaly.expected_value,
                anomaly.actual_value, anomaly.deviation_score
            ))
    
    def get_anomalies(self, pipeline_id: str = None, limit: int = 50) -> List[Dict]:
        """Get detected anomalies."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            if pipeline_id:
                cur.execute("""
                    SELECT * FROM anomalies
                    WHERE pipeline_id = %s
                    ORDER BY detected_at DESC
                    LIMIT %s
                """, (pipeline_id, limit))
            else:
                cur.execute("""
                    SELECT * FROM anomalies
                    ORDER BY detected_at DESC
                    LIMIT %s
                """, (limit,))
            return cur.fetchall()
    
    def update_baseline_stats(self, pipeline_id: str):
        """Update baseline statistics for a pipeline."""
        with self.conn.cursor() as cur:
            # Calculate and store baseline statistics
            cur.execute("""
                INSERT INTO baseline_stats (
                    pipeline_id, metric_name, sample_count,
                    mean_value, std_dev, min_value, max_value,
                    p50_value, p90_value, p99_value
                )
                SELECT 
                    %s,
                    'job_duration_seconds',
                    COUNT(*),
                    AVG(job_duration_seconds),
                    STDDEV(job_duration_seconds),
                    MIN(job_duration_seconds),
                    MAX(job_duration_seconds),
                    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY job_duration_seconds),
                    PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY job_duration_seconds),
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY job_duration_seconds)
                FROM pipeline_metrics
                WHERE pipeline_id = %s AND time > NOW() - INTERVAL '30 days'
                ON CONFLICT (pipeline_id, metric_name) DO UPDATE SET
                    calculated_at = CURRENT_TIMESTAMP,
                    sample_count = EXCLUDED.sample_count,
                    mean_value = EXCLUDED.mean_value,
                    std_dev = EXCLUDED.std_dev,
                    min_value = EXCLUDED.min_value,
                    max_value = EXCLUDED.max_value,
                    p50_value = EXCLUDED.p50_value,
                    p90_value = EXCLUDED.p90_value,
                    p99_value = EXCLUDED.p99_value
            """, (pipeline_id, pipeline_id))
    
    def get_baseline_stats(self, pipeline_id: str) -> Dict:
        """Get baseline statistics for a pipeline."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM baseline_stats
                WHERE pipeline_id = %s
            """, (pipeline_id,))
            rows = cur.fetchall()
            return {row['metric_name']: dict(row) for row in rows}

# ===========================================
# ANOMALY DETECTION ENGINE
# ===========================================
class AnomalyDetectionEngine:
    """ML-based anomaly detection using Isolation Forest."""
    
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self.feature_columns = [
            'job_duration_seconds',
            'step_count',
            'output_size_bytes'
        ]
        # Baseline means (Job duration ~300s, Step count ~15, Output ~10MB)
        self.means = [300.0, 15.0, 10 * 1024 * 1024.0] 
        self._load_or_create_model()
    
    def _load_or_create_model(self):
        """Load existing model or create new one."""
        try:
            # Try loading the specific new model file first
            specific_model_path = os.path.join(self.model_path, 'isolation_forest_model.pkl')
            
            if os.path.exists(specific_model_path):
                self.model = joblib.load(specific_model_path)
                logger.info(f"Loaded specific model from {specific_model_path}")
            else:
                # Fallback to generic name
                path = os.path.join(self.model_path, 'isolation_forest.joblib')
                if os.path.exists(path):
                    self.model = joblib.load(path)
                    logger.info(f"Loaded existing model from {path}")
                
            if not self.model:
                logger.warning("No model found, creating new untrained model")
                self.model = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
                
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.model = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
    
    def _generate_synthetic_training_data(self) -> pd.DataFrame:
        """Generate realistic synthetic CI/CD pipeline metrics for training."""
        np.random.seed(42)
        n_samples = 500
        
        # Define realistic CI/CD pipeline patterns
        # Pattern 1: Quick unit test jobs (60% of runs)
        quick_jobs = {
            'job_duration_seconds': np.random.normal(45, 10, int(n_samples * 0.6)),
            'step_count': np.random.choice([5, 6, 7, 8], int(n_samples * 0.6)),
            'output_size_bytes': np.random.normal(15000, 3000, int(n_samples * 0.6)),
            'artifact_count': np.random.choice([0, 1, 1, 1], int(n_samples * 0.6))
        }
        
        # Pattern 2: Build and deploy jobs (25% of runs)
        build_jobs = {
            'job_duration_seconds': np.random.normal(180, 40, int(n_samples * 0.25)),
            'step_count': np.random.choice([12, 14, 15, 16], int(n_samples * 0.25)),
            'output_size_bytes': np.random.normal(85000, 15000, int(n_samples * 0.25)),
            'artifact_count': np.random.choice([2, 3, 3, 4], int(n_samples * 0.25))
        }
        
        # Pattern 3: Integration test jobs (15% of runs)
        integration_jobs = {
            'job_duration_seconds': np.random.normal(300, 60, int(n_samples * 0.15)),
            'step_count': np.random.choice([18, 20, 22, 25], int(n_samples * 0.15)),
            'output_size_bytes': np.random.normal(120000, 25000, int(n_samples * 0.15)),
            'artifact_count': np.random.choice([3, 4, 5, 5], int(n_samples * 0.15))
        }
        
        # Combine all patterns
        data = {
            'job_duration_seconds': np.concatenate([
                quick_jobs['job_duration_seconds'],
                build_jobs['job_duration_seconds'],
                integration_jobs['job_duration_seconds']
            ]),
            'step_count': np.concatenate([
                quick_jobs['step_count'],
                build_jobs['step_count'],
                integration_jobs['step_count']
            ]),
            'output_size_bytes': np.concatenate([
                quick_jobs['output_size_bytes'],
                build_jobs['output_size_bytes'],
                integration_jobs['output_size_bytes']
            ]),
            'artifact_count': np.concatenate([
                quick_jobs['artifact_count'],
                build_jobs['artifact_count'],
                integration_jobs['artifact_count']
            ])
        }
        
        df = pd.DataFrame(data)
        
        # Ensure no negative values
        df['job_duration_seconds'] = df['job_duration_seconds'].clip(lower=5)
        df['output_size_bytes'] = df['output_size_bytes'].clip(lower=1000)
        
        logger.info(f"Generated {len(df)} synthetic training samples:")
        logger.info(f"   - Duration: mean={df['job_duration_seconds'].mean():.1f}s, std={df['job_duration_seconds'].std():.1f}s")
        logger.info(f"   - Steps: mean={df['step_count'].mean():.1f}, range=[{df['step_count'].min()}-{df['step_count'].max()}]")
        logger.info(f"   - Output: mean={df['output_size_bytes'].mean()/1000:.1f}KB")
        
        return df
    
    def train(self, df: pd.DataFrame) -> bool:
        """Train the model on historical data."""
        if df.empty or len(df) < MIN_SAMPLES_FOR_TRAINING:
            logger.warning(f"Insufficient data for training: {len(df)} samples")
            return False
        
        try:
            # Prepare features (3 features matching the new model)
            X = df[['job_duration_seconds', 'step_count', 'output_size_bytes']].fillna(0).values
            
            # Train model (no scaling for this model pipeline)
            self.model.fit(X)
            
            # Update means for reporting
            self.means = [
                df['job_duration_seconds'].mean(),
                df['step_count'].mean(),
                df['output_size_bytes'].mean()
            ]
            
            # Save model
            os.makedirs(self.model_path, exist_ok=True)
            joblib.dump(self.model, os.path.join(self.model_path, 'isolation_forest_model.pkl'))
            
            logger.info(f"Model trained on {len(df)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return False
    
    def detect(self, metric: PipelineMetric) -> Optional[List[Anomaly]]:
        """Detect if a metric is anomalous using hybrid approach (ML + rules).
        Returns a list of anomalies if any are detected."""
        try:
            # Prepare feature vector (3 features, NO SCALING as per new model training)
            features = np.array([[
                metric.job_duration_seconds or 0,
                metric.step_count or 0,
                metric.output_size_bytes or 0
            ]])
            
            # Get ML anomaly score (-1 for anomaly, 1 for normal)
            prediction = self.model.predict(features)[0]
            score = self.model.decision_function(features)[0]
            
            # Collect all detected anomalies
            anomalies = []
            
            # Rule 1: Duration > 600s (10 min) is unusual for most quick jobs
            if metric.job_duration_seconds > 600:
                severity = 'CRITICAL' if metric.job_duration_seconds > 1800 else ('HIGH' if metric.job_duration_seconds > 900 else 'MEDIUM')
                anomalies.append({
                    'type': 'UNUSUAL_DURATION',
                    'reason': f"Job took {metric.job_duration_seconds:.0f}s (>{600}s threshold)",
                    'severity': severity,
                    'actual': metric.job_duration_seconds,
                    'expected': self.means[0]
                })
            
            # Rule 2: High step count (> 15 steps indicates complex pipeline)
            if metric.step_count > 15:
                severity = 'CRITICAL' if metric.step_count > 25 else ('HIGH' if metric.step_count > 20 else 'MEDIUM')
                anomalies.append({
                    'type': 'UNUSUAL_STEP_COUNT',
                    'reason': f"Job has {metric.step_count} steps (>15 threshold)",
                    'severity': severity,
                    'actual': metric.step_count,
                    'expected': self.means[1]
                })
            
            # Rule 3: Large output (> 20KB indicates verbose/spammy logs)
            if metric.output_size_bytes > 20000:
                severity = 'HIGH' if metric.output_size_bytes > 100000 else 'MEDIUM'
                anomalies.append({
                    'type': 'LARGE_OUTPUT',
                    'reason': f"Output size is {metric.output_size_bytes/1000:.1f}KB (>20KB threshold)",
                    'severity': severity,
                    'actual': metric.output_size_bytes,
                    'expected': self.means[2]
                })
            
            # Rule 4: ML model says anomaly (only if no rule-based anomalies)
            if prediction == -1 and score < ANOMALY_THRESHOLD and not anomalies:
                anomalies.append({
                    'type': 'ML_DETECTED',
                    'reason': f"ML model anomaly score: {score:.4f}",
                    'severity': self._determine_severity(score),
                    'actual': metric.job_duration_seconds,
                    'expected': self.means[0]
                })
            
            # Create Anomaly objects for each detected issue
            result = []
            for a in anomalies:
                logger.warning(f"ANOMALY DETECTED: {a['type']} - {a['reason']}")
                result.append(Anomaly(
                    anomaly_id=str(uuid.uuid4()),
                    pipeline_id=metric.pipeline_id,
                    anomaly_type=a['type'],
                    severity=a['severity'],
                    title=f"Anomalous {a['type'].replace('_', ' ').title()} Detected",
                    description=f"{a['reason']}\n\nThis behavior significantly deviates from normal patterns.",
                    metric_name=a['type'].lower(),
                    expected_value=a['expected'],
                    actual_value=a['actual'],
                    deviation_score=abs(score) if score else 0.5,
                    detected_at=datetime.utcnow().isoformat()
                ))
            
            return result if result else None
            
        except Exception as e:
            logger.error(f"Detection failed: {e}")
            return None
    
    def _identify_anomaly_type(self, metric: PipelineMetric, scaled_features: np.ndarray) -> Tuple:
        """Identify which metric is most anomalous."""
        # Find the feature with the highest absolute scaled value
        feature_names = ['DURATION', 'PATTERN', 'RESOURCE', 'ARTIFACT']
        feature_values = [
            ('job_duration_seconds', metric.job_duration_seconds or 0),
            ('step_count', metric.step_count or 0),
            ('output_size_bytes', metric.output_size_bytes or 0),
            ('artifact_count', metric.artifact_count or 0)
        ]
        
        max_idx = np.argmax(np.abs(scaled_features))
        anomaly_type = feature_names[max_idx]
        metric_name, actual = feature_values[max_idx]
        
        # Calculate expected value (mean from scaler)
        expected = self.scaler.mean_[max_idx]
        
        return anomaly_type, metric_name, expected, actual
    
    def _determine_severity(self, score: float) -> str:
        """Determine anomaly severity based on score."""
        if score < -0.7:
            return 'CRITICAL'
        elif score < -0.5:
            return 'HIGH'
        elif score < -0.3:
            return 'MEDIUM'
        return 'LOW'
    
    def _generate_description(self, anomaly_type: str, expected: float, actual: float, score: float) -> str:
        """Generate anomaly description."""
        deviation = ((actual - expected) / expected * 100) if expected != 0 else 0
        
        return f"""Anomaly detected in pipeline execution.
Type: {anomaly_type}
Expected Value: {expected:.2f}
Actual Value: {actual:.2f}
Deviation: {deviation:.1f}%
Anomaly Score: {score:.4f}

This behavior significantly deviates from historical patterns and warrants investigation."""

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
                exchange='logs_parsed',
                exchange_type='fanout',
                durable=True
            )
            
            self.channel.queue_declare(queue='anomaly_detector_queue', durable=True)
            self.channel.queue_bind(
                exchange='logs_parsed',
                queue='anomaly_detector_queue'
            )
            
            logger.info("Connected to RabbitMQ")
        except Exception as e:
            logger.error(f"RabbitMQ connection failed: {e}")
            raise

# ===========================================
# MAIN SERVICE
# ===========================================
app = Flask(__name__)
mongo = None
timescale = None
mq = None
engine = None


def init_services():
    """Initialize all service connections."""
    global mongo, timescale, mq, engine
    mongo = MongoManager()
    timescale = TimescaleManager()
    mq = MessageQueue()
    engine = AnomalyDetectionEngine(MODEL_PATH)


def extract_metrics(parsed_event: Dict) -> PipelineMetric:
    """Extract metrics from parsed event."""
    details = parsed_event.get('details', {})
    
    # Use jobs_detected for step count (steps_detected is often empty)
    jobs = details.get('jobs_detected', [])
    steps = details.get('steps_detected', [])
    step_count = len(jobs) if jobs else len(steps)
    
    return PipelineMetric(
        pipeline_id=parsed_event.get('pipeline_id', 'unknown'),
        job_name=parsed_event.get('job_name'),
        job_duration_seconds=parsed_event.get('duration_seconds') or 0,
        step_count=step_count,
        output_size_bytes=details.get('character_count', 0),
        artifact_count=len(parsed_event.get('artifacts', [])),
        exit_code=0 if parsed_event.get('status') == 'COMPLETED' else 1,
        source=parsed_event.get('source', 'Unknown'),
        timestamp=datetime.utcnow()
    )


def process_message(ch, method, properties, body):
    """Process incoming parsed log message."""
    global mongo, timescale, engine
    
    try:
        message = json.loads(body)
        event_id = message.get('event_id')
        
        logger.info(f"Processing event for anomaly detection: {event_id}")
        
        # Fetch full parsed event from MongoDB
        parsed_event = mongo.get_parsed_event(event_id)
        if not parsed_event:
            logger.warning(f"Event {event_id} not found in MongoDB")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return
        
        # Extract metrics
        metric = extract_metrics(parsed_event)
        
        # Save metrics to TimescaleDB
        timescale.save_metric(metric)
        
        # Detect anomalies (returns list of anomalies)
        anomalies = engine.detect(metric)
        
        if anomalies:
            for anomaly in anomalies:
                timescale.save_anomaly(anomaly)
                logger.warning(f"Anomaly detected: {anomaly.title} ({anomaly.severity})")
            logger.warning(f"Total anomalies detected: {len(anomalies)}")
        else:
            logger.info(f"No anomaly detected for event {event_id}")
        
        # Update baseline stats periodically
        # (In production, this would be a separate scheduled job)
        
        ch.basic_ack(delivery_tag=method.delivery_tag)
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)


def start_consumer():
    """Start consuming messages from RabbitMQ."""
    global mq
    
    logger.info("Starting AnomalyDetector consumer...")
    
    mq.channel.basic_qos(prefetch_count=1)
    mq.channel.basic_consume(
        queue='anomaly_detector_queue',
        on_message_callback=process_message
    )
    
    logger.info("AnomalyDetector consumer started. Waiting for messages...")
    mq.channel.start_consuming()


@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'anomaly-detector',
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/anomaly', methods=['POST'])
def detect_anomaly():
    """Manually check for anomalies in an event."""
    global mongo, timescale, engine
    
    try:
        data = request.json
        event_id = data.get('event_id')
        
        if not event_id:
            return jsonify({'success': False, 'error': 'event_id required'}), 400
        
        parsed_event = mongo.get_parsed_event(event_id)
        if not parsed_event:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
        
        metric = extract_metrics(parsed_event)
        anomalies = engine.detect(metric)
        
        if anomalies:
            for anomaly in anomalies:
                timescale.save_anomaly(anomaly)
            return jsonify({
                'success': True,
                'anomaly_detected': True,
                'count': len(anomalies),
                'data': [asdict(a) for a in anomalies]
            })
        
        return jsonify({
            'success': True,
            'anomaly_detected': False,
            'message': 'No anomaly detected'
        })
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/anomalies')
def list_anomalies():
    """List detected anomalies."""
    global timescale
    
    pipeline_id = request.args.get('pipeline_id')
    limit = int(request.args.get('limit', 50))
    
    anomalies = timescale.get_anomalies(pipeline_id, limit)
    
    for a in anomalies:
        for key in a:
            if isinstance(a[key], uuid.UUID):
                a[key] = str(a[key])
            elif hasattr(a[key], 'isoformat'):
                a[key] = a[key].isoformat()
    
    return jsonify({'success': True, 'data': anomalies})


@app.route('/train', methods=['POST'])
def train_model():
    """Trigger model training."""
    global timescale, engine
    
    try:
        days = int(request.args.get('days', 30))
        df = timescale.get_all_metrics(days)
        
        success = engine.train(df)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Model trained on {len(df)} samples'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Training failed - insufficient data'
            }), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/stats')
def get_stats():
    """Get anomaly statistics."""
    global timescale
    
    with timescale.conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
                COUNT(DISTINCT pipeline_id) as affected_pipelines
            FROM anomalies
            WHERE detected_at > NOW() - INTERVAL '7 days'
        """)
        stats = cur.fetchone()
    
    return jsonify({'success': True, 'data': dict(stats) if stats else {}})


if __name__ == '__main__':
    import threading
    
    # Create models directory
    os.makedirs(MODEL_PATH, exist_ok=True)
    
    init_services()
    
    # Start RabbitMQ consumer in a separate thread
    consumer_thread = threading.Thread(target=start_consumer, daemon=True)
    consumer_thread.start()
    
    # Run Flask app
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
