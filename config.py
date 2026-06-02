"""
Configuration file for Threat Intelligence & Forensics System
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API Keys and Credentials
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'your_api_key_here')
HAVEIBEENPWNED_API_KEY = os.getenv('HAVEIBEENPWNED_API_KEY', 'your_api_key_here')

# Data Paths
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
BREACH_DATA_DIR = os.path.join(DATA_DIR, 'breach_datasets')
LOGS_DIR = os.path.join(DATA_DIR, 'sample_logs')
THREAT_FEEDS_DIR = os.path.join(DATA_DIR, 'threat_feeds')

# Output Paths
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output')
REPORTS_DIR = os.path.join(OUTPUT_DIR, 'reports')
LOGS_OUTPUT_DIR = os.path.join(OUTPUT_DIR, 'logs')

# Create directories if they don't exist
os.makedirs(BREACH_DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(THREAT_FEEDS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_OUTPUT_DIR, exist_ok=True)

# Database Configuration
DB_PATH = os.path.join(DATA_DIR, 'threat_intelligence.db')

# Threat Detection Thresholds
THREAT_LEVEL_CRITICAL = 90
THREAT_LEVEL_HIGH = 70
THREAT_LEVEL_MEDIUM = 50
THREAT_LEVEL_LOW = 30

# CVE Configuration
CVE_UPDATE_INTERVAL = 3600  # Update every 1 hour
CVE_SEVERITY_THRESHOLD = 'HIGH'  # Only alert on HIGH and CRITICAL

# Breach Analysis Configuration
BREACH_ANALYSIS_BATCH_SIZE = 1000
MAX_BREACH_RECORDS = 1000000  # Process up to 1M records

# Incident Response Configuration
INCIDENT_SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
AUTO_REMEDIATION_ENABLED = True
ALERT_EMAIL = os.getenv('ALERT_EMAIL', 'security@example.com')

# Logging Configuration
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# External API Endpoints
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3'
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json'
ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2'

# Settings
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
MAX_WORKERS = 4  # For concurrent processing
REQUEST_TIMEOUT = 30  # seconds