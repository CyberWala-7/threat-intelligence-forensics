# Threat Intelligence & Forensics System

## Quick Start

This guide will get you started analyzing threats in 5 minutes.

### 1. Install

```bash
git clone https://github.com/CyberWala-7/threat-intelligence-forensics.git
cd threat-intelligence-forensics
pip install -r requirements.txt
cp .env.example .env
```

### 2. Run Demo

```bash
python main.py
```

### 3. Analyze Breaches

```python
from main import ThreatIntelligenceSystem

system = ThreatIntelligenceSystem()

# Analyze breach data
results = system.analyze_breach_dataset('data/breach_datasets/breaches.csv')
print(results)

# Check credentials
cred_result = system.check_compromised_credentials('user@example.com', 'password')
print(cred_result)

# Detect malware
malware = system.detect_malware('d41d8cd98f00b204e9800998ecf8427e')
print(malware)

# Generate report
report = system.generate_comprehensive_report('output/reports/report.json')
```

## Features

✅ **Real Breach Analysis** - Analyze public breach datasets  
✅ **Credential Detection** - Check against HaveIBeenPwned  
✅ **Malware Detection** - Scan hashes with VirusTotal  
✅ **CVE Monitoring** - Track latest vulnerabilities  
✅ **Incident Response** - Automated threat reporting  

## Key Capabilities

### 1. Breach Data Analysis
- Processes 1M+ records from breach datasets
- Identifies duplicate credentials
- Analyzes password patterns
- Detects compromised email domains

### 2. Real-Time Detection
- Checks against live HaveIBeenPwned API
- VirusTotal malware hash lookup
- IP reputation checking
- Domain threat analysis

### 3. CVE Tracking
- Monitors NVD for latest vulnerabilities
- Filters by severity (LOW, MEDIUM, HIGH, CRITICAL)
- Tracks affected products
- Identifies critical patches needed

### 4. Automation
- Automated incident creation
- Alert generation
- Timeline tracking
- Remediation suggestions

## Real-World Detection Examples

### Example 1: Detect Compromised Password
```python
detector = CredentialDetector()
result = detector.check_credential('user@example.com', 'password123')

if result['is_compromised']:
    print(f"Password found in {len(result['sources'])} breaches!")
    print(f"Risk Score: {result['risk_score']}/100")
```

### Example 2: Malware Detection
```python
malware = MalwareDetector()
result = malware.check_hash('d41d8cd98f00b204e9800998ecf8427e')

if result['is_malicious']:
    print(f"⚠️  Malicious file detected!")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Detected by: {result['detections']}")
```

### Example 3: Vulnerability Check
```python
cve = CVEAnalyzer()
latest = cve.get_latest_cves(days=7, severity='CRITICAL')

for cve_item in latest:
    print(f"🔴 {cve_item['cve_id']}: {cve_item['description']}")
    print(f"   CVSS Score: {cve_item['cvss_score']}")
```

## Project Structure

```
src/
  ├── breach_analyzer.py       # Analyze public breaches
  ├── credential_detector.py   # Check compromised credentials
  ├── malware_detector.py      # Detect malware/IoCs
  ├── cve_analyzer.py          # Monitor CVEs
  └── incident_responder.py    # Automate incident response

tests/
  └── test_modules.py          # Comprehensive test suite

docs/
  ├── INSTALLATION.md          # Setup guide
  ├── API_REFERENCE.md         # Full API docs
  └── USAGE.md                 # Usage examples

data/
  ├── breach_datasets/         # Add your breach CSVs here
  ├── sample_logs/             # Log files to analyze
  └── threat_feeds/            # Threat intelligence feeds

output/
  ├── reports/                 # Generated reports (JSON)
  └── logs/                    # Application logs
```

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src

# Run specific test
python -m pytest tests/test_modules.py::TestBreachAnalyzer -v
```

## Real Data Sources

This project integrates with:

- **HaveIBeenPwned API** - Breach database (325M+ accounts)
- **VirusTotal API** - Malware hashes (75M+ files)
- **NVD API** - CVEs (100K+ vulnerabilities)
- **AbuseIPDB** - IP reputation
- **Public Datasets** - Kaggle, GitHub breaches

## Performance Metrics

- Processes **1M+ breach records** in seconds
- Queries **live threat intelligence APIs**
- Generates **incident reports in real-time**
- Correlates data across **multiple sources**

## Important Notes

⚠️ **Ethical Use Only**
- For authorized security testing only
- Obtain proper permissions before testing
- Comply with all laws and regulations
- Protect sensitive data responsibly

## License

MIT License - See LICENSE file

## Author

**CyberWala-7** - Cybersecurity Student

---

**Ready to use!** 🚀 See docs/ for detailed guides.