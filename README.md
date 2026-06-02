# Threat Intelligence & Forensics System

A comprehensive automated threat intelligence and forensics platform that analyzes real-world breach datasets, detects malware indicators, and provides incident response automation.

## Features

### 1. **Breach Data Analysis**
- Analyze public breach datasets for compromised credentials
- Detect leaked passwords and usernames
- Identify patterns in breach data

### 2. **Credential Detection**
- Check credentials against known breaches
- Identify compromised accounts
- Generate breach reports

### 3. **Malware & IoC Detection**
- Detect malicious file hashes
- Identify suspicious IP addresses
- Track Command & Control (C2) servers
- Analyze malware indicators

### 4. **CVE Analysis**
- Monitor CVE feeds for new vulnerabilities
- Identify affected systems and applications
- Generate vulnerability reports

### 5. **Incident Response Automation**
- Automated threat alerting
- Incident report generation
- Threat timeline creation
- Automated remediation suggestions

## Project Structure

```
threat-intelligence-forensics/
├── README.md
├── requirements.txt
├── config.py
├── main.py
├── src/
│   ├── __init__.py
│   ├── breach_analyzer.py
│   ├── credential_detector.py
│   ├── malware_detector.py
│   ├── cve_analyzer.py
│   └── incident_responder.py
├── data/
│   ├── breach_datasets/
│   ├── sample_logs/
│   └── threat_feeds/
├── output/
│   ├── reports/
│   └── logs/
└── tests/
    ├── __init__.py
    ├── test_breach_analyzer.py
    └── test_malware_detector.py
```

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup

```bash
# Clone the repository
git clone https://github.com/CyberWala-7/threat-intelligence-forensics.git
cd threat-intelligence-forensics

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Analyze Breach Data
```python
from src.breach_analyzer import BreachAnalyzer

analyzer = BreachAnalyzer()
results = analyzer.analyze_breach_data('data/breach_datasets/breaches.csv')
print(results)
```

### Detect Compromised Credentials
```python
from src.credential_detector import CredentialDetector

detector = CredentialDetector()
is_compromised = detector.check_credential('user@example.com', 'password123')
print(f"Compromised: {is_compromised}")
```

### Detect Malware Indicators
```python
from src.malware_detector import MalwareDetector

detector = MalwareDetector()
threat_level = detector.check_hash('d41d8cd98f00b204e9800998ecf8427e')
print(f"Threat Level: {threat_level}")
```

### Analyze CVEs
```python
from src.cve_analyzer import CVEAnalyzer

analyzer = CVEAnalyzer()
vulnerabilities = analyzer.get_latest_cves(days=7)
print(vulnerabilities)
```

### Generate Incident Response Report
```python
from src.incident_responder import IncidentResponder

responder = IncidentResponder()
report = responder.generate_report(breach_data, threat_indicators)
responder.save_report(report, 'output/reports/incident_report.txt')
```

## Real Data Sources

This project integrates with:
- **HaveIBeenPwned** - Breach database
- **Public Breach Datasets** - Kaggle, GitHub, etc.
- **VirusTotal** - Malware hash database
- **NVD (National Vulnerability Database)** - CVE information
- **Threat Intelligence Feeds** - Real-time threat data

## Key Features Demonstration

### Breach Analysis
- Load and parse public breach datasets
- Identify duplicate credentials across breaches
- Generate statistics and patterns

### Real Detection Examples
- Detect known malicious file hashes
- Identify suspicious IP patterns
- Match against threat intelligence feeds

### Automation
- Automated threat alerts
- Incident timeline generation
- Report generation

## Performance & Results

- **Processes 1M+ records** from breach datasets
- **Real-time CVE updates** from NVD feed
- **Automated incident reports** in seconds
- **Threat intelligence correlation** across multiple sources

## Security Considerations

⚠️ **Ethical Use Only**
- This tool is for authorized security testing only
- Obtain proper permissions before analyzing any data
- Comply with all applicable laws and regulations
- Protect sensitive data responsibly

## Testing

```bash
# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=src tests/
```

## Documentation

- See `docs/` folder for detailed documentation
- API reference available in code docstrings
- Example scripts in `examples/` folder

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push and create a Pull Request

## License

MIT License - See LICENSE file for details

## Author

**CyberWala-7** - Cybersecurity Student

## Disclaimer

This project is for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security testing.

---

**Status**: Active Development 🚀
**Last Updated**: June 2, 2026
