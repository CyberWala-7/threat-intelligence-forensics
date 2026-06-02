# Threat Intelligence & Forensics System - Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

## Step-by-Step Installation

### 1. Clone the Repository

```bash
git clone https://github.com/CyberWala-7/threat-intelligence-forensics.git
cd threat-intelligence-forensics
```

### 2. Create Virtual Environment

**On Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Keys

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```
VIRUSTOTAL_API_KEY=your_virustotal_key
HAVEIBEENPWNED_API_KEY=your_hibp_key
ALERT_EMAIL=your_email@example.com
DEBUG_MODE=False
LOG_LEVEL=INFO
```

### 5. Verify Installation

```bash
python main.py
```

You should see the demo running successfully!

## Getting API Keys

### VirusTotal API
1. Go to https://www.virustotal.com/gui/home/upload
2. Sign up for free account
3. Get API key from settings

### HaveIBeenPwned API
1. Go to https://haveibeenpwned.com/API/v3
2. Sign up for API access
3. Get your API key

## Usage Examples

### Basic Usage

```python
from src.breach_analyzer import BreachAnalyzer
from src.credential_detector import CredentialDetector
from src.malware_detector import MalwareDetector

# Analyze breaches
breacher = BreachAnalyzer()
results = breacher.analyze_breach_data('data/breach.csv')

# Check credentials
detector = CredentialDetector()
result = detector.check_credential('user@example.com', 'password')

# Detect malware
malware = MalwareDetector()
result = malware.check_hash('abc123def456')
```

## Project Structure

```
threat-intelligence-forensics/
├── src/
│   ├── breach_analyzer.py      # Breach dataset analysis
│   ├── credential_detector.py  # Credential validation
│   ├── malware_detector.py     # Malware/IoC detection
│   ├── cve_analyzer.py         # CVE monitoring
│   └── incident_responder.py   # Incident automation
├── data/
│   ├── breach_datasets/        # Breach CSV files
│   ├── sample_logs/            # Log files for analysis
│   └── threat_feeds/           # Threat intelligence feeds
├── output/
│   ├── reports/                # Generated reports
│   └── logs/                   # Application logs
├── tests/
│   └── test_modules.py         # Test suite
├── main.py                     # Demo application
├── config.py                   # Configuration
└── requirements.txt            # Dependencies
```

## Troubleshooting

### ModuleNotFoundError
```bash
# Make sure you activated venv and installed requirements
source venv/bin/activate
pip install -r requirements.txt
```

### API Key Issues
- Verify API keys are correct in `.env`
- Check API rate limits
- Ensure API account is active

### Permission Errors
```bash
# On Linux/macOS
chmod +x main.py
```

## Support

For issues, check the GitHub Issues section or contact the developer.

## Security Notes

⚠️ **Never commit `.env` file with real API keys**

- Add `.env` to `.gitignore`
- Use environment variable substitution in CI/CD
- Rotate API keys regularly