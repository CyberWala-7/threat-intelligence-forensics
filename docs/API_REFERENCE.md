# API Reference

## BreachAnalyzer

### Methods

#### `load_breach_data(file_path)`
Load breach dataset from CSV file.

**Parameters:**
- `file_path` (str): Path to CSV file

**Returns:** pd.DataFrame with loaded data

#### `analyze_breach_data(file_path)`
Perform comprehensive breach analysis.

**Parameters:**
- `file_path` (str): Path to CSV file

**Returns:** Dictionary with:
- `total_records`: Number of records analyzed
- `statistics`: Data statistics
- `patterns`: Identified patterns
- `duplicates`: Duplicate findings
- `breach_sources`: Breach source analysis

#### `check_credential_in_breach(email, password=None)`
Check if credential exists in breach data.

**Parameters:**
- `email` (str): Email to check
- `password` (str, optional): Password to check

**Returns:** Dictionary with match results

---

## CredentialDetector

### Methods

#### `check_credential(email, password)`
Check if credential is compromised.

**Parameters:**
- `email` (str): Email address
- `password` (str): Password

**Returns:** Dictionary with:
- `is_compromised`: Boolean
- `risk_level`: Risk assessment
- `risk_score`: 0-100 score
- `sources`: Detection sources

#### `check_credentials_batch(credentials_list)`
Check multiple credentials at once.

**Parameters:**
- `credentials_list` (list): List of `{'email': str, 'password': str}`

**Returns:** List of detection results

#### `generate_report(output_file=None)`
Generate detection report.

**Parameters:**
- `output_file` (str, optional): Save location

**Returns:** Report dictionary

---

## MalwareDetector

### Methods

#### `check_hash(file_hash, hash_type='md5')`
Check file hash against malware databases.

**Parameters:**
- `file_hash` (str): Hash value
- `hash_type` (str): Hash type (md5, sha1, sha256)

**Returns:** Dictionary with:
- `is_malicious`: Boolean
- `threat_level`: Threat classification
- `threat_score`: 0-100 score
- `detections`: Detection details

#### `check_ip_reputation(ip_address)`
Check IP address reputation.

**Parameters:**
- `ip_address` (str): IP address

**Returns:** IP reputation result

#### `check_domain(domain)`
Check domain for malicious activity.

**Parameters:**
- `domain` (str): Domain name

**Returns:** Domain reputation result

#### `scan_log_file(log_file_path)`
Scan log file for malware indicators.

**Parameters:**
- `log_file_path` (str): Path to log file

**Returns:** Scan results with indicators found

---

## CVEAnalyzer

### Methods

#### `get_latest_cves(days=7, severity='HIGH')`
Get latest CVEs from NVD.

**Parameters:**
- `days` (int): Days to look back
- `severity` (str): Minimum severity

**Returns:** List of CVE dictionaries

#### `check_cve(cve_id)`
Get detailed CVE information.

**Parameters:**
- `cve_id` (str): CVE ID (e.g., CVE-2021-44228)

**Returns:** CVE details dictionary

#### `check_product_vulnerabilities(product_name, version=None)`
Check vulnerabilities for product.

**Parameters:**
- `product_name` (str): Product name
- `version` (str, optional): Product version

**Returns:** List of applicable CVEs

---

## IncidentResponder

### Methods

#### `create_incident(threat_data, breach_data=None, cve_data=None)`
Create incident from threat data.

**Parameters:**
- `threat_data` (dict): Threat information
- `breach_data` (dict, optional): Breach info
- `cve_data` (dict, optional): CVE info

**Returns:** Incident dictionary with:
- `incident_id`: Unique ID
- `severity`: Severity level
- `timeline`: Event timeline
- `remediation_steps`: Suggested fixes

#### `generate_alert(incident_id, message, severity='HIGH')`
Generate alert for incident.

**Parameters:**
- `incident_id` (str): Incident ID
- `message` (str): Alert message
- `severity` (str): Severity level

**Returns:** Alert dictionary

#### `generate_incident_report(incident_id, output_file=None)`
Generate incident report.

**Parameters:**
- `incident_id` (str): Incident ID
- `output_file` (str, optional): Save location

**Returns:** Report dictionary

#### `close_incident(incident_id, resolution_notes)`
Close incident.

**Parameters:**
- `incident_id` (str): Incident ID
- `resolution_notes` (str): Resolution details

**Returns:** Updated incident

---

## ThreatIntelligenceSystem (Main)

### Methods

#### `analyze_breach_dataset(file_path)`
Analyze breach dataset.

#### `check_compromised_credentials(email, password)`
Check compromised credentials.

#### `detect_malware(file_hash, hash_type='md5')`
Detect malware.

#### `check_vulnerabilities(product_name, version=None)`
Check product vulnerabilities.

#### `generate_comprehensive_report(output_file=None)`
Generate comprehensive system report.