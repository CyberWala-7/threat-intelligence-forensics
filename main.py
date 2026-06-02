"""
Main Application - Threat Intelligence & Forensics System
Demonstrates the complete threat analysis pipeline
"""

import logging
import json
from datetime import datetime
from src.breach_analyzer import BreachAnalyzer
from src.credential_detector import CredentialDetector
from src.malware_detector import MalwareDetector
from src.cve_analyzer import CVEAnalyzer
from src.incident_responder import IncidentResponder
import config

logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class ThreatIntelligenceSystem:
    """
    Main threat intelligence and forensics system
    """
    
    def __init__(self):
        self.breach_analyzer = BreachAnalyzer()
        self.credential_detector = CredentialDetector()
        self.malware_detector = MalwareDetector()
        self.cve_analyzer = CVEAnalyzer()
        self.incident_responder = IncidentResponder()
        logger.info("Threat Intelligence System initialized")
    
    def analyze_breach_dataset(self, file_path):
        """
        Analyze public breach dataset
        
        Args:
            file_path (str): Path to breach CSV file
            
        Returns:
            dict: Analysis results
        """
        logger.info(f"Starting breach analysis: {file_path}")
        results = self.breach_analyzer.analyze_breach_data(file_path)
        return results
    
    def check_compromised_credentials(self, email, password):
        """
        Check if credentials are compromised
        
        Args:
            email (str): Email address
            password (str): Password
            
        Returns:
            dict: Detection results
        """
        logger.info(f"Checking credentials for: {email}")
        result = self.credential_detector.check_credential(email, password)
        
        if result['is_compromised']:
            # Create incident for compromised credential
            incident = self.incident_responder.create_incident(
                threat_data=result,
                breach_data={'email': email}
            )
            logger.warning(f"Compromised credential detected: {incident['incident_id']}")
        
        return result
    
    def detect_malware(self, file_hash, hash_type='md5'):
        """
        Detect malware by file hash
        
        Args:
            file_hash (str): File hash
            hash_type (str): Hash type (md5, sha1, sha256)
            
        Returns:
            dict: Detection results
        """
        logger.info(f"Checking file hash: {file_hash}")
        result = self.malware_detector.check_hash(file_hash, hash_type)
        
        if result['is_malicious']:
            # Create incident for malware
            incident = self.incident_responder.create_incident(threat_data=result)
            logger.warning(f"Malware detected: {incident['incident_id']}")
        
        return result
    
    def check_vulnerabilities(self, product_name, version=None):
        """
        Check for vulnerabilities in product
        
        Args:
            product_name (str): Product name
            version (str, optional): Product version
            
        Returns:
            list: List of CVEs
        """
        logger.info(f"Checking vulnerabilities for: {product_name}")
        cves = self.cve_analyzer.check_product_vulnerabilities(product_name, version)
        return cves
    
    def get_latest_threats(self):
        """
        Get latest threats and vulnerabilities
        
        Returns:
            dict: Summary of latest threats
        """
        logger.info("Fetching latest threats")
        
        latest_cves = self.cve_analyzer.get_latest_cves(days=7, severity='HIGH')
        
        return {
            'timestamp': datetime.now().isoformat(),
            'latest_cves': latest_cves,
            'cve_count': len(latest_cves)
        }
    
    def generate_comprehensive_report(self, output_file=None):
        """
        Generate comprehensive threat report
        
        Args:
            output_file (str, optional): File to save report
            
        Returns:
            dict: Comprehensive report
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'threat_summary': {
                'breaches_analyzed': self.breach_analyzer.analysis_results,
                'credentials_checked': len(self.credential_detector.detection_history),
                'malware_detected': len([t for t in self.malware_detector.detected_threats if t['is_malicious']]),
                'cves_found': len(self.cve_analyzer.cve_history),
                'incidents_created': len(self.incident_responder.incidents)
            },
            'incidents': self.incident_responder.incidents,
            'alerts': self.incident_responder.alerts
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4, default=str)
            logger.info(f"Comprehensive report saved to {output_file}")
        
        return report


if __name__ == "__main__":
    # Initialize system
    system = ThreatIntelligenceSystem()
    
    # Example usage
    logger.info("=" * 60)
    logger.info("Threat Intelligence & Forensics System Demo")
    logger.info("=" * 60)
    
    # Check a credential
    logger.info("\n1. Checking compromised credentials...")
    cred_result = system.check_compromised_credentials(
        'user@example.com',
        'Test@123456'
    )
    print(json.dumps(cred_result, indent=2, default=str))
    
    # Check a file hash
    logger.info("\n2. Checking file hash for malware...")
    malware_result = system.detect_malware('d41d8cd98f00b204e9800998ecf8427e')
    print(json.dumps(malware_result, indent=2, default=str))
    
    # Get latest CVEs
    logger.info("\n3. Fetching latest vulnerabilities...")
    threats = system.get_latest_threats()
    print(json.dumps(threats, indent=2, default=str))
    
    # Generate report
    logger.info("\n4. Generating comprehensive report...")
    report = system.generate_comprehensive_report(
        output_file='output/reports/system_report.json'
    )
    print(f"Report generated with {len(report.get('incidents', []))} incidents")
    
    logger.info("\n" + "=" * 60)
    logger.info("Demo completed successfully!")
    logger.info("=" * 60)