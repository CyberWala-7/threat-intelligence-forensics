import asyncio
import json
from datetime import datetime
from config import logger
from src.credential_detector import CredentialDetector
from src.malware_detector import MalwareDetector
from src.cve_analyzer import CVEAnalyzer
from src.threat_intel import ThreatIntel
from src.incident_responder import IncidentResponder
from src.models import ThreatReport

class ThreatIntelligenceSystem:
    def __init__(self):
        self.cred_detector = CredentialDetector()
        self.malware_detector = MalwareDetector()
        self.cve_analyzer = CVEAnalyzer()
        self.threat_intel = ThreatIntel()
        self.responder = IncidentResponder()
        logger.info("Threat Intelligence System initialized")
    
    async def scan_indicator(self, ioc_type: str, value: str) -> dict:
        if ioc_type == "ip":
            result = await self.threat_intel.check_ip(value)
            if result.get("malicious"):
                self.responder.create_incident("malicious_ip", result)
            return result
        elif ioc_type == "email":
            result = await self.cred_detector.check_credential(value)
            if result.is_compromised:
                self.responder.create_incident("compromised_credential", result.model_dump(mode='json'))
            return result.model_dump(mode='json')
        elif ioc_type == "hash":
            result = await self.malware_detector.check_hash(value)
            if result.is_malicious:
                self.responder.create_incident("malware", result.model_dump(mode='json'))
            return result.model_dump(mode='json')
        else:
            return {"error": "unsupported ioc type"}
    
    async def check_vulnerabilities(self, product: str, version: str = None) -> list:
        cves = await self.cve_analyzer.check_product_vulnerabilities(product, version)
        if cves:
            for cve in cves:
                if cve.severity.value in ("HIGH", "CRITICAL"):
                    self.responder.create_incident("vulnerability", cve.model_dump(mode='json'))
        return [cve.model_dump(mode='json') for cve in cves]
    
    async def get_latest_threats(self) -> dict:
        latest_cves = await self.cve_analyzer.get_latest_cves(days=7, severity='HIGH')
        return {
            'timestamp': datetime.now().isoformat(),
            'latest_cves': [cve.model_dump(mode='json') for cve in latest_cves],
            'cve_count': len(latest_cves)
        }
    
    async def generate_report(self, output_file: str = None) -> dict:
        report = ThreatReport(
            timestamp=datetime.now(),
            threat_summary={
                "credentials_checked": len(self.cred_detector.detection_history),
                "malware_detected": sum(1 for inc in self.responder.incidents if inc.threat_type == "malware"),
                "vulnerabilities_found": len(self.cve_analyzer.cve_history),
                "incidents": len(self.responder.incidents)
            },
            incidents=self.responder.incidents,
            alerts=self.responder.alerts
        )
        report_dict = report.model_dump(mode='json')
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report_dict, f, indent=4)
            logger.info(f"Report saved to {output_file}")
        return report_dict
    
    async def close(self):
        await self.cred_detector.breach_analyzer.close()
        await self.malware_detector.close()
        await self.cve_analyzer.close()
        await self.threat_intel.close()

async def main():
    system = ThreatIntelligenceSystem()
    try:
        # Demo checks
        print("\n1. Checking IP reputation (1.1.1.1):")
        ip_result = await system.scan_indicator("ip", "1.1.1.1")
        print(json.dumps(ip_result, indent=2))
        
        print("\n2. Checking compromised credentials (test@example.com):")
        cred_result = await system.scan_indicator("email", "test@example.com")
        print(json.dumps(cred_result, indent=2))
        
        print("\n3. Checking malware hash (EICAR test hash):")
        malware_result = await system.scan_indicator("hash", "44d88612fea8a8f36de82e1278abb02f")
        print(json.dumps(malware_result, indent=2))
        
        print("\n4. Checking vulnerabilities for 'nginx':")
        cves = await system.check_vulnerabilities("nginx", "1.20.0")
        print(f"Found {len(cves)} CVEs (only showing first 2):")
        for cve in cves[:2]:
            print(json.dumps(cve, indent=2))
        
        print("\n5. Latest high-severity CVEs (past 7 days):")
        latest = await system.get_latest_threats()
        print(f"Found {latest['cve_count']} recent CVEs")
        
        print("\n6. Generating final report...")
        report = await system.generate_report("output/threat_report.json")
        print(f"Report generated with {len(report['incidents'])} incidents")
    finally:
        await system.close()

if __name__ == "__main__":
    asyncio.run(main())
