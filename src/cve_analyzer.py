"""
CVE Analyzer Module
Analyzes CVEs and vulnerabilities from public feeds
"""

import requests
import logging
from datetime import datetime, timedelta
import config

logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class CVEAnalyzer:
    """
    Analyzes Common Vulnerabilities and Exposures (CVEs)
    """
    
    def __init__(self):
        self.cve_database = {}
        self.cve_history = []
        logger.info("CVEAnalyzer initialized")
    
    def get_latest_cves(self, days=7, severity='HIGH'):
        """
        Get latest CVEs from NVD
        
        Args:
            days (int): Number of days to look back
            severity (str): Minimum severity level (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            list: List of recent CVEs
        """
        cves = []
        start_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        try:
            url = f'{config.NVD_API_URL}/cves/1.0'
            params = {
                'pubStartDate': start_date,
                'resultsPerPage': 100
            }
            
            response = requests.get(url, params=params, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                
                for result in data.get('result', {}).get('CVE_Items', []):
                    cve_id = result.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                    severity_score = self._extract_severity(result)
                    
                    if severity_score and self._meets_severity_threshold(severity_score, severity):
                        cve = {
                            'cve_id': cve_id,
                            'severity': severity_score,
                            'published_date': result.get('publishedDate'),
                            'description': self._extract_description(result),
                            'cvss_score': self._extract_cvss_score(result),
                            'affected_products': self._extract_affected_products(result)
                        }
                        
                        cves.append(cve)
                        self.cve_database[cve_id] = cve
                        self.cve_history.append(cve)
            
            logger.info(f"Retrieved {len(cves)} CVEs from NVD")
        
        except Exception as e:
            logger.error(f"Error fetching CVEs: {str(e)}")
        
        return cves
    
    def check_cve(self, cve_id):
        """
        Get detailed information about a specific CVE
        
        Args:
            cve_id (str): CVE ID (e.g., CVE-2021-44228)
            
        Returns:
            dict: CVE details
        """
        if cve_id in self.cve_database:
            return self.cve_database[cve_id]
        
        try:
            url = f'{config.NVD_API_URL}/cves/1.0/{cve_id}'
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                result = response.json().get('result', {}).get('CVE_Items', [{}])[0]
                
                cve = {
                    'cve_id': cve_id,
                    'severity': self._extract_severity(result),
                    'published_date': result.get('publishedDate'),
                    'description': self._extract_description(result),
                    'cvss_score': self._extract_cvss_score(result),
                    'affected_products': self._extract_affected_products(result),
                    'references': self._extract_references(result)
                }
                
                self.cve_database[cve_id] = cve
                return cve
        
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {str(e)}")
        
        return None
    
    def check_product_vulnerabilities(self, product_name, version=None):
        """
        Check vulnerabilities for a specific product
        
        Args:
            product_name (str): Product name (e.g., 'apache')
            version (str, optional): Product version
            
        Returns:
            list: List of applicable CVEs
        """
        vulnerabilities = []
        
        try:
            url = f'{config.NVD_API_URL}/cpes/1.0'
            params = {
                'keyword': product_name,
                'resultsPerPage': 50
            }
            
            response = requests.get(url, params=params, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                
                for result in data.get('result', {}).get('cpes', []):
                    cpe = result.get('cpe23Uri')
                    
                    if version is None or version in cpe:
                        # Get CVEs for this CPE
                        cve_match = self._get_cves_for_cpe(cpe)
                        vulnerabilities.extend(cve_match)
        
        except Exception as e:
            logger.error(f"Error checking product vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _extract_severity(self, cve_item):
        """Extract severity from CVE item"""
        impact = cve_item.get('impact', {})
        cvss_v3 = impact.get('baseMetricV3', {})
        cvss_v2 = impact.get('baseMetricV2', {})
        
        if cvss_v3:
            return cvss_v3.get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
        elif cvss_v2:
            return self._convert_cvss_v2_severity(cvss_v2.get('severity', 'UNKNOWN'))
        
        return 'UNKNOWN'
    
    def _convert_cvss_v2_severity(self, severity_score):
        """Convert CVSS v2 score to severity level"""
        try:
            score = float(severity_score)
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        except:
            return 'UNKNOWN'
    
    def _extract_description(self, cve_item):
        """Extract description from CVE item"""
        return cve_item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', '')
    
    def _extract_cvss_score(self, cve_item):
        """Extract CVSS score"""
        impact = cve_item.get('impact', {})
        cvss_v3 = impact.get('baseMetricV3', {})
        
        if cvss_v3:
            return cvss_v3.get('cvssV3', {}).get('baseScore')
        
        cvss_v2 = impact.get('baseMetricV2', {})
        if cvss_v2:
            return cvss_v2.get('cvssV2', {}).get('baseScore')
        
        return None
    
    def _extract_affected_products(self, cve_item):
        """Extract affected products"""
        products = []
        
        for config_item in cve_item.get('configurations', {}).get('nodes', []):
            for cpe_match in config_item.get('cpe_match', []):
                products.append(cpe_match.get('cpe23Uri'))
        
        return list(set(products))
    
    def _extract_references(self, cve_item):
        """Extract reference URLs"""
        references = []
        
        for ref in cve_item.get('cve', {}).get('references', {}).get('reference_data', []):
            references.append(ref.get('url'))
        
        return references
    
    def _meets_severity_threshold(self, severity, threshold):
        """Check if severity meets threshold"""
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        threshold_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        
        return severity_levels.get(severity, 0) >= threshold_levels.get(threshold, 0)
    
    def _get_cves_for_cpe(self, cpe):
        """Get CVEs for a specific CPE (placeholder)"""
        # This would integrate with NVD API to get CVEs for CPE
        return []
    
    def generate_vulnerability_report(self, output_file=None):
        """
        Generate vulnerability report
        
        Args:
            output_file (str, optional): File to save report
            
        Returns:
            dict: Report summary
        """
        critical_count = sum(1 for cve in self.cve_history if cve.get('severity') == 'CRITICAL')
        high_count = sum(1 for cve in self.cve_history if cve.get('severity') == 'HIGH')
        
        report = {
            'total_cves': len(self.cve_history),
            'critical_cves': critical_count,
            'high_cves': high_count,
            'cve_list': self.cve_history
        }
        
        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4, default=str)
            logger.info(f"Vulnerability report saved to {output_file}")
        
        return report