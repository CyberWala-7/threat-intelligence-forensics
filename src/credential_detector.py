"""
Credential Detector Module
Detects compromised credentials against known breaches
"""

import hashlib
import logging
from datetime import datetime
import requests
import config

logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class CredentialDetector:
    """
    Detects compromised credentials against breach databases
    """
    
    def __init__(self):
        self.compromised_credentials = set()
        self.detection_history = []
        logger.info("CredentialDetector initialized")
    
    def check_credential(self, email, password):
        """
        Check if credential is compromised
        
        Args:
            email (str): Email address to check
            password (str): Password to check
            
        Returns:
            dict: Detection result with risk level
        """
        result = {
            'email': email,
            'password': '***',
            'timestamp': datetime.now().isoformat(),
            'is_compromised': False,
            'risk_level': 'LOW',
            'sources': [],
            'details': {}
        }
        
        # Check password against known breaches using SHA1
        password_hash = self._sha1_hash(password)
        password_compromised = self._check_password_hash(password_hash)
        
        # Check email against breach databases
        email_compromised = self._check_email_breach(email)
        
        # Determine if compromised
        both = password_compromised and email_compromised
        if password_compromised or email_compromised:
            result['is_compromised'] = True
            result['risk_level'] = 'CRITICAL' if both else 'HIGH'
        
        if password_compromised:
            result['sources'].append('Password Hash Database')
            result['details']['password_hash'] = password_hash
        
        if email_compromised:
            result['sources'].append('Email Breach Database')
            result['details']['email_breaches'] = email_compromised
        
        # Calculate risk score
        result['risk_score'] = self._calculate_risk_score(email, password)
        
        self.detection_history.append(result)
        return result
    
    def _sha1_hash(self, text):
        """Generate SHA1 hash of text"""
        return hashlib.sha1(text.encode()).hexdigest().upper()
    
    def _check_password_hash(self, password_hash):
        """
        Check password hash against HaveIBeenPwned database
        Uses k-anonymity for privacy
        
        Args:
            password_hash (str): SHA1 hash of password
            
        Returns:
            bool: True if password found in breaches
        """
        try:
            # Use first 5 characters for API call (k-anonymity)
            prefix = password_hash[:5]
            suffix = password_hash[5:]
            
            url = f'https://api.pwnedpasswords.com/range/{prefix}'
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for h in hashes:
                    if suffix in h:
                        logger.warning(f"Password hash found in breach database: {password_hash[:8]}...")
                        return True
            
            return False
        except Exception as e:
            logger.warning(f"Error checking password hash: {str(e)}")
            return False
    
    def _check_email_breach(self, email):
        """
        Check email against breach databases
        
        Args:
            email (str): Email address to check
            
        Returns:
            list: List of breaches if found
        """
        try:
            url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
            headers = {'User-Agent': 'Threat-Intelligence-System'}
            
            response = requests.get(url, headers=headers, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                breaches = response.json()
                logger.warning(f"Email found in {len(breaches)} breaches: {email}")
                return [b.get('Name') for b in breaches]
            elif response.status_code == 404:
                return []
            
        except Exception as e:
            logger.debug(f"Error checking email breach: {str(e)}")
        
        return []
    
    def _calculate_risk_score(self, email, password):
        """
        Calculate risk score (0-100)
        
        Args:
            email (str): Email address
            password (str): Password
            
        Returns:
            int: Risk score
        """
        score = 0
        
        # Password weak characteristics
        if len(password) < 8:
            score += 20
        if not any(c.isupper() for c in password):
            score += 15
        if not any(c.isdigit() for c in password):
            score += 15
        if not any(c in '!@#$%^&*' for c in password):
            score += 15
        
        # Common password patterns
        common_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if any(pattern in password.lower() for pattern in common_patterns):
            score += 20
        
        # Email reputation (simple check)
        if email.count('@') != 1 or email.count('.') < 1:
            score += 10
        
        return min(score, 100)
    
    def check_credentials_batch(self, credentials_list):
        """
        Check multiple credentials
        
        Args:
            credentials_list (list): List of {'email': str, 'password': str}
            
        Returns:
            list: Detection results
        """
        results = []
        for cred in credentials_list:
            result = self.check_credential(cred.get('email'), cred.get('password'))
            results.append(result)
        
        logger.info(f"Checked {len(credentials_list)} credentials")
        return results
    
    def generate_report(self, output_file=None):
        """
        Generate detection report
        
        Args:
            output_file (str, optional): File to save report
            
        Returns:
            dict: Report summary
        """
        compromised_count = sum(1 for h in self.detection_history if h['is_compromised'])
        
        report = {
            'total_checked': len(self.detection_history),
            'compromised_count': compromised_count,
            'risk_distribution': self._calculate_risk_distribution(),
            'detection_history': self.detection_history
        }
        
        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4, default=str)
            logger.info(f"Report saved to {output_file}")
        
        return report
    
    def _calculate_risk_distribution(self):
        """Calculate distribution of risk levels"""
        distribution = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for history in self.detection_history:
            risk = history.get('risk_level', 'LOW')
            if risk in distribution:
                distribution[risk] += 1
        
        return distribution