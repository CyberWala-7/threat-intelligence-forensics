"""
Incident Response Module
Automates incident response and threat reporting
"""

import logging
from datetime import datetime
import json
import config

logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class IncidentResponder:
    """
    Handles automated incident response and reporting
    """
    
    def __init__(self):
        self.incidents = []
        self.alerts = []
        logger.info("IncidentResponder initialized")
    
    def create_incident(self, threat_data, breach_data=None, cve_data=None):
        """
        Create incident from threat data
        
        Args:
            threat_data (dict): Threat information
            breach_data (dict, optional): Breach information
            cve_data (dict, optional): CVE information
            
        Returns:
            dict: Incident record
        """
        incident = {
            'incident_id': f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'severity': self._determine_severity(threat_data),
            'threat_data': threat_data,
            'breach_data': breach_data,
            'cve_data': cve_data,
            'status': 'OPEN',
            'timeline': [{
                'time': datetime.now().isoformat(),
                'event': 'Incident Created',
                'details': 'Automated incident creation from threat detection'
            }],
            'remediation_steps': self._generate_remediation(threat_data),
            'affected_assets': self._identify_affected_assets(threat_data, breach_data)
        }
        
        self.incidents.append(incident)
        logger.info(f"Incident created: {incident['incident_id']}")
        
        return incident
    
    def generate_alert(self, incident_id, message, severity='HIGH'):
        """
        Generate alert for incident
        
        Args:
            incident_id (str): Incident ID
            message (str): Alert message
            severity (str): Alert severity
            
        Returns:
            dict: Alert record
        """
        alert = {
            'alert_id': f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'incident_id': incident_id,
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'status': 'UNACKNOWLEDGED'
        }
        
        self.alerts.append(alert)
        logger.warning(f"Alert generated: {alert['alert_id']} - {message}")
        
        if config.AUTO_REMEDIATION_ENABLED:
            self._trigger_remediation(incident_id)
        
        return alert
    
    def _determine_severity(self, threat_data):
        """
        Determine incident severity
        
        Args:
            threat_data (dict): Threat information
            
        Returns:
            str: Severity level
        """
        if threat_data.get('threat_level') == 'CRITICAL':
            return 'CRITICAL'
        elif threat_data.get('threat_level') == 'HIGH':
            return 'HIGH'
        elif threat_data.get('threat_level') == 'MEDIUM':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_remediation(self, threat_data):
        """
        Generate remediation steps
        
        Args:
            threat_data (dict): Threat information
            
        Returns:
            list: Remediation steps
        """
        steps = []
        
        if threat_data.get('is_malicious'):
            steps.extend([
                'Isolate affected systems from network',
                'Quarantine malicious files',
                'Kill malicious processes',
                'Conduct full system scan',
                'Review file integrity'
            ])
        
        if threat_data.get('is_compromised'):
            steps.extend([
                'Force password reset for affected accounts',
                'Enable MFA if not already enabled',
                'Review account activity logs',
                'Check for unauthorized access',
                'Update security credentials'
            ])
        
        return steps
    
    def _identify_affected_assets(self, threat_data, breach_data):
        """
        Identify affected assets
        
        Args:
            threat_data (dict): Threat information
            breach_data (dict, optional): Breach information
            
        Returns:
            list: List of affected assets
        """
        assets = []
        
        if threat_data.get('hash'):
            assets.append({
                'type': 'File Hash',
                'value': threat_data['hash'],
                'impact': 'Potential malware infection'
            })
        
        if breach_data and breach_data.get('email'):
            assets.append({
                'type': 'Email Account',
                'value': breach_data['email'],
                'impact': 'Credential compromise'
            })
        
        return assets
    
    def _trigger_remediation(self, incident_id):
        """
        Trigger automated remediation
        
        Args:
            incident_id (str): Incident ID
        """
        logger.info(f"Triggering automated remediation for {incident_id}")
        # Placeholder for automated remediation actions
        pass
    
    def generate_incident_report(self, incident_id, output_file=None):
        """
        Generate comprehensive incident report
        
        Args:
            incident_id (str): Incident ID
            output_file (str, optional): File to save report
            
        Returns:
            dict: Incident report
        """
        incident = next((inc for inc in self.incidents if inc['incident_id'] == incident_id), None)
        
        if not incident:
            logger.error(f"Incident not found: {incident_id}")
            return None
        
        report = {
            'incident_id': incident['incident_id'],
            'timestamp': incident['timestamp'],
            'severity': incident['severity'],
            'status': incident['status'],
            'summary': f"Incident {incident['incident_id']} with severity {incident['severity']}",
            'threat_overview': incident['threat_data'],
            'affected_assets': incident['affected_assets'],
            'timeline': incident['timeline'],
            'remediation_steps': incident['remediation_steps'],
            'related_alerts': [a for a in self.alerts if a['incident_id'] == incident_id]
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4, default=str)
            logger.info(f"Incident report saved to {output_file}")
        
        return report
    
    def generate_summary_report(self, output_file=None):
        """
        Generate summary of all incidents
        
        Args:
            output_file (str, optional): File to save report
            
        Returns:
            dict: Summary report
        """
        critical_count = sum(1 for inc in self.incidents if inc['severity'] == 'CRITICAL')
        high_count = sum(1 for inc in self.incidents if inc['severity'] == 'HIGH')
        
        summary = {
            'report_timestamp': datetime.now().isoformat(),
            'total_incidents': len(self.incidents),
            'critical_incidents': critical_count,
            'high_incidents': high_count,
            'open_incidents': sum(1 for inc in self.incidents if inc['status'] == 'OPEN'),
            'total_alerts': len(self.alerts),
            'incidents': self.incidents
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(summary, f, indent=4, default=str)
            logger.info(f"Summary report saved to {output_file}")
        
        return summary
    
    def close_incident(self, incident_id, resolution_notes):
        """
        Close an incident
        
        Args:
            incident_id (str): Incident ID
            resolution_notes (str): Resolution notes
            
        Returns:
            dict: Updated incident
        """
        incident = next((inc for inc in self.incidents if inc['incident_id'] == incident_id), None)
        
        if incident:
            incident['status'] = 'CLOSED'
            incident['timeline'].append({
                'time': datetime.now().isoformat(),
                'event': 'Incident Closed',
                'details': resolution_notes
            })
            logger.info(f"Incident closed: {incident_id}")
        
        return incident