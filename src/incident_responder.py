import uuid
import subprocess
from datetime import datetime
from config import settings, logger
from src.models import Incident
from typing import Dict, Any, List

class IncidentResponder:
    def __init__(self):
        self.incidents: List[Incident] = []
        self.alerts: List[Dict[str, Any]] = []
        logger.info("IncidentResponder initialized")
    
    def create_incident(self, threat_type: str, threat_data: Dict[str, Any]) -> Incident:
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            threat_type=threat_type,
            threat_data=threat_data,
            status="open"
        )
        self.incidents.append(incident)
        self._auto_respond(incident)
        # Also log an alert
        self.alerts.append({
            "type": "incident_created",
            "incident_id": incident.incident_id,
            "threat_type": threat_type,
            "timestamp": incident.timestamp.isoformat()
        })
        logger.warning(f"Incident created: {incident.incident_id} - {threat_type}")
        return incident
    
    def _auto_respond(self, incident: Incident):
        if incident.threat_type == "compromised_credential":
            email = incident.threat_data.get("email")
            if email and settings.auto_reset_password:
                self._reset_user_password(email)
            self._send_alert(f"Credential compromise detected for {email}")
        elif incident.threat_type == "malware":
            file_hash = incident.threat_data.get("hash")
            if file_hash:
                self._quarantine_file(file_hash)
            self._send_alert(f"Malware detected: {file_hash}")
        elif incident.threat_type == "malicious_ip":
            ip = incident.threat_data.get("ip")
            if ip and settings.auto_block_ip:
                self._block_ip_firewall(ip)
            self._send_alert(f"Malicious IP blocked: {ip}")
    
    def _reset_user_password(self, email: str):
        logger.warning(f"[ACTION] Resetting password for {email}")
        # Example: subprocess.run(["python", "reset_pwd.py", email])
    
    def _quarantine_file(self, file_hash: str):
        logger.warning(f"[ACTION] Quarantining file with hash {file_hash}")
    
    def _block_ip_firewall(self, ip: str):
        try:
            # Windows Firewall example
            cmd = f'netsh advfirewall firewall add rule name="BlockMaliciousIP_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=False)
            logger.info(f"[ACTION] Blocked IP {ip} via firewall")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
    
    def _send_alert(self, message: str):
        if settings.alert_email:
            # Implement SMTP if desired; for now log it
            logger.info(f"ALERT to {settings.alert_email}: {message}")
        else:
            logger.info(f"ALERT: {message}")
    
    def resolve_incident(self, incident_id: str, resolution: str):
        for inc in self.incidents:
            if inc.incident_id == incident_id:
                inc.status = "resolved"
                inc.resolution = resolution
                logger.info(f"Incident {incident_id} resolved: {resolution}")
                break
