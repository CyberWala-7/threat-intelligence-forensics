from src.models import CredentialCheck
from src.breach_analyzer import BreachAnalyzer
from config import logger
from typing import Optional

class CredentialDetector:
    def __init__(self, breach_analyzer: Optional[BreachAnalyzer] = None):
        self.breach_analyzer = breach_analyzer or BreachAnalyzer()
        self.detection_history = []
        logger.info("CredentialDetector initialized")
    
    async def check_credential(self, email: str, password: str = None) -> CredentialCheck:
        result = await self.breach_analyzer.check_breach(email)
        if result is None:
            result = CredentialCheck(email=email, is_compromised=False)
        self.detection_history.append(result)
        return result
