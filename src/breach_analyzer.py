import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from config import settings, logger
from src.models import CredentialCheck
from typing import Optional

class BreachAnalyzer:
    def __init__(self):
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.headers = {"hibp-api-key": settings.hibp_api_key} if settings.hibp_api_key else {}
        self.client = httpx.AsyncClient(timeout=settings.api_timeout)
        logger.info("BreachAnalyzer initialized")
    
    @retry(stop=stop_after_attempt(settings.max_retries),
           wait=wait_exponential(multiplier=settings.retry_backoff))
    async def check_breach(self, email: str) -> Optional[CredentialCheck]:
        try:
            response = await self.client.get(f"{self.base_url}/breachedaccount/{email}", headers=self.headers)
            if response.status_code == 404:
                return CredentialCheck(email=email, is_compromised=False)
            elif response.status_code == 200:
                breaches = response.json()
                return CredentialCheck(
                    email=email,
                    is_compromised=True,
                    breach_count=len(breaches),
                    breaches=[b["Name"] for b in breaches]
                )
            else:
                logger.error(f"HIBP API error: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Breach check failed for {email}: {e}")
            return None
    
    async def close(self):
        await self.client.aclose()
