import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from config import settings, logger
from src.models import CVE, Severity
from datetime import datetime, timedelta
from typing import List, Optional

class CVEAnalyzer:
    def __init__(self):
        self.api_key = settings.nvd_api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.client = httpx.AsyncClient(timeout=settings.api_timeout)
        self.cve_history = []
        logger.info("CVEAnalyzer initialized")
    
    @retry(stop=stop_after_attempt(settings.max_retries))
    async def check_product_vulnerabilities(self, product_name: str, version: Optional[str] = None) -> List[CVE]:
        params = {"keywordSearch": product_name, "resultsPerPage": 20}
        if version:
            params["keywordSearch"] += f" {version}"
        try:
            response = await self.client.get(self.base_url, params=params)
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln["cve"]
                    metrics = cve_data.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    severity_str = cvss_v3.get("baseSeverity", "MEDIUM")
                    try:
                        severity = Severity[severity_str.upper()]
                    except KeyError:
                        severity = Severity.MEDIUM
                    cve = CVE(
                        id=cve_data["id"],
                        severity=severity,
                        cvss_score=cvss_v3.get("baseScore"),
                        description=cve_data["descriptions"][0]["value"],
                        published_date=datetime.fromisoformat(cve_data["published"].replace("Z", "+00:00")),
                        product=product_name,
                        version=version
                    )
                    cves.append(cve)
                self.cve_history.extend(cves)
                return cves
            else:
                return []
        except Exception as e:
            logger.error(f"CVE check failed: {e}")
            return []
    
    async def get_latest_cves(self, days: int = 7, severity: str = "HIGH") -> List[CVE]:
        pub_start_date = (datetime.now() - timedelta(days=days)).isoformat() + "Z"
        params = {"pubStartDate": pub_start_date, "resultsPerPage": 50}
        try:
            response = await self.client.get(self.base_url, params=params)
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln["cve"]
                    metrics = cve_data.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    sev = cvss_v3.get("baseSeverity", "LOW")
                    try:
                        severity_enum = Severity[sev.upper()]
                    except KeyError:
                        severity_enum = Severity.LOW
                    if severity_enum.value >= Severity[severity.upper()].value:
                        cves.append(CVE(
                            id=cve_data["id"],
                            severity=severity_enum,
                            cvss_score=cvss_v3.get("baseScore"),
                            description=cve_data["descriptions"][0]["value"],
                            published_date=datetime.fromisoformat(cve_data["published"].replace("Z", "+00:00"))
                        ))
                return cves
            return []
        except Exception as e:
            logger.error(f"Latest CVEs fetch failed: {e}")
            return []
    
    async def close(self):
        await self.client.aclose()
