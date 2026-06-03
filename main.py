from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import structlog
from dotenv import load_dotenv
import os

# Explicitly load .env from the Desktop folder
env_path = r'C:\Users\LENOVO X280\Desktop\.env'
load_dotenv(dotenv_path=env_path)

# Debug: print loaded keys (remove after confirming)
print("DEBUG: VIRUSTOTAL_API_KEY =", os.getenv("VIRUSTOTAL_API_KEY"))
print("DEBUG: ABUSEIPDB_API_KEY =", os.getenv("ABUSEIPDB_API_KEY"))
print("DEBUG: HIBP_API_KEY =", os.getenv("HIBP_API_KEY"))

class Settings(BaseSettings):
    virustotal_api_key: str = Field("", alias="ADD YOUR API KEY")
    hibp_api_key: str = Field("", alias="ADD YOUR API KEY")
    nvd_api_key: str = Field("", alias="NVD_API_KEY")
    alienvault_otx_key: str = Field("", alias="ALIENVAULT_OTX_KEY")
    abuseipdb_api_key: str = Field("", alias="ADD YOUR API KEY")
    auto_reset_password: bool = Field(False, alias="AUTO_RESET_PASSWORD")
    auto_block_ip: bool = Field(False, alias="AUTO_BLOCK_IP")
    alert_email: str = Field("", alias="ALERT_EMAIL")
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    api_timeout: int = Field(10, alias="API_TIMEOUT")
    max_retries: int = Field(3, alias="MAX_RETRIES")
    retry_backoff: float = Field(1.0, alias="RETRY_BACKOFF")

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )

settings = Settings()

# Optional: if settings still empty, manually assign from os.getenv (fallback)
if not settings.virustotal_api_key:
    settings.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
if not settings.abuseipdb_api_key:
    settings.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
if not settings.hibp_api_key:
    settings.hibp_api_key = os.getenv("HIBP_API_KEY", "")

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger()
