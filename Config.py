from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import structlog

class Settings(BaseSettings):
    virustotal_api_key: str = Field("", alias="VIRUSTOTAL_API_KEY")
    hibp_api_key: str = Field("", alias="HIBP_API_KEY")
    nvd_api_key: str = Field("", alias="NVD_API_KEY")
    alienvault_otx_key: str = Field("", alias="ALIENVAULT_OTX_KEY")
    abuseipdb_api_key: str = Field("", alias="ABUSEIPDB_API_KEY")
    auto_reset_password: bool = Field(False, alias="AUTO_RESET_PASSWORD")
    auto_block_ip: bool = Field(False, alias="AUTO_BLOCK_IP")
    alert_email: str = Field("", alias="ALERT_EMAIL")
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    api_timeout: int = Field(10, alias="API_TIMEOUT")
    max_retries: int = Field(3, alias="MAX_RETRIES")
    retry_backoff: float = Field(1.0, alias="RETRY_BACKOFF")

    # Updated Pydantic V2 configuration syntax
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False
    )

settings = Settings()

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
