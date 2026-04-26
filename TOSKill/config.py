"""
TOSKill 配置文件

独立配置，监听 8081 端口。
"""
from pydantic_settings import BaseSettings
from pydantic import ConfigDict, field_validator
from typing import Optional
from pathlib import Path


class TOSKillSettings(BaseSettings):
    APP_NAME: str = "TOSKill Security Scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    HOST: str = "0.0.0.0"
    PORT: int = 8081
    
    CORS_ORIGINS: list = ["*"]
    
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/toskill.log"
    
    OPENAI_API_KEY: str = "001aa457c2c63574b2799bf1e3342e72:YTRkOGU4NWU3NjRiZjk5Y2E5OTMzZTBl"
    OPENAI_BASE_URL: str = "https://maas-api.cn-huabei-1.xf-yun.com/v2"
    MODEL_ID: str = "xop3qwen1b7"
    
    SCAN_TIMEOUT: int = 300
    MAX_CONCURRENT_SCANS: int = 5
    
    REPORTS_DIR: str = "reports"
    UPLOAD_DIR: str = "uploads"

    @field_validator('OPENAI_API_KEY', mode='before')
    @classmethod
    def strip_key(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else v

    model_config = ConfigDict(
        env_file=str(Path(__file__).parent / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True
    )


settings = TOSKillSettings()
PROJECT_ROOT = Path(__file__).parent.resolve()
