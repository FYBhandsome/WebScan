"""
TOSKill 配置文件

独立配置，监听 8081 端口。
"""
import os
from pydantic_settings import BaseSettings
from pydantic import ConfigDict, field_validator
from typing import Optional
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.resolve()


class TOSKillSettings(BaseSettings):
    APP_NAME: str = "TOSKill Security Scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    HOST: str = "127.0.0.1"
    PORT: int = 8081
    
    CORS_ORIGINS: list = ["*"]
    
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/toskill.log"


    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "https://maas-api.cn-huabei-1.xf-yun.com/v2")
    MODEL_ID: str = os.getenv("MODEL_ID", "xop35qwen2b")
    LLM_TEMPERATURE: float = 0.1
    
    RAG_ENABLED: bool = True
    RAG_MODE: str = "mapping"
    RAG_ALLOWED_MODES: list = ["mapping", "vector"]
    RAG_KNOWLEDGE_DIR: str = "knowledge"
    RAG_UPLOAD_MAX_SIZE: int = 10 * 1024 * 1024
    SCAN_TIMEOUT: int = 300
    MAX_CONCURRENT_SCANS: int = 5
    # Help: 是否在启动时重置运行时数据
    RESET_RUNTIME_DATA_ON_STARTUP: bool = True
    
    REPORTS_DIR: str = "reports"
    SCRIPTS_DIR: str = "scripts"
    CUSTOM_SCRIPTS_DIR: str = "scripts/custom"
    UPLOAD_DIR: str = "uploads"
    DB_PATH: str = "TOSKill/data/toskill.db"
    RUNTIME_LOG_FILE: str = "logs/runtime.log"
    MAX_LOG_FILE_SIZE: int = 10 * 1024 * 1024
    MAX_LOG_BACKUP_FILES: int = 5
    
    @property
    def REPORTS_PATH(self) -> Path:
        return PROJECT_ROOT / self.REPORTS_DIR
    
    @property
    def SCRIPTS_PATH(self) -> Path:
        return PROJECT_ROOT / self.SCRIPTS_DIR
    
    @property
    def CUSTOM_SCRIPTS_PATH(self) -> Path:
        return PROJECT_ROOT / self.CUSTOM_SCRIPTS_DIR
    
    @property
    def DATABASE_PATH(self) -> Path:
        return PROJECT_ROOT / "data" / "toskill.db"
    
    @property
    def RUNTIME_LOG_PATH(self) -> Path:
        return PROJECT_ROOT / self.RUNTIME_LOG_FILE

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
