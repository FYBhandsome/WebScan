"""
FastAPI 应用配置文件

使用 Pydantic Settings 管理应用配置,支持从环境变量和 .env 文件加载。
配置加载优先级:
1. 环境变量
2. .env 文件
3. 代码中的默认值
"""
from pydantic_settings import BaseSettings
from pydantic import ConfigDict, field_validator
from typing import Optional
from pathlib import Path


class Settings(BaseSettings):
    APP_NAME: str = "WebScan AI Security Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    HOST: str = "127.0.0.1"
    PORT: int = 8888
    
    CORS_ORIGINS: list = ["http://localhost:5173", "http://127.0.0.1:5173"]
    
    DATABASE_URL: str = "sqlite://backend/data/webscan.db"
    
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/app.log"
    CODE_EXECUTOR_LOG_FILE: str = "logs/code_executor.log"
    
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 300
    
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_BASE_URL: str = "https://maas-api.cn-huabei-1.xf-yun.com/v2"
    MODEL_ID: str = "xop3qwen1b7"
    QWEN_API_KEY: Optional[str] = None
    
    AWVS_API_URL: str = "https://127.0.0.1:3443"
    AWVS_API_KEY: Optional[str] = None
    
    UPLOAD_DIR: str = "uploads"
    
    SEEBUG_API_KEY: Optional[str] = None
    SEEBUG_API_BASE_URL: str = "https://www.seebug.org/api"
    
    CODE_EXECUTOR_WORKSPACE: str = "executor_workspace"
    CODE_EXECUTOR_TIMEOUT: int = 30
    CODE_EXECUTOR_ENABLED: bool = True
    
    AGENT_MAX_EXECUTION_TIME: int = 18000
    AGENT_TEMPERATURE: float = 0.3
    
    AGENT_MAX_RETRIES: int = 3
    
    POC_VERIFICATION_ENABLED: bool = True
    POC_MAX_CONCURRENT_EXECUTIONS: int = 5
    POC_EXECUTION_TIMEOUT: int = 60
    POC_RETRY_MAX_COUNT: int = 3
    POC_RESULT_ACCURACY_THRESHOLD: float = 0.95
    POC_CACHE_ENABLED: bool = True
    POC_CACHE_TTL: int = 3600
    POC_REPORT_FORMAT: str = "html"
    
    REPORTS_DIR: str = "reports"
    
    @property
    def REPORTS_PATH(self) -> Path:
        """获取报告目录的绝对路径"""
        return PROJECT_ROOT / "backend" / self.REPORTS_DIR
    
    @property
    def DATABASE_PATH(self) -> Path:
        """获取数据库文件的绝对路径"""
        return PROJECT_ROOT / "backend" / "data" / "webscan.db"

    @field_validator('AWVS_API_KEY', 'OPENAI_API_KEY', 'QWEN_API_KEY', 'SEEBUG_API_KEY', mode='before')
    @classmethod
    def strip_whitespace(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return v.strip()

    model_config = ConfigDict(
        env_file=str(Path(__file__).parent / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True
    )


settings = Settings()

PROJECT_ROOT = Path(__file__).parent.parent.resolve()

TORTOISE_ORM = {
    "connections": {
        "default": settings.DATABASE_URL
    },
    "apps": {
        "models": {
            "models": ["backend.models", "aerich.models"],
            "default_connection": "default",
        },
    },
}
