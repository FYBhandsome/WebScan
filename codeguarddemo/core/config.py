from typing import ClassVar
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "CodeGuard-AST 代码审计智能体"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DB_URL: str = "sqlite://data/codeguard.db"

    VULN_LEVEL: ClassVar[dict] = {
        "HIGH": "高危",
        "MEDIUM": "中危",
        "LOW": "低危"
    }


settings = Settings()
