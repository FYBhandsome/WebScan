"""
FastAPI 应用配置文件
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """应用配置类"""
    
    # 应用基础配置
    APP_NAME: str = "WebScan AI Security Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # 服务器配置
    HOST: str = "127.0.0.1"
    PORT: int = 3000
    
    # CORS 配置
    CORS_ORIGINS: list = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:3000"
    ]
    
    # 数据库配置 - Tortoise-ORM 格式
    # SQLite: sqlite://./database.db
    # MySQL: mysql://user:password@host:port/database
    # PostgreSQL: postgres://user:password@host:port/database
    DATABASE_URL: str = "sqlite://./webscan.db"
    
    # 日志配置
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/app.log"
    
    # 扫描配置
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 300
    
    # API 密钥配置（可选）
    API_KEY: Optional[str] = None
    
    # AWVS 配置
    AWVS_API_URL: str = "https://127.0.0.1:3443"
    AWVS_API_KEY: str = "1986ad8c0a5b3df4d7028d5f3c06e936c4afa9c3233a64e329c40686bd9dbd468"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# Tortoise-ORM 配置（用于 Aerich 迁移工具）
TORTOISE_ORM = {
    "connections": {
        "default": settings.DATABASE_URL
    },
    "apps": {
        "models": {
            "models": ["models", "aerich.models"],
            "default_connection": "default",
        },
    },
}















