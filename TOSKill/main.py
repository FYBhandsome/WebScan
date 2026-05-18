"""
TOSKill FastAPI 主应用入口

独立的安全扫描服务，监听 8081 端口。
"""
import sys
from pathlib import Path

current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
import uvicorn

from TOSKill.config import settings

Path("logs").mkdir(exist_ok=True)
Path("reports").mkdir(exist_ok=True)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(settings.LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    logger.info(f"启动 {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"服务地址: http://{settings.HOST}:{settings.PORT}")
    
    from TOSKill.AI.model_check import verify_model_connectivity
    result = verify_model_connectivity()
    if result["success"]:
        logger.info(f"AI模型已连接: {result['message']} ({result['latency_ms']}ms)")
    else:
        logger.warning(f"AI模型未连接: {result['message']}，扫描功能仍可用但AI决策将使用回退策略")
    
    yield
    logger.info("服务关闭")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI驱动的Web安全扫描服务",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.middleware("http")
async def cors_preflight_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Accept, Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
                "Access-Control-Max-Age": "600",
                "Access-Control-Allow-Credentials": "false",
                "Access-Control-Expose-Headers": "*",
            }
        )
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.get("/")
async def root():
    """根路径"""
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy"}


from TOSKill.api import ai_chat_router, chat_router, report_router, scan_router, log_ws_router
from TOSKill.api.scan_api import script_router
app.include_router(scan_router, prefix="/api")
app.include_router(ai_chat_router, prefix="/api")
app.include_router(report_router, prefix="/api")
app.include_router(chat_router, prefix="/api")
app.include_router(script_router, prefix="/api")
app.include_router(log_ws_router, prefix="/api")


if __name__ == "__main__":
    uvicorn.run(
        "TOSKill.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True
    )
