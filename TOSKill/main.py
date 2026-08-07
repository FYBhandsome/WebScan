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
Path(settings.RUNTIME_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(settings.LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)


async def reset_runtime_data() -> dict:
    """Reset persisted scan state, task statuses, reports, and orphan tasks."""
    from TOSKill.AI.graph import memory_store
    from TOSKill.AI.task_status_store import get_task_status_store
    from TOSKill.api.ai_chat_websocket import manager as ai_chat_manager
    from TOSKill.tools.report.report_manager import get_report_manager

    cancelled = await ai_chat_manager.reset_runtime_state()
    sessions = memory_store.reset_runtime_data()
    statuses = get_task_status_store().clear_all()
    reports = get_report_manager().clear_all_reports()
    return {
        "cancelled_tasks": cancelled,
        "sessions": sessions,
        "task_statuses": statuses,
        "reports": reports,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"启动 {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"服务地址: http://{settings.HOST}:{settings.PORT}")
    
    from TOSKill.AI.log_collector import log_collector
    log_collector.initialize()
    if settings.RESET_RUNTIME_DATA_ON_STARTUP:
        reset_summary = await reset_runtime_data()
        logger.info("Runtime data reset on startup: %s", reset_summary)
        log_collector.add_system_log("info", "启动时已清理扫描任务和报告数据", "system")
    log_collector.add_system_log("info", f"服务启动: {settings.APP_NAME} v{settings.APP_VERSION}", "system")
    
    from TOSKill.AI.model_check import verify_model_connectivity
    result = verify_model_connectivity()
    if result["success"]:
        logger.info(f"AI模型已连接: {result['message']} ({result['latency_ms']}ms)")
        log_collector.add_system_log("success", f"AI模型已连接: {result['message']}", "system")
    else:
        logger.warning(f"AI模型未连接: {result['message']}，扫描功能仍可用但AI决策将使用回退策略")
        log_collector.add_system_log("warning", f"AI模型未连接: {result['message']}", "system")
    
    yield
    
    log_collector.add_system_log("info", "服务关闭", "system")
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
    
    if request.url.path.startswith("/api/ws") or "upgrade" in request.headers.get("connection", "").lower():
        return await call_next(request)
    
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
from TOSKill.api.rag_api import router as rag_router
from TOSKill.api.scan_api import script_router
app.include_router(scan_router, prefix="/api")
app.include_router(ai_chat_router, prefix="/api")
app.include_router(report_router, prefix="/api")
app.include_router(chat_router, prefix="/api")
app.include_router(script_router, prefix="/api")
app.include_router(log_ws_router, prefix="/api")
app.include_router(rag_router, prefix="/api")


@app.post("/api/runtime/reset")
async def runtime_reset():
    """Manually clear all transient scan data for local development."""
    return {"status": "reset", "data": await reset_runtime_data()}


if __name__ == "__main__":
    uvicorn.run(
        "TOSKill.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=(settings.LOG_LEVEL or "info").lower(),
        access_log=True
    )
