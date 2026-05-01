"""
FastAPI 主应用入口文件

本文件是 WebScan AI Security Platform 的主入口,负责:
- 创建和配置 FastAPI 应用实例
- 设置 CORS 中间件
- 注册 API 路由
- 配置日志系统
- 管理应用生命周期(启动/关闭)
- 初始化数据库连接
- 验证外部服务连接(如 AWVS)
- 启动后台任务
- 任务恢复功能
"""
import sys
import warnings
import asyncio
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning, module="paramiko")
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import socket

def handle_asyncio_exception(loop, context):
    """
    自定义 asyncio 异常处理器
    
    处理 Windows 平台上常见的连接重置错误，包括：
    - ConnectionResetError [WinError 10054]: 远程主机强迫关闭了一个现有的连接
    - ConnectionAbortedError [WinError 10053]: 你的主机中的软件中止了一个已建立的连接
    - BrokenPipeError [WinError 10032]: 管道正在关闭
    """
    exception = context.get("exception")
    
    if exception:
        if isinstance(exception, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError)):
            exception_code = getattr(exception, 'winerror', getattr(exception, 'errno', None))
            known_codes = [10054, 10053, 10032, 32, 9, 104]
            if exception_code in known_codes or isinstance(exception, (ConnectionResetError, BrokenPipeError)):
                return
    
    message = context.get("message", "")
    if "Connection reset" in message or "pipe" in message.lower():
        return
    
    loop.default_exception_handler(context)

def setup_asyncio_exception_handler():
    if sys.platform == 'win32':
        try:
            policy = asyncio.WindowsProactorEventLoopPolicy()
            asyncio.set_event_loop_policy(policy)
        except (AttributeError, NotImplementedError):
            pass
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(handle_asyncio_exception)
        print("asyncio 异常处理器已配置")
    except Exception as e:
        print(f"设置 asyncio 异常处理器失败: {e}")

setup_asyncio_exception_handler()

current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
from backend.config import settings
from backend.database import init_db, close_db
import logging

Path("logs").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)

from backend.utils.logging_utils import (
    setup_structured_logging,
    set_request_id,
    get_request_id,
    JsonFormatter
)

setup_structured_logging(
    log_level=settings.LOG_LEVEL,
    log_file=settings.LOG_FILE,
    json_format=True,
    console_output=True
)

logger = logging.getLogger(__name__)

api_logger = logging.getLogger("api_logger")
api_logger.setLevel(getattr(logging, settings.LOG_LEVEL))
api_file_handler = logging.FileHandler("logs/api.log", encoding='utf-8')
api_file_handler.setFormatter(JsonFormatter())
api_logger.addHandler(api_file_handler)

shutdown_timeout = 30

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    应用生命周期管理
    
    管理应用的启动和关闭流程:
    启动时:
    - 初始化数据库连接
    - 验证 AWVS API 连接
    - 启动后台数据同步任务
    - 注册信号处理器
    - 恢复未完成任务
    
    关闭时:
    - 关闭任务执行器
    - 关闭WebSocket连接
    - 关闭数据库连接
    - 清理资源
    
    Args:
        app: FastAPI 应用实例
        
    Yields:
        None: 控制权交还给应用
    """
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(handle_asyncio_exception)
    
    logger.info(f"启动 {settings.APP_NAME} v{settings.APP_VERSION}")
    
    await init_db()
    
    try:
        from backend.AVWS.API.Base import Base as AWVSBase
        awvs_base = AWVSBase(settings.AWVS_API_URL, settings.AWVS_API_KEY)
        success, message = awvs_base.check_connection()
        if success:
            logger.info("AWVS API 连接测试成功")
        else:
            logger.error(f"AWVS API 连接测试失败: {message}")
            logger.warning("请检查配置文件中的 AWVS_API_URL 和 AWVS_API_KEY")
    except Exception as e:
        logger.error(f"执行 AWVS 连接测试时发生错误: {str(e)}")

    try:
        from backend.api.awvs import sync_scans_from_awvs
        
        if success:
            logger.info("AWVS API 连接成功，开始自动同步数据...")
            await sync_scans_from_awvs()
            logger.info("AWVS 数据自动同步完成")
        else:
            logger.warning("AWVS API 未连接，跳过自动同步")
    except Exception as e:
        logger.error(f"自动同步AWVS数据失败: {str(e)}")
    
    try:
        from backend.task_executor import task_executor
        

        task_executor.start_worker()
        logger.info("任务执行器 Worker 已启动")
        
        await task_executor.recover_pending_tasks()
        
    except Exception as e:
        logger.error(f"启动任务执行器失败: {str(e)}")

    yield
    
    logger.info("=" * 50)
    logger.info("开始优雅关闭流程...")
    logger.info("=" * 50)
    
    shutdown_start_time = asyncio.get_event_loop().time()
    
    try:
        logger.info("[1/3] 正在关闭任务执行器...")
        from backend.task_executor import task_executor
        await asyncio.wait_for(
            task_executor.shutdown(),
            timeout=shutdown_timeout
        )
        logger.info("[1/3] 任务执行器已关闭")
    except asyncio.TimeoutError:
        logger.warning(f"[1/3] 任务执行器关闭超时 ({shutdown_timeout}s)")
    except Exception as e:
        logger.error(f"[1/3] 关闭任务执行器时发生错误: {e}")

    try:
        logger.info("[2/3] 正在关闭所有WebSocket连接...")
        from backend.api.websocket import manager
        await asyncio.wait_for(
            manager.close_all(),
            timeout=10
        )
        logger.info("[2/3] WebSocket连接已全部关闭")
    except asyncio.TimeoutError:
        logger.warning("[2/3] WebSocket关闭超时")
    except Exception as e:
        logger.error(f"[2/3] 关闭WebSocket时发生错误: {e}")

    try:
        logger.info("[3/3] 正在关闭数据库连接...")
        await asyncio.wait_for(
            close_db(),
            timeout=10
        )
        logger.info("[3/3] 数据库连接已关闭")
    except asyncio.TimeoutError:
        logger.warning("[3/3] 数据库关闭超时")
    except Exception as e:
        logger.error(f"[3/3] 关闭数据库时发生错误: {e}")
    
    shutdown_duration = asyncio.get_event_loop().time() - shutdown_start_time
    logger.info("=" * 50)
    logger.info(f"优雅关闭完成，耗时: {shutdown_duration:.2f}秒")
    logger.info("=" * 50)

# 创建 FastAPI 应用实例
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI驱动的Web安全扫描平台",
    lifespan=lifespan
)

# 配置 CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 配置 API 日志中间件
from backend.api.logging_middleware import setup_api_logging
setup_api_logging(app, settings.LOG_LEVEL)


@app.get("/")
async def root():
    """
    根路径
    
    返回 API 基本信息,用于验证服务是否正常运行。
    
    Returns:
        Dict: 包含欢迎消息、版本号和状态的响应
        
    Examples:
        >>> GET /
        >>> {
        ...     "message": "Welcome to WebScan AI Security Platform",
        ...     "version": "1.0.0",
        ...     "status": "running"
        ... }
    """
    return {
        "message": "Welcome to WebScan AI Security Platform",
        "version": settings.APP_VERSION,
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """
    健康检查端点
    
    用于监控服务健康状态,负载均衡器和容器编排系统可以定期调用此端点。
    
    Returns:
        Dict: 包含健康状态的响应
        
    Examples:
        >>> GET /health
        >>> {"status": "healthy"}
    """
    return {"status": "healthy"}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    全局异常处理器
    
    捕获所有未处理的异常,统一返回错误响应。
    在生产环境中,不会返回详细的错误信息以避免泄露敏感信息。
    
    Args:
        request: 请求对象
        exc: 异常对象
        
    Returns:
        JSONResponse: 统一的错误响应格式
    """
    logger.error(f"未处理的异常: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "code": 500,
            "message": "服务器内部错误",
            "error": str(exc) if settings.DEBUG else "Internal Server Error"
        }
    )


# 注册路由
from backend.api import api_router
app.include_router(api_router, prefix="/api")


if __name__ == "__main__":
    """
    应用启动入口
    
    使用 Uvicorn ASGI 服务器运行 FastAPI 应用。
    """
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
        use_colors=True,
        loop="asyncio"
    )
