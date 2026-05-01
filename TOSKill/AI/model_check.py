"""
AI 模型连通性检测模块
服务启动时调用，验证与模型服务的连接
"""
import logging
from ..config import settings

logger = logging.getLogger(__name__)


def verify_model_connectivity() -> dict:
    """
    验证 AI 模型服务连通性

    Returns:
        dict: {"success": bool, "message": str, "latency_ms": float}
    """
    import time
    from openai import OpenAI

    result = {"success": False, "message": "", "latency_ms": 0}

    if not settings.OPENAI_API_KEY:
        result["message"] = "OPENAI_API_KEY 未配置"
        logger.warning(f"AI模型连通性检测: {result['message']}")
        return result

    try:
        client = OpenAI(
            api_key=settings.OPENAI_API_KEY,
            base_url=settings.OPENAI_BASE_URL,
            timeout=10
        )

        start = time.time()
        response = client.chat.completions.create(
            model=settings.MODEL_ID,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5,
            timeout=10
        )
        latency = (time.time() - start) * 1000

        if response.choices:
            result["success"] = True
            result["message"] = f"连接成功 (模型: {settings.MODEL_ID})"
            result["latency_ms"] = round(latency, 1)
            logger.info(f"AI模型连通性检测: {result['message']}, 延迟: {result['latency_ms']}ms")
        else:
            result["message"] = "模型返回空响应"
            logger.warning(f"AI模型连通性检测: {result['message']}")
    except Exception as e:
        result["message"] = f"连接失败: {str(e)[:100]}"
        logger.warning(f"AI模型连通性检测: {result['message']}")

    return result
