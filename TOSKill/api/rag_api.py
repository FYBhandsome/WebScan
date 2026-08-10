"""RAG 知识库管理接口。"""
import asyncio
import logging
import threading
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from TOSKill.api.scan_api import APIResponse
from TOSKill.config import settings
from TOSKill.RAG.rag_engine import get_rag_engine


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/rag", tags=["RAG 知识库"])

# 重建过程会写入同一组 LlamaIndex 持久化文件。进程内只允许一个请求执行，
# 避免用户重复点击导致索引文件和内存 retriever 相互覆盖。
_rebuild_lock = threading.Lock()


def _status_payload(engine: Any, *, rebuilding: bool = False) -> Dict[str, Any]:
    """构造可公开给前端的 RAG 状态，避免返回本机绝对目录。"""
    stats = engine.get_stats()
    if not settings.RAG_ENABLED:
        index_status = "disabled"
    elif rebuilding:
        index_status = "rebuilding"
    elif stats["ready"]:
        index_status = "ready"
    elif stats.get("model_load_error"):
        index_status = "error"
    else:
        index_status = "not_ready"

    return {
        "enabled": settings.RAG_ENABLED,
        "index_status": index_status,
        "initialized": stats["initialized"],
        "ready": stats["ready"],
        "document_count": stats["document_count"],
        "knowledge_base_version": engine.get_kb_version(),
        "embed_model": stats["embed_model"],
        "embed_model_loaded": stats["embed_model_loaded"],
        "model_load_error": stats.get("model_load_error"),
        "keyword_fallback_enabled": stats["keyword_fallback_enabled"],
    }


@router.get("/status", response_model=APIResponse)
async def get_rag_status() -> APIResponse:
    """获取 RAG 模型和向量索引的可用状态。"""
    try:
        engine = await asyncio.to_thread(get_rag_engine)
        return APIResponse(data=_status_payload(engine, rebuilding=_rebuild_lock.locked()))
    except Exception as exc:
        logger.exception("获取 RAG 状态失败")
        raise HTTPException(status_code=500, detail="获取 RAG 状态失败") from exc


@router.post("/rebuild", response_model=APIResponse)
async def rebuild_rag_index() -> APIResponse:
    """根据 ``RAG/knowledge`` 中当前文档重新生成向量索引。"""
    if not settings.RAG_ENABLED:
        raise HTTPException(status_code=503, detail="RAG 功能当前未启用")

    if not _rebuild_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="RAG 索引正在重建，请勿重复提交")

    try:
        engine = await asyncio.to_thread(get_rag_engine)
        rebuilt = await asyncio.to_thread(engine.rebuild_index)
        if not rebuilt:
            stats = engine.get_stats()
            detail = stats.get("model_load_error") or "向量索引重建失败"
            raise HTTPException(status_code=500, detail=detail)

        status = _status_payload(engine)
        logger.info(
            "RAG 索引已通过管理接口重建: documents=%s, version=%s",
            status["document_count"],
            status["knowledge_base_version"],
        )
        return APIResponse(message="RAG 向量索引重建成功", data=status)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("RAG 索引重建失败")
        raise HTTPException(status_code=500, detail="RAG 索引重建失败") from exc
    finally:
        _rebuild_lock.release()
