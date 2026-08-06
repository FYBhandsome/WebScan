"""RAG knowledge document management API."""
import os
import re
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from TOSKill.config import settings

router = APIRouter(prefix="/rag", tags=["RAG API"])

_KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "RAG" / "knowledge"
_ALLOWED_EXTENSIONS = {".md", ".txt"}
_DEFAULT_MAX_UPLOAD_SIZE = 5 * 1024 * 1024
_ALLOWED_MODES = ("mapping", "vector")
_index_stale = False
_rebuild_operations: dict[str, dict[str, Any]] = {}
_rebuild_lock = threading.Lock()
_active_rebuild_id: str | None = None


class RAGConfigUpdate(BaseModel):
    mode: str


def _get_rag_engine():
    from TOSKill.RAG.rag_engine import get_rag_engine

    return get_rag_engine()


def _rebuild_knowledge_base() -> bool:
    return _get_rag_engine().rebuild_index()


def _config_response(engine) -> dict[str, Any]:
    status = engine.get_status()
    return {
        "mode": status.get("mode"),
        "allowed_modes": list(_ALLOWED_MODES),
        "model_loaded": bool(status.get("model_loaded")),
        "index_ready": bool(status.get("index_ready")),
        "index_stale": bool(status.get("index_stale", _index_stale)),
        "last_error": status.get("last_error"),
    }


def _restore_index(engine, snapshot: tuple[Any, Any]) -> None:
    lock = getattr(engine, "_state_lock", None)
    if lock is None:
        engine.index, engine.retriever = snapshot
        return
    with lock:
        engine.index, engine.retriever = snapshot


def _run_rebuild(operation_id: str) -> None:
    global _active_rebuild_id, _index_stale
    with _rebuild_lock:
        operation = _rebuild_operations[operation_id]
        operation.update(status="running", progress=10)

    try:
        engine = _get_rag_engine()
        old_index = getattr(engine, "index", None)
        old_retriever = getattr(engine, "retriever", None)
        try:
            succeeded = _rebuild_knowledge_base()
        except Exception:
            _restore_index(engine, (old_index, old_retriever))
            raise
        if not succeeded:
            _restore_index(engine, (old_index, old_retriever))
            status = engine.get_status()
            raise RuntimeError(status.get("last_error") or "知识库索引重建失败")

        result = engine.get_status()
        _index_stale = False
        with _rebuild_lock:
            operation.update(status="completed", progress=100, result=result)
    except Exception as exc:
        with _rebuild_lock:
            operation.update(status="exception", progress=100, error=str(exc))
    finally:
        with _rebuild_lock:
            if _active_rebuild_id == operation_id:
                _active_rebuild_id = None


@router.get("/config")
async def get_rag_config():
    return _config_response(_get_rag_engine())


@router.put("/config")
async def update_rag_config(config: RAGConfigUpdate):
    if config.mode not in _ALLOWED_MODES:
        raise HTTPException(status_code=422, detail=f"非法 RAG 模式，允许值: {list(_ALLOWED_MODES)}")
    engine = _get_rag_engine()
    try:
        status = engine.set_mode(config.mode)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"切换 RAG 模式失败: {exc}")
    if config.mode == "vector" and not status.get("model_loaded"):
        error = status.get("last_error") or "vector 模式初始化失败"
        raise HTTPException(status_code=503, detail=error)
    if config.mode == "vector" and not status.get("index_ready"):
        error = status.get("last_error") or "vector 索引不可用"
        raise HTTPException(status_code=503, detail=error)
    return _config_response(engine)


@router.post("/index/rebuild", status_code=202)
async def rebuild_rag_index(background_tasks: BackgroundTasks):
    global _active_rebuild_id
    with _rebuild_lock:
        if _active_rebuild_id is not None:
            raise HTTPException(
                status_code=409,
                detail={"message": "索引重建已在进行中", "operation_id": _active_rebuild_id},
            )
        operation_id = uuid.uuid4().hex
        _active_rebuild_id = operation_id
        _rebuild_operations[operation_id] = {
            "operation_id": operation_id,
            "status": "queued",
            "progress": 0,
            "error": None,
            "result": None,
        }
    background_tasks.add_task(_run_rebuild, operation_id)
    return _rebuild_operations[operation_id].copy()


@router.get("/index/rebuild/{operation_id}")
async def get_rebuild_status(operation_id: str):
    with _rebuild_lock:
        operation = _rebuild_operations.get(operation_id)
        if operation is None:
            raise HTTPException(status_code=404, detail="重建操作不存在")
        return operation.copy()


def _knowledge_dir() -> Path:
    return _KNOWLEDGE_DIR.resolve()


def _safe_document_path(filename: str) -> Path:
    if not filename or filename != Path(filename.replace("\\", "/")).name:
        raise HTTPException(status_code=400, detail="非法文件名")
    path = (_knowledge_dir() / filename).resolve()
    knowledge_dir = _knowledge_dir()
    if path.parent != knowledge_dir or path.suffix.lower() not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="非法文件名或扩展名")
    return path


def _max_upload_size() -> int:
    for name in ("RAG_MAX_UPLOAD_SIZE", "MAX_RAG_UPLOAD_SIZE", "MAX_UPLOAD_SIZE"):
        value = getattr(settings, name, None)
        if value is not None:
            try:
                return max(1, int(value))
            except (TypeError, ValueError):
                break
    return _DEFAULT_MAX_UPLOAD_SIZE


def _document_info(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "filename": path.name,
        "name": path.name,
        "size": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "extension": path.suffix.lower(),
        "source": "RAG/knowledge",
    }


def _notify_rag_refresh() -> None:
    """Notify an already-created engine without triggering vector rebuilding."""
    try:
        from TOSKill.RAG.rag_engine import TOSKillRAGEngine
        engine = TOSKillRAGEngine._instance
        refresh = getattr(engine, "refresh_mapping", None) if engine else None
        if callable(refresh):
            refresh()
    except Exception:
        return


@router.get("/documents")
async def list_documents():
    knowledge_dir = _knowledge_dir()
    knowledge_dir.mkdir(parents=True, exist_ok=True)
    documents = [
        _document_info(path)
        for path in knowledge_dir.iterdir()
        if path.is_file() and path.suffix.lower() in _ALLOWED_EXTENSIONS
    ]
    documents.sort(key=lambda item: item["filename"].casefold())
    return documents


@router.get("/documents/{filename}")
async def get_document(filename: str):
    path = _safe_document_path(filename)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="文档不存在")
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail="文档不是有效的 UTF-8 文本")
    return {"filename": path.name, "name": path.name, "content": content}


@router.post("/documents")
async def upload_document(request: Request):
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" not in content_type.lower():
        raise HTTPException(status_code=415, detail="请求必须使用 multipart/form-data")
    try:
        form = await request.form()
    except RuntimeError as exc:
        if "python-multipart" in str(exc).lower() or "multipart" in str(exc).lower():
            raise HTTPException(status_code=503, detail="缺少 python-multipart 依赖")
        raise

    upload = form.get("file")
    if upload is None or not hasattr(upload, "filename") or not hasattr(upload, "read"):
        raise HTTPException(status_code=400, detail="缺少 file 上传字段")
    raw_name = str(upload.filename or "").replace("\\", "/")
    filename = Path(raw_name).name
    if not filename or filename != raw_name or not re.fullmatch(r"[^/\\]+", filename):
        raise HTTPException(status_code=400, detail="非法文件名")
    path = _safe_document_path(filename)
    max_size = _max_upload_size()
    _knowledge_dir().mkdir(parents=True, exist_ok=True)
    temp_path = None
    total = 0
    try:
        with tempfile.NamedTemporaryFile(dir=_knowledge_dir(), prefix=".rag-", suffix=".tmp", delete=False) as temp:
            temp_path = Path(temp.name)
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    raise HTTPException(status_code=413, detail=f"文件大小超过限制（{max_size} 字节）")
                temp.write(chunk)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_path, path)
    except HTTPException:
        raise
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()

    global _index_stale
    _index_stale = True
    _notify_rag_refresh()
    return JSONResponse(status_code=201, content={"filename": path.name, "name": path.name, "size": total, "index_stale": True})
