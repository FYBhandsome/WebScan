"""
报告下载API

提供报告列表查询、文件下载、内容查看等功能
报告生成在扫描任务完成时自动执行，不提供独立API
"""
import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from TOSKill.api.scan_api import APIResponse
from TOSKill.config import settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

REPORTS_DIR = PROJECT_ROOT / "reports"
REPORT_EXTENSIONS = ["*.md", "*.html", "*.pdf"]


def ensure_reports_dir():
    """确保报告目录存在"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def validate_report_path(filename: str) -> Path:
    """验证并返回安全的报告文件路径"""
    ensure_reports_dir()
    file_path = REPORTS_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="报告文件不存在")
    
    if not str(file_path.resolve()).startswith(str(REPORTS_DIR.resolve())):
        raise HTTPException(status_code=403, detail="非法文件路径")
    
    return file_path


def build_report_info(file_path: Path) -> Dict[str, Any]:
    """构建报告信息字典"""
    stat = file_path.stat()
    return {
        "id": file_path.stem,
        "name": file_path.name,
        "size": stat.st_size,
        "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "download_url": f"/api/reports/download/{file_path.name}"
    }


@router.get("/list", response_model=APIResponse)
async def list_reports() -> APIResponse:
    """获取报告列表"""
    ensure_reports_dir()
    
    reports = []
    for ext in REPORT_EXTENSIONS:
        for file_path in REPORTS_DIR.glob(ext):
            reports.append(build_report_info(file_path))
    
    try:
        from TOSKill.tools.report.report_manager import get_report_manager
        rm = get_report_manager()
        mapping_reports = rm.get_all_reports()
        
        for mp in mapping_reports:
            existing = next((r for r in reports if r["id"] == mp.get("report_id")), None)
            if not existing and mp.get("report_file"):
                rp = REPORTS_DIR / mp.get("report_file")
                if rp.exists():
                    reports.append({
                        "id": mp.get("report_id", ""),
                        "name": mp.get("report_file", ""),
                        "session_id": mp.get("session_id", ""),
                        "target": mp.get("target", ""),
                        "created_at": mp.get("created_at", ""),
                        "download_url": mp.get("download_url", "")
                    })
    except Exception as e:
        logger.warning(f"加载映射报告失败: {e}")
    
    reports.sort(key=lambda x: x.get("modified_at") or x.get("created_at") or "", reverse=True)
    
    return APIResponse(data={"reports": reports, "total": len(reports)})


@router.get("/session/{session_id}", response_model=APIResponse)
async def get_report_by_session(session_id: str) -> APIResponse:
    """根据会话ID获取报告信息"""
    try:
        from TOSKill.tools.report.report_manager import get_report_manager
        rm = get_report_manager()
        report_info = rm.get_report_by_session(session_id)
        
        if not report_info:
            raise HTTPException(status_code=404, detail=f"会话 {session_id} 的报告不存在")
        
        return APIResponse(data={"report": report_info})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取报告失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/download/{filename}")
async def download_report(filename: str):
    """下载报告文件"""
    file_path = validate_report_path(filename)
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/octet-stream"
    )


@router.delete("/{filename}", response_model=APIResponse)
async def delete_report(filename: str) -> APIResponse:
    """删除报告文件"""
    file_path = validate_report_path(filename)
    
    try:
        file_path.unlink()
        return APIResponse(message=f"报告 {filename} 已删除")
    except Exception as e:
        logger.error(f"删除报告失败: {e}")
        raise HTTPException(status_code=500, detail=f"删除失败: {str(e)}")


@router.delete("/session/{session_id}", response_model=APIResponse)
async def delete_report_by_session(session_id: str) -> APIResponse:
    """根据会话ID删除报告"""
    try:
        from TOSKill.tools.report.report_manager import get_report_manager
        rm = get_report_manager()
        
        success = rm.delete_report(session_id)
        
        if success:
            return APIResponse(message=f"会话 {session_id} 的报告已删除")
        else:
            raise HTTPException(status_code=404, detail=f"会话 {session_id} 的报告不存在")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除报告失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{filename}/content", response_model=APIResponse)
async def get_report_content(filename: str) -> APIResponse:
    """获取报告内容"""
    file_path = validate_report_path(filename)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return APIResponse(data={"filename": filename, "content": content})
    except Exception as e:
        logger.error(f"读取报告失败: {e}")
        raise HTTPException(status_code=500, detail=f"读取失败: {str(e)}")


@router.get("/{filename}/preview", response_model=APIResponse)
async def preview_report(filename: str) -> APIResponse:
    """预览报告（返回内容+统计信息）"""
    file_path = validate_report_path(filename)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        is_html = filename.endswith('.html')
        
        preview_data = {
            "filename": filename,
            "is_html": is_html,
            "content": content,
            "size": file_path.stat().st_size,
            "created_at": datetime.fromtimestamp(file_path.stat().st_ctime).isoformat(),
            "download_url": f"/api/reports/download/{filename}"
        }
        
        return APIResponse(data=preview_data)
    except Exception as e:
        logger.error(f"预览报告失败: {e}")
        raise HTTPException(status_code=500, detail=f"预览失败: {str(e)}")


@router.get("/stats/summary", response_model=APIResponse)
async def get_report_stats() -> APIResponse:
    """获取报告统计摘要"""
    ensure_reports_dir()
    
    reports = []
    total_size = 0
    formats = {}
    
    for ext in REPORT_EXTENSIONS:
        for file_path in REPORTS_DIR.glob(ext):
            info = build_report_info(file_path)
            reports.append(info)
            total_size += info["size"]
            fmt = file_path.suffix.lower().replace(".", "")
            formats[fmt] = formats.get(fmt, 0) + 1
    
    try:
        from TOSKill.tools.report.report_manager import get_report_manager
        rm = get_report_manager()
        mapping_count = len(rm.get_all_reports())
    except Exception:
        mapping_count = 0
    
    return APIResponse(data={
        "total_reports": len(reports),
        "total_size": total_size,
        "total_size_formatted": f"{total_size / 1024:.1f} KB" if total_size < 1024 * 1024 else f"{total_size / (1024 * 1024):.1f} MB",
        "formats": formats,
        "mapping_entries": mapping_count,
        "reports": reports[:5]
    })
