"""
报告下载API

提供报告列表查询和文件下载功能
"""
import os
import logging
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

REPORTS_DIR = Path("reports")


def ensure_reports_dir():
    """确保报告目录存在"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


@router.get("/list")
async def list_reports() -> Dict[str, Any]:
    """获取报告列表"""
    ensure_reports_dir()
    
    reports = []
    
    for file_path in REPORTS_DIR.glob("*.md"):
        stat = file_path.stat()
        reports.append({
            "id": file_path.stem,
            "name": file_path.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "download_url": f"/api/reports/download/{file_path.name}"
        })
    
    for file_path in REPORTS_DIR.glob("*.html"):
        stat = file_path.stat()
        reports.append({
            "id": file_path.stem,
            "name": file_path.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "download_url": f"/api/reports/download/{file_path.name}"
        })
    
    reports.sort(key=lambda x: x["modified_at"], reverse=True)
    
    return {
        "success": True,
        "reports": reports,
        "total": len(reports)
    }


@router.get("/download/{filename}")
async def download_report(filename: str):
    """下载报告文件"""
    ensure_reports_dir()
    
    file_path = REPORTS_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="报告文件不存在")
    
    if not str(file_path.resolve()).startswith(str(REPORTS_DIR.resolve())):
        raise HTTPException(status_code=403, detail="非法文件路径")
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/octet-stream"
    )


@router.delete("/{filename}")
async def delete_report(filename: str):
    """删除报告文件"""
    ensure_reports_dir()
    
    file_path = REPORTS_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="报告文件不存在")
    
    if not str(file_path.resolve()).startswith(str(REPORTS_DIR.resolve())):
        raise HTTPException(status_code=403, detail="非法文件路径")
    
    try:
        file_path.unlink()
        return {
            "success": True,
            "message": f"报告 {filename} 已删除"
        }
    except Exception as e:
        logger.error(f"删除报告失败: {e}")
        raise HTTPException(status_code=500, detail=f"删除失败: {str(e)}")


@router.get("/{filename}/content")
async def get_report_content(filename: str):
    """获取报告内容"""
    ensure_reports_dir()
    
    file_path = REPORTS_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="报告文件不存在")
    
    if not str(file_path.resolve()).startswith(str(REPORTS_DIR.resolve())):
        raise HTTPException(status_code=403, detail="非法文件路径")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return {
            "success": True,
            "filename": filename,
            "content": content
        }
    except Exception as e:
        logger.error(f"读取报告失败: {e}")
        raise HTTPException(status_code=500, detail=f"读取失败: {str(e)}")
