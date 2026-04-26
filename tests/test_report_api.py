"""
报告API测试用例

测试报告列表、下载、删除和内容获取功能
"""
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from fastapi.testclient import TestClient


class TestReportPathValidation:
    """报告路径验证测试"""
    
    def test_validate_existing_file(self):
        """测试验证存在的文件"""
        from TOSKill.api.report import validate_report_path, REPORTS_DIR
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("test content")
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import validate_report_path as validate
                result = validate("test.md")
                assert result == test_file
    
    def test_validate_nonexistent_file_raises_404(self):
        """测试验证不存在的文件抛出404"""
        from TOSKill.api.report import validate_report_path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import validate_report_path as validate
                
                with pytest.raises(HTTPException) as exc_info:
                    validate("nonexistent.md")
                
                assert exc_info.value.status_code == 404
    
    def test_validate_path_traversal_raises_403(self):
        """测试路径遍历攻击抛出403"""
        with tempfile.TemporaryDirectory() as tmpdir:
            parent_dir = Path(tmpdir).parent
            test_file = parent_dir / "secret.txt"
            test_file.write_text("secret")
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import validate_report_path as validate
                
                with pytest.raises(HTTPException) as exc_info:
                    validate("../secret.txt")
                
                assert exc_info.value.status_code == 403


class TestBuildReportInfo:
    """报告信息构建测试"""
    
    def test_build_report_info_structure(self):
        """测试报告信息结构"""
        from TOSKill.api.report import build_report_info
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test_report.md"
            test_file.write_text("# Test Report")
            
            info = build_report_info(test_file)
            
            assert info["id"] == "test_report"
            assert info["name"] == "test_report.md"
            assert info["size"] > 0
            assert "created_at" in info
            assert "modified_at" in info
            assert "download_url" in info


class TestListReports:
    """报告列表测试"""
    
    @pytest.mark.asyncio
    async def test_list_reports_empty(self):
        """测试空报告列表"""
        from TOSKill.api.report import list_reports
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import list_reports as list_reports_func
                
                result = await list_reports_func()
                
                assert result["success"] is True
                assert result["reports"] == []
                assert result["total"] == 0
    
    @pytest.mark.asyncio
    async def test_list_reports_with_files(self):
        """测试包含文件的报告列表"""
        from TOSKill.api.report import list_reports
        
        with tempfile.TemporaryDirectory() as tmpdir:
            md_file = Path(tmpdir) / "report1.md"
            html_file = Path(tmpdir) / "report2.html"
            md_file.write_text("# Report 1")
            html_file.write_text("<html></html>")
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import list_reports as list_reports_func
                
                result = await list_reports_func()
                
                assert result["success"] is True
                assert result["total"] == 2
                assert len(result["reports"]) == 2
    
    @pytest.mark.asyncio
    async def test_list_reports_sorted_by_modified_time(self):
        """测试报告按修改时间排序"""
        import time
        
        from TOSKill.api.report import list_reports
        
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "older.md"
            file2 = Path(tmpdir) / "newer.md"
            
            file1.write_text("older")
            time.sleep(0.1)
            file2.write_text("newer")
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import list_reports as list_reports_func
                
                result = await list_reports_func()
                
                assert result["reports"][0]["name"] == "newer.md"
                assert result["reports"][1]["name"] == "older.md"


class TestDownloadReport:
    """报告下载测试"""
    
    @pytest.mark.asyncio
    async def test_download_existing_report(self):
        """测试下载存在的报告"""
        from TOSKill.api.report import download_report
        from fastapi.responses import FileResponse
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("# Test Report")
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import download_report as download_func
                
                result = await download_func("test.md")
                
                assert isinstance(result, FileResponse)
    
    @pytest.mark.asyncio
    async def test_download_nonexistent_report(self):
        """测试下载不存在的报告"""
        from TOSKill.api.report import download_report
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import download_report as download_func
                
                with pytest.raises(HTTPException) as exc_info:
                    await download_func("nonexistent.md")
                
                assert exc_info.value.status_code == 404


class TestDeleteReport:
    """报告删除测试"""
    
    @pytest.mark.asyncio
    async def test_delete_existing_report(self):
        """测试删除存在的报告"""
        from TOSKill.api.report import delete_report
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("# Test")
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import delete_report as delete_func
                
                result = await delete_func("test.md")
                
                assert result["success"] is True
                assert not test_file.exists()
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_report(self):
        """测试删除不存在的报告"""
        from TOSKill.api.report import delete_report
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import delete_report as delete_func
                
                with pytest.raises(HTTPException) as exc_info:
                    await delete_func("nonexistent.md")
                
                assert exc_info.value.status_code == 404


class TestGetReportContent:
    """报告内容获取测试"""
    
    @pytest.mark.asyncio
    async def test_get_content_existing_report(self):
        """测试获取存在报告的内容"""
        from TOSKill.api.report import get_report_content
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.md"
            test_content = "# Test Report\n\nThis is a test."
            test_file.write_text(test_content, encoding='utf-8')
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import get_report_content as get_content_func
                
                result = await get_content_func("test.md")
                
                assert result["success"] is True
                assert result["filename"] == "test.md"
                assert result["content"] == test_content
    
    @pytest.mark.asyncio
    async def test_get_content_nonexistent_report(self):
        """测试获取不存在报告的内容"""
        from TOSKill.api.report import get_report_content
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import get_report_content as get_content_func
                
                with pytest.raises(HTTPException) as exc_info:
                    await get_content_func("nonexistent.md")
                
                assert exc_info.value.status_code == 404
    
    @pytest.mark.asyncio
    async def test_get_content_with_chinese(self):
        """测试获取包含中文的报告内容"""
        from TOSKill.api.report import get_report_content
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "chinese.md"
            test_content = "# 测试报告\n\n这是中文内容。"
            test_file.write_text(test_content, encoding='utf-8')
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import get_report_content as get_content_func
                
                result = await get_content_func("chinese.md")
                
                assert result["content"] == test_content


class TestReportExtensions:
    """报告扩展名测试"""
    
    def test_supported_extensions(self):
        """测试支持的扩展名"""
        from TOSKill.api.report import REPORT_EXTENSIONS
        
        assert "*.md" in REPORT_EXTENSIONS
        assert "*.html" in REPORT_EXTENSIONS
    
    @pytest.mark.asyncio
    async def test_only_supported_extensions_listed(self):
        """测试只列出支持的扩展名"""
        from TOSKill.api.report import list_reports
        
        with tempfile.TemporaryDirectory() as tmpdir:
            md_file = Path(tmpdir) / "report.md"
            html_file = Path(tmpdir) / "report.html"
            txt_file = Path(tmpdir) / "report.txt"
            
            md_file.write_text("md")
            html_file.write_text("html")
            txt_file.write_text("txt")
            
            with patch('TOSKill.api.report.REPORTS_DIR', Path(tmpdir)):
                from TOSKill.api.report import list_reports as list_reports_func
                
                result = await list_reports_func()
                
                assert result["total"] == 2
                filenames = [r["name"] for r in result["reports"]]
                assert "report.md" in filenames
                assert "report.html" in filenames
                assert "report.txt" not in filenames
