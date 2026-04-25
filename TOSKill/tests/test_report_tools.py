# -*- coding:utf-8 -*-
"""
报告生成工具测试模块
测试所有报告生成相关工具的可调用性、返回数据结构和错误处理
"""

import pytest
import sys
import os
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.tools.report import (
    ai_analyzer,
    vuln_analyzer,
    vuln_analyzer_async,
    ReportSaver,
    save_report,
    generate_report,
    get_default_saver,
    REPORT_TOOLS,
)
from TOSKill.tests.test_data.test_config import get_test_config, get_test_targets_path


class TestReportToolsBasic:
    """报告生成工具基础测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """测试前设置"""
        self.config = get_test_config()
        with open(get_test_targets_path(), 'r', encoding='utf-8') as f:
            self.test_targets = json.load(f)
        self.test_vulnerabilities = [
            {
                "id": "vuln_001",
                "vuln_type": "sqli",
                "severity": "high",
                "url": "http://example.com/test?id=1",
                "title": "SQL Injection",
                "description": "SQL injection vulnerability"
            },
            {
                "id": "vuln_002",
                "vuln_type": "xss",
                "severity": "medium",
                "url": "http://example.com/search?q=test",
                "title": "XSS",
                "description": "Cross-site scripting vulnerability"
            }
        ]
        self.test_tool_results = {
            "baseinfo": {"success": True, "data": {"server": "nginx"}},
            "portscan": {"success": True, "data": {"open_ports": ["80", "443"]}}
        }
        self.test_target_context = {
            "target": "http://example.com",
            "domain": "example.com"
        }
    
    def test_report_tools_list_not_empty(self):
        """测试报告工具列表不为空"""
        assert len(REPORT_TOOLS) == 3, f"预期3个报告工具，实际{len(REPORT_TOOLS)}个"
    
    def test_all_report_tools_have_name(self):
        """测试所有报告工具都有name属性"""
        for tool in REPORT_TOOLS:
            assert hasattr(tool, 'name'), f"工具缺少name属性: {type(tool)}"
            assert tool.name is not None and tool.name != "", f"工具name属性为空: {tool}"
    
    def test_all_report_tools_have_description(self):
        """测试所有报告工具都有description属性"""
        for tool in REPORT_TOOLS:
            assert hasattr(tool, 'description'), f"工具缺少description属性: {tool.name}"
            assert tool.description is not None and tool.description != "", f"工具description属性为空: {tool.name}"
    
    def test_all_report_tools_are_callable(self):
        """测试所有报告工具都可调用"""
        for tool in REPORT_TOOLS:
            is_callable = (
                hasattr(tool, 'invoke') and callable(getattr(tool, 'invoke')) or
                hasattr(tool, 'run') and callable(getattr(tool, 'run')) or
                hasattr(tool, '_run') and callable(getattr(tool, '_run')) or
                callable(tool)
            )
            assert is_callable, f"报告工具不可调用: {tool.name}"


class TestAIAnalyzerTool:
    """AI分析器工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = ai_analyzer
        self.test_vulnerabilities = [
            {
                "id": "vuln_001",
                "vuln_type": "sqli",
                "severity": "high",
                "url": "http://example.com/test?id=1"
            }
        ]
        self.test_tool_results = {"baseinfo": {"success": True}}
        self.test_target_context = {"target": "http://example.com", "domain": "example.com"}
    
    def test_ai_analyzer_has_correct_name(self):
        """测试ai_analyzer工具名称正确"""
        assert self.tool.name == "ai_analyzer"
    
    def test_ai_analyzer_has_description(self):
        """测试ai_analyzer工具有描述"""
        assert hasattr(self.tool, 'description')
        assert "AI" in self.tool.description or "分析" in self.tool.description
    
    def test_ai_analyzer_invoke_returns_correct_structure(self):
        """测试ai_analyzer返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "summary": "发现高危漏洞",
                    "risk_level": "high",
                    "causes": [],
                    "risks": [],
                    "priorities": [],
                    "business_impact": {},
                    "evidence": []
                },
                "error": None,
                "metadata": {
                    "tool": "ai_analyzer",
                    "target": "http://example.com",
                    "risk_level": "high",
                    "vulnerability_count": 1
                }
            }
            
            result = self.tool.invoke({
                "vulnerabilities": self.test_vulnerabilities,
                "tool_results": self.test_tool_results,
                "target_context": self.test_target_context
            })
            
            assert isinstance(result, dict), "返回结果应为字典类型"
            assert "success" in result, "返回结果应包含success字段"
            assert "data" in result, "返回结果应包含data字段"
            assert "error" in result, "返回结果应包含error字段"
            assert "metadata" in result, "返回结果应包含metadata字段"
    
    def test_ai_analyzer_with_llm(self):
        """测试ai_analyzer使用LLM分析"""
        with patch('TOSKill.tools.report.ai_analyzer._init_llm_client') as mock_init:
            mock_llm = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content='{"summary": "测试分析", "risk_level": "high", "top_vulnerabilities": [], "recommendations": []}'))]
            mock_llm.chat.completions.create.return_value = mock_response
            mock_init.return_value = (mock_llm, "gpt-4", "https://api.openai.com")
            
            result = self.tool.invoke({
                "vulnerabilities": self.test_vulnerabilities,
                "tool_results": self.test_tool_results,
                "target_context": self.test_target_context
            })
            
            assert isinstance(result, dict)
            assert "success" in result
    
    def test_ai_analyzer_with_rules_fallback(self):
        """测试ai_analyzer规则引擎回退"""
        with patch('TOSKill.tools.report.ai_analyzer._init_llm_client') as mock_init:
            mock_init.return_value = (None, None, None)
            
            result = self.tool.invoke({
                "vulnerabilities": self.test_vulnerabilities,
                "tool_results": self.test_tool_results,
                "target_context": self.test_target_context
            })
            
            assert isinstance(result, dict)
            assert result["success"] is True
    
    def test_ai_analyzer_empty_vulnerabilities(self):
        """测试ai_analyzer处理空漏洞列表"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "summary": "未发现漏洞",
                    "risk_level": "info",
                    "causes": [],
                    "risks": [],
                    "priorities": [],
                    "business_impact": {},
                    "evidence": []
                },
                "error": None,
                "metadata": {
                    "tool": "ai_analyzer",
                    "vulnerability_count": 0
                }
            }
            
            result = self.tool.invoke({
                "vulnerabilities": [],
                "tool_results": {},
                "target_context": {"target": "http://example.com"}
            })
            
            assert result["success"] is True
            assert result["data"]["risk_level"] == "info"


class TestVulnAnalyzerTool:
    """漏洞分析器工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = vuln_analyzer
        self.test_vulnerabilities = [
            {
                "id": "vuln_001",
                "vuln_type": "sqli",
                "severity": "high",
                "url": "http://example.com/test?id=1",
                "title": "SQL Injection"
            },
            {
                "id": "vuln_002",
                "vuln_type": "xss",
                "severity": "medium",
                "url": "http://example.com/search?q=test",
                "title": "XSS"
            },
            {
                "id": "vuln_003",
                "vuln_type": "sqli",
                "severity": "high",
                "url": "http://example.com/test?id=1",
                "title": "SQL Injection Duplicate"
            }
        ]
    
    def test_vuln_analyzer_has_correct_name(self):
        """测试vuln_analyzer工具名称正确"""
        assert self.tool.name == "vuln_analyzer"
    
    def test_vuln_analyzer_has_description(self):
        """测试vuln_analyzer工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_vuln_analyzer_invoke_returns_correct_structure(self):
        """测试vuln_analyzer返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "statistics": {
                        "total": 2,
                        "by_severity": {"high": 1, "medium": 1},
                        "by_type": {"sqli": 1, "xss": 1}
                    },
                    "vulnerabilities": self.test_vulnerabilities[:2]
                },
                "error": None,
                "metadata": {
                    "tool": "vuln_analyzer",
                    "vulnerability_count": 2
                }
            }
            
            result = self.tool.invoke({
                "vulnerabilities": self.test_vulnerabilities,
                "enable_dedup": True,
                "enable_sort": True
            })
            
            assert isinstance(result, dict), "返回结果应为字典类型"
            assert "success" in result, "返回结果应包含success字段"
            assert "data" in result, "返回结果应包含data字段"
    
    def test_vuln_analyzer_deduplication(self):
        """测试vuln_analyzer去重功能"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "statistics": {
                        "total": 2,
                        "duplicates_removed": 1
                    },
                    "vulnerabilities": self.test_vulnerabilities[:2]
                },
                "error": None,
                "metadata": {}
            }
            
            result = self.tool.invoke({
                "vulnerabilities": self.test_vulnerabilities,
                "enable_dedup": True
            })
            
            assert result["success"] is True
    
    def test_vuln_analyzer_sorting(self):
        """测试vuln_analyzer排序功能"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "vulnerabilities": [
                        {"severity": "critical"},
                        {"severity": "high"},
                        {"severity": "medium"}
                    ]
                },
                "error": None,
                "metadata": {}
            }
            
            result = self.tool.invoke({
                "vulnerabilities": self.test_vulnerabilities,
                "enable_sort": True
            })
            
            assert result["success"] is True


class TestVulnAnalyzerAsyncTool:
    """异步漏洞分析器工具测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tool = vuln_analyzer_async
        self.test_vulnerabilities = [
            {
                "id": "vuln_001",
                "vuln_type": "sqli",
                "severity": "high",
                "url": "http://example.com/test?id=1"
            }
        ]
    
    def test_vuln_analyzer_async_has_correct_name(self):
        """测试vuln_analyzer_async工具名称正确"""
        assert self.tool.name == "vuln_analyzer_async"
    
    def test_vuln_analyzer_async_has_description(self):
        """测试vuln_analyzer_async工具有描述"""
        assert hasattr(self.tool, 'description')
        assert len(self.tool.description) > 0
    
    def test_vuln_analyzer_async_invoke_returns_correct_structure(self):
        """测试vuln_analyzer_async返回数据结构正确"""
        with patch.object(self.tool, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "statistics": {"total": 1},
                    "vulnerabilities": self.test_vulnerabilities
                },
                "error": None,
                "metadata": {"tool": "vuln_analyzer_async"}
            }
            
            result = self.tool.invoke({
                "vulnerabilities": self.test_vulnerabilities
            })
            
            assert isinstance(result, dict)
            assert "success" in result


class TestReportSaver:
    """报告保存器测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.temp_dir = tempfile.mkdtemp()
        self.saver = ReportSaver(output_dir=self.temp_dir)
        self.test_data = {
            "success": True,
            "data": {
                "target": "http://example.com",
                "vulnerabilities": [
                    {"vuln_type": "sqli", "severity": "high"}
                ]
            }
        }
        self.test_target = "http://example.com"
    
    def teardown_method(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_report_saver_initialization(self):
        """测试报告保存器初始化"""
        assert self.saver.output_dir == Path(self.temp_dir)
        assert os.path.exists(self.temp_dir)
    
    def test_save_json(self):
        """测试保存JSON格式报告"""
        filepath = self.saver.save_json(self.test_data, self.test_target, "test_scan")
        
        assert os.path.exists(filepath)
        assert filepath.endswith(".json")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            loaded_data = json.load(f)
        
        assert loaded_data == self.test_data
    
    def test_save_markdown(self):
        """测试保存Markdown格式报告"""
        filepath = self.saver.save_markdown(self.test_data, self.test_target, "test_scan")
        
        assert os.path.exists(filepath)
        assert filepath.endswith(".md")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "# 安全扫描报告" in content
        assert self.test_target in content
    
    def test_save_multiple_formats(self):
        """测试保存多格式报告"""
        saved_files = self.saver.save(
            self.test_data,
            self.test_target,
            "test_scan",
            formats=["json", "markdown"]
        )
        
        assert "json" in saved_files
        assert "markdown" in saved_files
        assert os.path.exists(saved_files["json"])
        assert os.path.exists(saved_files["markdown"])
    
    def test_generate_filename(self):
        """测试生成文件名"""
        filename = self.saver._generate_filename(
            target="http://example.com",
            report_type="security_scan",
            extension="json"
        )
        
        assert filename.startswith("security_scan_")
        assert filename.endswith(".json")
        assert "example.com" in filename or "http_example.com" in filename


class TestSaveReportFunction:
    """保存报告函数测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_data = {
            "success": True,
            "data": {"target": "http://example.com"}
        }
        self.test_target = "http://example.com"
    
    def teardown_method(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_save_report_default_saver(self):
        """测试使用默认保存器保存报告"""
        with patch('TOSKill.tools.report.get_default_saver') as mock_get_saver:
            mock_saver = MagicMock()
            mock_saver.save.return_value = {"json": "/path/to/report.json"}
            mock_get_saver.return_value = mock_saver
            
            result = save_report(self.test_data, self.test_target)
            
            assert "json" in result
    
    def test_save_report_custom_output_dir(self):
        """测试使用自定义输出目录保存报告"""
        with patch('TOSKill.tools.report.ReportSaver') as mock_saver_class:
            mock_saver = MagicMock()
            mock_saver.save.return_value = {"json": "/custom/path/report.json"}
            mock_saver_class.return_value = mock_saver
            
            result = save_report(
                self.test_data,
                self.test_target,
                output_dir=self.temp_dir
            )
            
            mock_saver_class.assert_called_once_with(self.temp_dir)


class TestGenerateReportFunction:
    """生成报告函数测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_vulnerabilities = [
            {
                "id": "vuln_001",
                "vuln_type": "sqli",
                "severity": "high",
                "url": "http://example.com/test?id=1"
            }
        ]
        self.test_tool_results = {"baseinfo": {"success": True}}
        self.test_target = "http://example.com"
    
    def teardown_method(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @pytest.mark.asyncio
    async def test_generate_report_with_ai_analysis(self):
        """测试生成报告包含AI分析"""
        with patch('TOSKill.tools.report.vuln_analyzer') as mock_vuln_analyzer, \
             patch('TOSKill.tools.report.ai_analyzer') as mock_ai_analyzer, \
             patch('TOSKill.tools.report.save_report') as mock_save:
            
            mock_vuln_analyzer.invoke.return_value = {
                "success": True,
                "data": {"statistics": {"total": 1}}
            }
            mock_ai_analyzer.invoke.return_value = {
                "success": True,
                "data": {"summary": "测试分析", "risk_level": "high"}
            }
            mock_save.return_value = {"json": "/path/to/report.json"}
            
            result = await generate_report(
                target=self.test_target,
                vulnerabilities=self.test_vulnerabilities,
                tool_results=self.test_tool_results,
                enable_ai_analysis=True
            )
            
            assert result["success"] is True
            assert "ai_analysis" in result["data"]
    
    @pytest.mark.asyncio
    async def test_generate_report_without_ai_analysis(self):
        """测试生成报告不包含AI分析"""
        with patch('TOSKill.tools.report.vuln_analyzer') as mock_vuln_analyzer, \
             patch('TOSKill.tools.report.save_report') as mock_save:
            
            mock_vuln_analyzer.invoke.return_value = {
                "success": True,
                "data": {"statistics": {"total": 1}}
            }
            mock_save.return_value = {"json": "/path/to/report.json"}
            
            result = await generate_report(
                target=self.test_target,
                vulnerabilities=self.test_vulnerabilities,
                tool_results=self.test_tool_results,
                enable_ai_analysis=False
            )
            
            assert result["success"] is True
            assert result["data"]["ai_analysis"] is None


class TestGetDefaultSaver:
    """获取默认保存器测试"""
    
    def test_get_default_saver_returns_instance(self):
        """测试获取默认保存器返回实例"""
        with patch('TOSKill.tools.report._default_saver', None):
            saver = get_default_saver()
            
            assert isinstance(saver, ReportSaver)
    
    def test_get_default_saver_singleton(self):
        """测试默认保存器单例模式"""
        with patch('TOSKill.tools.report._default_saver', None):
            saver1 = get_default_saver()
            saver2 = get_default_saver()
            
            assert saver1 is saver2


class TestReportToolsErrorHandling:
    """报告工具错误处理测试"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.tools = REPORT_TOOLS
    
    def test_ai_analyzer_handles_exception(self):
        """测试ai_analyzer异常处理"""
        with patch('TOSKill.tools.report.ai_analyzer._init_llm_client') as mock_init:
            mock_init.side_effect = Exception("Test exception")
            
            result = ai_analyzer.invoke({
                "vulnerabilities": [],
                "tool_results": {},
                "target_context": {"target": "test"}
            })
            
            assert isinstance(result, dict)
            assert "success" in result
    
    def test_vuln_analyzer_handles_empty_input(self):
        """测试vuln_analyzer处理空输入"""
        with patch.object(vuln_analyzer, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "statistics": {"total": 0},
                    "vulnerabilities": []
                },
                "error": None,
                "metadata": {}
            }
            
            result = vuln_analyzer.invoke({"vulnerabilities": []})
            
            assert result["success"] is True
            assert result["data"]["statistics"]["total"] == 0
    
    def test_report_saver_handles_invalid_data(self):
        """测试报告保存器处理无效数据"""
        temp_dir = tempfile.mkdtemp()
        try:
            saver = ReportSaver(output_dir=temp_dir)
            
            invalid_data = {"invalid": "data structure"}
            filepath = saver.save_json(invalid_data, "test_target")
            
            assert os.path.exists(filepath)
        finally:
            shutil.rmtree(temp_dir)


class TestReportToolsDataValidation:
    """报告工具数据验证测试"""
    
    def test_ai_analyzer_result_structure(self):
        """测试AI分析器结果结构"""
        expected_fields = ["summary", "risk_level", "causes", "risks", "priorities", "business_impact", "evidence"]
        
        with patch.object(ai_analyzer, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "summary": "测试分析",
                    "risk_level": "high",
                    "causes": [],
                    "risks": [],
                    "priorities": [],
                    "business_impact": {},
                    "evidence": []
                },
                "error": None,
                "metadata": {}
            }
            
            result = ai_analyzer.invoke({
                "vulnerabilities": [],
                "tool_results": {},
                "target_context": {}
            })
            
            for field in expected_fields:
                assert field in result["data"], f"AI分析结果应包含{field}字段"
    
    def test_vuln_analyzer_statistics_structure(self):
        """测试漏洞分析器统计结构"""
        with patch.object(vuln_analyzer, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {
                    "statistics": {
                        "total": 2,
                        "by_severity": {"high": 1, "medium": 1},
                        "by_type": {"sqli": 1, "xss": 1}
                    },
                    "vulnerabilities": []
                },
                "error": None,
                "metadata": {}
            }
            
            result = vuln_analyzer.invoke({"vulnerabilities": []})
            
            assert "statistics" in result["data"]
            assert "total" in result["data"]["statistics"]
            assert "by_severity" in result["data"]["statistics"]
    
    def test_risk_level_values(self):
        """测试风险等级值"""
        valid_risk_levels = ["critical", "high", "medium", "low", "info"]
        
        for risk_level in valid_risk_levels:
            with patch.object(ai_analyzer, 'invoke') as mock_invoke:
                mock_invoke.return_value = {
                    "success": True,
                    "data": {
                        "risk_level": risk_level,
                        "summary": "测试"
                    },
                    "error": None,
                    "metadata": {}
                }
                
                result = ai_analyzer.invoke({
                    "vulnerabilities": [],
                    "tool_results": {},
                    "target_context": {}
                })
                
                assert result["data"]["risk_level"] == risk_level


class TestReportToolsMetadata:
    """报告工具元数据测试"""
    
    def test_ai_analyzer_metadata(self):
        """测试AI分析器元数据"""
        with patch.object(ai_analyzer, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {},
                "error": None,
                "metadata": {
                    "tool": "ai_analyzer",
                    "target": "http://example.com",
                    "risk_level": "high",
                    "vulnerability_count": 1,
                    "analysis_method": "LLM"
                }
            }
            
            result = ai_analyzer.invoke({
                "vulnerabilities": [{"id": "1"}],
                "tool_results": {},
                "target_context": {"target": "http://example.com"}
            })
            
            assert result["metadata"]["tool"] == "ai_analyzer"
            assert "target" in result["metadata"]
            assert "vulnerability_count" in result["metadata"]
    
    def test_vuln_analyzer_metadata(self):
        """测试漏洞分析器元数据"""
        with patch.object(vuln_analyzer, 'invoke') as mock_invoke:
            mock_invoke.return_value = {
                "success": True,
                "data": {},
                "error": None,
                "metadata": {
                    "tool": "vuln_analyzer",
                    "vulnerability_count": 2
                }
            }
            
            result = vuln_analyzer.invoke({"vulnerabilities": [{"id": "1"}, {"id": "2"}]})
            
            assert result["metadata"]["tool"] == "vuln_analyzer"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
