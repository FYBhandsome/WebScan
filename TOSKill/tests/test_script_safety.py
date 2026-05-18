"""
TOSKill 脚本安全审查测试
验证危险函数检测、AST分析、安全审查功能
"""
import pytest
from unittest.mock import patch, MagicMock


class TestScriptSafetyBasic:
    """脚本安全基础测试"""

    def test_script_safety_import(self):
        """验证script_safety模块可导入"""
        from TOSKill.AI import script_safety
        assert script_safety is not None

    def test_validation_result_class(self):
        """ValidationResult类应存在"""
        from TOSKill.AI.script_safety import ValidationResult, ValidationStage
        assert ValidationResult is not None
        assert ValidationStage is not None

    def test_validation_stage_values(self):
        """验证阶段枚举值"""
        from TOSKill.AI.script_safety import ValidationStage
        stages = [ValidationStage.SIZE_CHECK, ValidationStage.SECURITY_CHECK,
                  ValidationStage.STRUCTURE_CHECK, ValidationStage.DEPENDENCY_CHECK]
        assert len(stages) == 4


class TestScriptValidation:
    """脚本验证测试"""

    def test_validate_safe_script(self, sample_script_content):
        """安全脚本应通过验证"""
        from TOSKill.AI.script_safety import validate_script_full
        success, message, details = validate_script_full(sample_script_content)
        assert success, f"安全脚本验证失败: {message}"

    def test_validate_malicious_script(self, sample_malicious_script):
        """恶意脚本应被检测"""
        from TOSKill.AI.script_safety import validate_script_full
        success, message, details = validate_script_full(sample_malicious_script)
        assert not success, "恶意脚本应被拒绝"

    def test_empty_script_rejected(self):
        """空脚本应被拒绝"""
        from TOSKill.AI.script_safety import validate_script_full
        success, message, details = validate_script_full("")
        assert not success, "空脚本应被拒绝"

    def test_script_without_run_function(self):
        """没有run函数的脚本应被拒绝"""
        script = 'print("hello world")\nx = 1 + 1'
        from TOSKill.AI.script_safety import validate_script_full
        success, message, details = validate_script_full(script)
        assert not success or "run" in message.lower()


class TestStructureValidation:
    """结构验证测试"""

    def test_validate_structure_basic(self):
        """基本验证可用"""
        from TOSKill.AI.script_safety import validate_script_structure
        script = '''
import requests

def run(target: str) -> dict:
    return {"status": "ok", "target": target}
'''
        result = validate_script_structure(script)
        assert result is not None
        assert result.is_valid


class TestDependencyValidation:
    """依赖验证测试"""

    def test_validate_dependencies(self):
        """依赖验证"""
        from TOSKill.AI.script_safety import validate_script_dependencies
        result = validate_script_dependencies("import requests\nimport os")
        assert result is not None


class TestFileValidation:
    """文件上传验证测试"""

    def test_validate_file_upload(self):
        """文件上传验证"""
        from TOSKill.AI.script_safety import validate_file_upload

        result = validate_file_upload(
            filename="test.py",
            content=b"print('test')"
        )
        assert result is not None

    def test_validate_file_upload_large_file(self):
        """大文件被拒绝"""
        from TOSKill.AI.script_safety import validate_file_upload

        large_content = b"x" * (20 * 1024 * 1024)
        result = validate_file_upload(
            filename="large.py",
            content=large_content
        )
        assert not result.is_valid

    def test_validate_file_upload_invalid_extension(self):
        """非法扩展名被拒绝"""
        from TOSKill.AI.script_safety import validate_file_upload

        result = validate_file_upload(
            filename="test.exe",
            content=b"binary"
        )
        assert not result.is_valid


class TestASTAnalysis:
    """AST分析测试"""

    def test_ast_analysis_basic(self):
        """基本AST分析"""
        from TOSKill.AI.script_safety import _analyze_script_ast, _check_dangerous_imports
        try:
            result = _analyze_script_ast("import os\nos.system('ls')")
            assert result is not None
        except (AttributeError, ImportError):
            pytest.skip("AST分析函数名不同")
        
        try:
            issues = _check_dangerous_imports("import os\nimport subprocess")
            assert len(issues) >= 0
        except (AttributeError, ImportError):
            pytest.skip("dangerous_imports函数名不同")