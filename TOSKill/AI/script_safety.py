"""
脚本安全审查模块
对上传脚本和AI生成脚本进行安全检测，防止恶意代码执行
"""
import os
import ast
import re
import logging
from typing import Tuple, Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ValidationStage(Enum):
    SIZE_CHECK = "size_check"
    SYNTAX_CHECK = "syntax_check"
    SECURITY_CHECK = "security_check"
    STRUCTURE_CHECK = "structure_check"
    DEPENDENCY_CHECK = "dependency_check"

@dataclass
class ValidationResult:
    is_valid: bool
    stage: ValidationStage
    message: str
    details: Dict[str, Any] = None
    
    def to_dict(self) -> Dict:
        return {
            "is_valid": self.is_valid,
            "stage": self.stage.value,
            "message": self.message,
            "details": self.details or {}
        }

DANGEROUS_FUNCTIONS = [
    "os.system",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.check_call",
    "subprocess.check_output",
    "eval(",
    "exec(",
    "compile(",
    "__import__(",
    "shutil.rmtree",
    "shutil.move",
]

DANGEROUS_MODULES = [
    "os",
    "subprocess",
    "shutil",
    "socket",
    "ctypes",
    "signal",
    "multiprocessing",
]

DANGEROUS_FILE_OPS = [
    "open(",
]

MAX_SCRIPT_SIZE_BYTES = 500 * 1024
ALLOWED_EXTENSIONS = [".py"]
ALLOWED_MIME_TYPES = ["text/x-python", "text/plain", "application/x-python-code"]


def sanitize_script_name(name: str) -> Tuple[str, str]:
    """
    安全化脚本文件名，拒绝路径穿越

    Returns:
        (sanitized_name, error_message) — error_message 非空时表示拒绝
    """
    if not name or not name.strip():
        return name, "脚本名称不能为空"

    name = name.strip()

    if len(name) > 64:
        return name, "脚本名称超过64字符"

    if re.search(r'[<>:"/\\|?*]', name):
        return name, f"脚本名称包含非法字符: {name}"

    if ".." in name:
        return name, f"脚本名称包含路径穿越: {name}"

    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        safe = safe.strip('_')
        if not safe:
            return name, f"脚本名称仅含非法字符无法安全化: {name}"
        return safe, ""

    return name, ""


def validate_script_safety(script_content: str) -> Tuple[bool, str]:
    """
    审查脚本内容安全性

    Returns:
        (is_safe, error_message) — is_safe=True 表示安全，False 表示拒绝
    """
    if not script_content or not script_content.strip():
        return False, "脚本内容为空"

    if len(script_content.encode("utf-8")) > MAX_SCRIPT_SIZE_BYTES:
        return False, f"脚本大小超过限制 ({MAX_SCRIPT_SIZE_BYTES // 1024}KB)"

    text_lower = script_content.lower()

    for func in DANGEROUS_FUNCTIONS:
        if func in text_lower:
            return False, f"脚本包含危险函数调用: {func}"

    try:
        tree = ast.parse(script_content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod_name = alias.name.split(".")[0]
                    if mod_name in DANGEROUS_MODULES:
                        return False, f"脚本导入危险模块: {mod_name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod_name = node.module.split(".")[0]
                    if mod_name in DANGEROUS_MODULES:
                        return False, f"脚本导入危险模块: {mod_name}"
    except SyntaxError as e:
        return False, f"脚本语法错误: {e}"

    return True, ""


def validate_script_completeness(script_content: str) -> Tuple[bool, str]:
    """
    验证脚本是否包含必要的入口函数

    Returns:
        (is_complete, error_message)
    """
    try:
        tree = ast.parse(script_content)
        func_names = {
            node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        if "run" in func_names or "scan" in func_names:
            return True, ""
        return False, "脚本缺少 run(target) 或 scan(target) 入口函数"
    except SyntaxError:
        return False, "脚本语法错误，无法解析函数定义"


def extract_code_block(response_text: str) -> str:
    """
    从LLM响应中提取Python代码块，强化版

    Returns:
        str: 提取的代码，失败时返回空字符串
    """
    if not response_text:
        return ""

    code_match = re.search(r'```(?:python)?\s*([\s\S]*?)\s*```', response_text)
    if code_match:
        return code_match.group(1).strip()

    if "def run(" in response_text or "def scan(" in response_text:
        return response_text.strip()

    return ""


def validate_file_upload(filename: str, content: bytes, content_type: str = None) -> ValidationResult:
    """
    验证上传文件的完整流程
    
    Args:
        filename: 文件名
        content: 文件内容（字节）
        content_type: MIME类型
        
    Returns:
        ValidationResult: 验证结果
    """
    if not filename:
        return ValidationResult(
            is_valid=False,
            stage=ValidationStage.SIZE_CHECK,
            message="文件名不能为空"
        )
    
    ext = os.path.splitext(filename.lower())[1] if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return ValidationResult(
            is_valid=False,
            stage=ValidationStage.SIZE_CHECK,
            message=f"不支持的文件类型: {ext}，仅支持: {', '.join(ALLOWED_EXTENSIONS)}",
            details={"allowed_extensions": ALLOWED_EXTENSIONS}
        )
    
    if len(content) > MAX_SCRIPT_SIZE_BYTES:
        return ValidationResult(
            is_valid=False,
            stage=ValidationStage.SIZE_CHECK,
            message=f"文件大小超过限制 ({len(content) // 1024}KB > {MAX_SCRIPT_SIZE_BYTES // 1024}KB)",
            details={"file_size": len(content), "max_size": MAX_SCRIPT_SIZE_BYTES}
        )
    
    if content_type and content_type not in ALLOWED_MIME_TYPES:
        logger.warning(f"可疑的MIME类型: {content_type}")
    
    return ValidationResult(
        is_valid=True,
        stage=ValidationStage.SIZE_CHECK,
        message="文件验证通过"
    )


def validate_script_structure(script_content: str) -> ValidationResult:
    """
    验证脚本结构完整性
    
    检查脚本是否包含必要的入口函数和合理的结构
    
    Returns:
        ValidationResult: 验证结果
    """
    if not script_content or not script_content.strip():
        return ValidationResult(
            is_valid=False,
            stage=ValidationStage.STRUCTURE_CHECK,
            message="脚本内容为空"
        )
    
    try:
        tree = ast.parse(script_content)
    except SyntaxError as e:
        return ValidationResult(
            is_valid=False,
            stage=ValidationStage.SYNTAX_CHECK,
            message=f"脚本语法错误: {e}",
            details={"line": e.lineno, "msg": e.msg}
        )
    
    func_names = set()
    class_names = set()
    imports = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func_names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            class_names.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    
    has_entry = "run" in func_names or "scan" in func_names
    if not has_entry:
        return ValidationResult(
            is_valid=False,
            stage=ValidationStage.STRUCTURE_CHECK,
            message="脚本缺少入口函数 run(target) 或 scan(target)",
            details={"found_functions": list(func_names), "required": ["run", "scan"]}
        )
    
    return ValidationResult(
        is_valid=True,
        stage=ValidationStage.STRUCTURE_CHECK,
        message="脚本结构验证通过",
        details={
            "functions": list(func_names),
            "classes": list(class_names),
            "imports": imports
        }
    )


def validate_script_dependencies(script_content: str) -> ValidationResult:
    """
    验证脚本依赖安全性
    
    检查脚本导入的模块是否安全
    
    Returns:
        ValidationResult: 验证结果
    """
    SAFE_MODULES = {
        "re", "json", "datetime", "time", "math", "random", "string",
        "collections", "itertools", "functools", "typing", "dataclasses",
        "urllib", "httpx", "requests", "aiohttp", "bs4", "lxml",
        "crypto", "hashlib", "base64", "binascii",
        "logging", "pathlib", "tempfile"
    }
    
    try:
        tree = ast.parse(script_content)
    except SyntaxError:
        return ValidationResult(
            is_valid=False,
            stage=ValidationStage.DEPENDENCY_CHECK,
            message="脚本语法错误，无法分析依赖"
        )
    
    imports = []
    warnings = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod_name = alias.name.split(".")[0]
                imports.append(mod_name)
                if mod_name in DANGEROUS_MODULES:
                    return ValidationResult(
                        is_valid=False,
                        stage=ValidationStage.DEPENDENCY_CHECK,
                        message=f"脚本导入危险模块: {mod_name}",
                        details={"dangerous_module": mod_name}
                    )
                if mod_name not in SAFE_MODULES:
                    warnings.append(f"模块 '{mod_name}' 不在安全列表中")
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mod_name = node.module.split(".")[0]
                imports.append(mod_name)
                if mod_name in DANGEROUS_MODULES:
                    return ValidationResult(
                        is_valid=False,
                        stage=ValidationStage.DEPENDENCY_CHECK,
                        message=f"脚本导入危险模块: {mod_name}",
                        details={"dangerous_module": mod_name}
                    )
                if mod_name not in SAFE_MODULES:
                    warnings.append(f"模块 '{mod_name}' 不在安全列表中")
    
    result = ValidationResult(
        is_valid=True,
        stage=ValidationStage.DEPENDENCY_CHECK,
        message="依赖验证通过" + (" (有警告)" if warnings else ""),
        details={"imports": imports, "warnings": warnings}
    )
    
    return result


def validate_script_full(script_content: str, filename: str = None) -> Tuple[bool, str, Dict]:
    """
    完整的脚本验证流程
    
    Args:
        script_content: 脚本内容
        filename: 可选的文件名
        
    Returns:
        (is_valid, message, details)
    """
    results = []
    
    if filename:
        try:
            content_bytes = script_content.encode('utf-8')
            result = validate_file_upload(filename, content_bytes)
            results.append(result)
            if not result.is_valid:
                return False, result.message, result.to_dict()
        except Exception as e:
            return False, f"文件验证失败: {e}", {"error": str(e)}
    
    is_safe, safety_msg = validate_script_safety(script_content)
    if not is_safe:
        result = ValidationResult(
            is_valid=False,
            stage=ValidationStage.SECURITY_CHECK,
            message=safety_msg
        )
        results.append(result)
        return False, safety_msg, result.to_dict()
    
    result = validate_script_structure(script_content)
    results.append(result)
    if not result.is_valid:
        return False, result.message, result.to_dict()
    
    result = validate_script_dependencies(script_content)
    results.append(result)
    
    all_details = {}
    for r in results:
        if r.details:
            all_details.update(r.details)
    
    return True, "脚本验证通过", all_details
