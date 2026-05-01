"""
脚本安全审查模块
对上传脚本和AI生成脚本进行安全检测，防止恶意代码执行
"""
import ast
import re
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

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
