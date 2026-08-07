"""
测试脚本注册到LangGraph功能
"""
import asyncio
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

print("=" * 60)
print("测试脚本注册到LangGraph功能")
print("=" * 60)

from TOSKill.AI.tools import (
    script_manager, TOOL_MAP, ALL_TOOLS, 
    get_all_tool_names, get_tool_by_name
)

print("\n1. 当前工具数量:", len(TOOL_MAP))
print("   当前工具列表:", list(TOOL_MAP.keys())[:5], "...")

test_script = '''
import requests

def run(target: str):
    """检测网站是否使用HTTPS"""
    try:
        if target.startswith("http://"):
            return {"success": True, "data": {"https": False, "message": "网站使用HTTP"}}
        elif target.startswith("https://"):
            return {"success": True, "data": {"https": True, "message": "网站使用HTTPS"}}
        return {"success": False, "error": "无效的URL格式"}
    except Exception as e:
        return {"success": False, "error": str(e)}
'''

print("\n2. 注册测试脚本...")
result = script_manager.register_script_as_tool(
    script_content=test_script,
    script_name="custom_https_check",
    description="检测网站是否使用HTTPS协议",
    category="custom"
)

if result.get("success"):
if result.get("success"): 
    print(f"   [PASS] 脚本注册成功: {result["tool_name"]}")
else:
    print(f"   [FAIL] 脚本注册失败: {result.get("error")}")
print("\n3. 验证工具是否已添加到TOOL_MAP...")
print("   注册后工具数量:", len(TOOL_MAP))
print("   工具 'custom_https_check' 存在:", "custom_https_check" in TOOL_MAP)

if "custom_https_check" in TOOL_MAP:
    tool = get_tool_by_name("custom_https_check")
    print(f"   工具描述: {getattr(tool, 'description', 'N/A')}")
    
    print("\n4. 测试工具执行...")
    try:
        test_result = tool.invoke("https://example.com")
        print(f"   执行结果: {test_result}")
        print("   [PASS] 工具执行成功")
    except Exception as e:
        print(f"   [FAIL] 工具执行失败: {e}")

print("\n5. 检查ALL_TOOLS列表...")
custom_tools = [t for t in ALL_TOOLS if hasattr(t, 'name') and (t.name.startswith('custom_') or t.name.startswith('ai_gen_'))]
print(f"   自定义工具数量: {len(custom_tools)}")
for t in custom_tools:
    print(f"   - {t.name}")

print("\n" + "=" * 60)
print("测试完成")
print("=" * 60)
