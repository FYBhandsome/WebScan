"""
测试TOSKill脚本生成和AI分析功能

验证：
1. 脚本生成功能
2. 脚本分析功能
3. AI报告分析功能
"""
import asyncio
import sys
import os
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
os.chdir(project_root)

print("=" * 60)
print("测试TOSKill脚本生成和AI分析功能")
print("=" * 60)

print("\n1. 测试脚本分析功能...")
from TOSKill.AI.tools import script_manager

async def test_script_analysis():
    test_script = '''
import requests

def run(target):
    """端口扫描脚本"""
    try:
        response = requests.get(f"{target}:8080", timeout=5)
        if response.status_code == 200:
            return {"success": True, "data": {"port": 8080, "status": "open"}}
        return {"success": False, "data": {}}
    except Exception as e:
        return {"success": False, "error": str(e)}
'''
    
    result = await script_manager.analyze_script_with_ai(test_script)
    print(f"   工具名称: {result.get('tool_name')}")
    print(f"   描述: {result.get('description')}")
    print(f"   类别: {result.get('category')}")
    print(f"   输入类型: {result.get('input_type')}")
    return result

try:
    analysis_result = asyncio.run(test_script_analysis())
    print("   ✅ 脚本分析成功")
except Exception as e:
    print(f"   ❌ 脚本分析失败: {e}")

print("\n2. 测试脚本生成功能...")
async def test_script_generation():
    description = "一个检测网站是否使用HTTPS的脚本"
    script_code = await script_manager.generate_script_with_ai(description)
    
    if script_code:
        print(f"   生成的脚本长度: {len(script_code)} 字符")
        print(f"   脚本预览:\n{script_code[:300]}...")
        return True
    return False

try:
    success = asyncio.run(test_script_generation())
    if success:
        print("   ✅ 脚本生成成功")
    else:
        print("   ⚠️ 脚本生成返回空")
except Exception as e:
    print(f"   ❌ 脚本生成失败: {e}")

print("\n3. 测试AI报告分析功能...")
from TOSKill.tools.report.ai_analyzer import ai_analyzer

test_vulns = [
    {
        "id": "vuln-001",
        "vuln_type": "sqli",
        "severity": "high",
        "url": "https://example.com/api/users?id=1",
        "title": "SQL注入漏洞",
        "description": "在用户查询接口发现SQL注入漏洞"
    },
    {
        "id": "vuln-002",
        "vuln_type": "xss",
        "severity": "medium",
        "url": "https://example.com/search?q=test",
        "title": "反射型XSS",
        "description": "搜索参数存在XSS漏洞"
    }
]

test_context = {
    "target": "https://example.com",
    "domain": "example.com",
    "scan_time": "2026-05-20T12:00:00Z",
    "strategy": "standard"
}

test_results = {
    "baseinfo_scan": {"success": True, "key_findings": ["服务器: nginx", "框架: Django"]},
    "port_scan": {"success": True, "key_findings": ["80: open", "443: open", "8080: open"]}
}

try:
    result = ai_analyzer.invoke({
        "vulnerabilities": test_vulns,
        "tool_results": test_results,
        "target_context": test_context
    })
    
    if result.get("success"):
        data = result.get("data", {})
        print(f"   风险等级: {data.get('risk_level')}")
        print(f"   风险总结: {data.get('summary', '')[:100]}...")
        print(f"   漏洞成因数: {len(data.get('causes', []))}")
        print(f"   利用风险数: {len(data.get('risks', []))}")
        print(f"   修复优先级数: {len(data.get('priorities', []))}")
        print(f"   分析方法: {result.get('metadata', {}).get('analysis_method')}")
        print("   ✅ AI报告分析成功")
    else:
        print(f"   ❌ AI报告分析失败: {result.get('error')}")
except Exception as e:
    print(f"   ❌ AI报告分析异常: {e}")

print("\n" + "=" * 60)
print("测试完成")
print("=" * 60)
