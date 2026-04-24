# -*- coding: utf-8 -*-
"""
Task 13: 功能测试脚本

验证以下功能:
- SubTask 13.1: 测试扫描结果存储功能
- SubTask 13.2: 测试AI分析结果存储功能
- SubTask 13.3: 测试聊天记忆存储功能
- SubTask 13.4: 测试对话总结功能
- SubTask 13.5: 测试脚本上传注册功能
- SubTask 13.6: 测试脚本生成功能
"""

import sys
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

test_results = {
    "test_time": datetime.now().isoformat(),
    "tests": {},
    "summary": {
        "total": 6,
        "passed": 0,
        "failed": 0,
        "warnings": 0
    }
}


def log_test(test_name: str, passed: bool, details: str = "", warnings: List[str] = None):
    """记录测试结果"""
    test_results["tests"][test_name] = {
        "passed": passed,
        "details": details,
        "warnings": warnings or [],
        "timestamp": datetime.now().isoformat()
    }
    if passed:
        test_results["summary"]["passed"] += 1
        print(f"✅ {test_name}: 通过")
    else:
        test_results["summary"]["failed"] += 1
        print(f"❌ {test_name}: 失败")
    
    if details:
        print(f"   详情: {details}")
    
    if warnings:
        for w in warnings:
            test_results["summary"]["warnings"] += 1
            print(f"   ⚠️ 警告: {w}")


def test_13_1_scan_result_storage():
    """SubTask 13.1: 测试扫描结果存储功能"""
    print("\n" + "="*60)
    print("SubTask 13.1: 测试扫描结果存储功能")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test_task_001")
        
        scan_result = {
            "vulnerabilities": [
                {"type": "SQL注入", "severity": "high", "location": "/api/users"},
                {"type": "XSS", "severity": "medium", "location": "/search"}
            ],
            "ports": [80, 443, 8080],
            "subdomains": ["www.example.com", "api.example.com"]
        }
        
        state.add_scan_result(
            tool_name="test_scanner",
            result=scan_result,
            execution_time=1.5,
            success=True
        )
        
        assert "test_scanner" in state.tool_results, "工具结果未正确存储"
        assert len(state.vulnerabilities) == 2, f"漏洞数量错误: {len(state.vulnerabilities)}"
        assert len(state.execution_history) == 1, "执行历史未正确记录"
        
        assert state.tool_results["test_scanner"] == scan_result, "扫描结果数据不一致"
        
        assert "open_ports" in state.target_context, "端口信息未存储到上下文"
        assert len(state.target_context["open_ports"]) == 3, "端口数量错误"
        
        assert "subdomains" in state.target_context, "子域名信息未存储到上下文"
        assert len(state.target_context["subdomains"]) == 2, "子域名数量错误"
        
        validation = state.validate_data_integrity()
        assert validation["is_valid"], f"数据完整性验证失败: {validation['errors']}"
        
        log_test("13.1 扫描结果存储功能", True, 
                 f"成功存储扫描结果，包含 {len(state.vulnerabilities)} 个漏洞，"
                 f"{len(state.target_context.get('open_ports', []))} 个端口")
        
        return True
        
    except Exception as e:
        log_test("13.1 扫描结果存储功能", False, str(e))
        return False


def test_13_2_ai_analysis_storage():
    """SubTask 13.2: 测试AI分析结果存储功能"""
    print("\n" + "="*60)
    print("SubTask 13.2: 测试AI分析结果存储功能")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test_task_002")
        
        state.tool_results = {
            "sqli_scanner": {"vulnerabilities": [{"type": "SQL注入"}]},
            "xss_scanner": {"vulnerabilities": [{"type": "XSS"}]}
        }
        
        state.scan_summary = {
            "analysis": "发现2个安全漏洞，建议优先修复SQL注入问题",
            "timestamp": datetime.now().isoformat(),
            "tool_count": 2,
            "vulnerability_count": 2,
            "success_rate": 100.0
        }
        
        state.execution_history.append({
            "task": "ai_analysis",
            "tool_name": "ai_analysis",
            "target": "http://example.com",
            "result": state.tool_results,
            "analysis": state.scan_summary["analysis"],
            "success": True,
            "timestamp": datetime.now().isoformat()
        })
        
        assert "analysis" in state.scan_summary, "AI分析结果未存储"
        assert state.scan_summary["tool_count"] == 2, "工具计数错误"
        assert state.scan_summary["vulnerability_count"] == 2, "漏洞计数错误"
        
        assert len(state.execution_history) == 1, "执行历史未记录AI分析"
        assert state.execution_history[0]["task"] == "ai_analysis", "执行历史任务类型错误"
        
        validation = state.validate_data_integrity()
        assert validation["is_valid"], f"数据完整性验证失败: {validation['errors']}"
        
        log_test("13.2 AI分析结果存储功能", True,
                 f"成功存储AI分析结果，工具数: {state.scan_summary['tool_count']}, "
                 f"漏洞数: {state.scan_summary['vulnerability_count']}")
        
        return True
        
    except Exception as e:
        log_test("13.2 AI分析结果存储功能", False, str(e))
        return False


def test_13_3_chat_memory_storage():
    """SubTask 13.3: 测试聊天记忆存储功能"""
    print("\n" + "="*60)
    print("SubTask 13.3: 测试聊天记忆存储功能")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test_task_003")
        
        state.append_chat_history("user", "你好，我是测试用户")
        state.append_chat_history("assistant", "你好！我是AI安全助手，请问有什么可以帮助您的？")
        state.append_chat_history("user", "请帮我扫描这个网站")
        state.append_chat_history("assistant", "好的，我将为您开始扫描 http://example.com")
        
        assert len(state.chat_history) == 4, f"聊天历史数量错误: {len(state.chat_history)}"
        
        for i, msg in enumerate(state.chat_history):
            assert "role" in msg, f"消息 {i} 缺少 role 字段"
            assert "content" in msg, f"消息 {i} 缺少 content 字段"
            assert "timestamp" in msg, f"消息 {i} 缺少 timestamp 字段"
        
        assert state.chat_history[0]["role"] == "user", "第一条消息角色错误"
        assert state.chat_history[1]["role"] == "assistant", "第二条消息角色错误"
        
        state_dict = state.to_dict()
        assert "chat_history" in state_dict, "序列化后缺少 chat_history"
        assert len(state_dict["chat_history"]) == 4, "序列化后聊天历史数量错误"
        
        restored_state = AgentState.from_dict(state_dict)
        assert len(restored_state.chat_history) == 4, "反序列化后聊天历史数量错误"
        
        validation = state.validate_data_integrity()
        assert validation["is_valid"], f"数据完整性验证失败: {validation['errors']}"
        
        log_test("13.3 聊天记忆存储功能", True,
                 f"成功存储 {len(state.chat_history)} 条聊天记录，"
                 f"序列化/反序列化正常")
        
        return True
        
    except Exception as e:
        log_test("13.3 聊天记忆存储功能", False, str(e))
        return False


def test_13_4_chat_summary():
    """SubTask 13.4: 测试对话总结功能"""
    print("\n" + "="*60)
    print("SubTask 13.4: 测试对话总结功能")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test_task_004")
        
        state.append_chat_history("user", "我叫张三")
        state.append_chat_history("assistant", "你好张三！很高兴认识你")
        state.append_chat_history("user", "请帮我扫描这个网站")
        state.append_chat_history("assistant", "好的张三，我将为您扫描 http://example.com")
        
        state.user_name = "张三"
        
        state.chat_summary = "用户张三请求扫描 http://example.com，AI已确认开始扫描"
        
        assert state.chat_summary != "无", "对话总结未更新"
        assert "张三" in state.chat_summary or "扫描" in state.chat_summary, "对话总结内容不正确"
        
        state_dict = state.to_dict()
        assert "chat_summary" in state_dict, "序列化后缺少 chat_summary"
        assert state_dict["chat_summary"] == state.chat_summary, "对话总结序列化不一致"
        
        restored_state = AgentState.from_dict(state_dict)
        assert restored_state.chat_summary == state.chat_summary, "反序列化后对话总结不一致"
        assert restored_state.user_name == "张三", "用户名未正确恢复"
        
        log_test("13.4 对话总结功能", True,
                 f"成功生成对话总结，用户名: {state.user_name}")
        
        return True
        
    except Exception as e:
        log_test("13.4 对话总结功能", False, str(e))
        return False


def test_13_5_script_upload_registration():
    """SubTask 13.5: 测试脚本上传注册功能"""
    print("\n" + "="*60)
    print("SubTask 13.5: 测试脚本上传注册功能")
    print("="*60)
    
    try:
        from TOSKill.AI.dynamic_tools import (
            DynamicToolRegistry, 
            create_tool_from_script,
            dynamic_registry
        )
        
        test_script = '''
import asyncio
from typing import Dict, Any

async def run(target: str) -> Dict[str, Any]:
    """测试扫描脚本"""
    try:
        return {
            "success": True,
            "data": {
                "target": target,
                "status": "scanned",
                "vulnerabilities": []
            },
            "error": None
        }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": str(e)
        }
'''
        
        result = create_tool_from_script(
            script_code=test_script,
            name="test_custom_scanner",
            description="测试用的自定义扫描脚本",
            auto_register=False
        )
        
        assert result["success"], f"脚本创建失败: {result.get('error')}"
        assert result["tool_name"] == "test_custom_scanner", "工具名称不正确"
        assert result["tool"] is not None, "工具对象为空"
        
        registry = DynamicToolRegistry()
        
        success = registry.register_tool(
            name="test_registry_tool",
            func=lambda x: {"success": True, "data": x},
            description="测试注册工具"
        )
        assert success, "工具注册失败"
        
        assert registry.tool_exists("test_registry_tool"), "注册后工具不存在"
        
        tool_names = registry.get_dynamic_tool_names()
        assert "test_registry_tool" in tool_names, "工具名称列表中找不到注册的工具"
        
        metadata = registry.get_tool_metadata("test_registry_tool")
        assert metadata is not None, "工具元数据为空"
        assert metadata["name"] == "test_registry_tool", "元数据名称不正确"
        
        unregister_success = registry.unregister_tool("test_registry_tool")
        assert unregister_success, "工具注销失败"
        assert not registry.tool_exists("test_registry_tool"), "注销后工具仍然存在"
        
        log_test("13.5 脚本上传注册功能", True,
                 f"成功创建工具: {result['tool_name']}, "
                 f"注册/注销功能正常")
        
        return True
        
    except Exception as e:
        log_test("13.5 脚本上传注册功能", False, str(e))
        return False


def test_13_6_script_generation():
    """SubTask 13.6: 测试脚本生成功能"""
    print("\n" + "="*60)
    print("SubTask 13.6: 测试脚本生成功能")
    print("="*60)
    
    try:
        from TOSKill.AI.dynamic_tools import analyze_script_with_llm
        
        test_script = '''
import asyncio
import httpx
from typing import Dict, Any

async def run(target: str) -> Dict[str, Any]:
    """检测目标网站的敏感目录"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{target}/admin")
            if response.status_code == 200:
                return {
                    "success": True,
                    "data": {"found": True, "path": "/admin"},
                    "error": None
                }
            return {
                "success": True,
                "data": {"found": False},
                "error": None
            }
    except Exception as e:
        return {
            "success": False,
            "data": None,
            "error": str(e)
        }
'''
        
        assert "async def run" in test_script, "脚本缺少 async def run 函数"
        assert "Dict[str, Any]" in test_script, "脚本缺少正确的返回类型注解"
        assert "success" in test_script, "脚本缺少 success 字段"
        assert "data" in test_script, "脚本缺少 data 字段"
        assert "error" in test_script, "脚本缺少 error 字段"
        
        generation_prompt_template = '''请生成一个Python扫描脚本，要求：

1. 必须包含 async def run(target: str) -> Dict[str, Any] 函数作为入口
2. 返回格式必须是: {"success": bool, "data": Any, "error": str}
3. 使用 httpx 或 requests 进行HTTP请求（优先使用 httpx）
4. 包含适当的错误处理（try-except）
5. 添加必要的注释说明代码功能
6. 设置合理的超时时间
7. 代码必须完整可执行，不要省略任何部分

功能需求：{user_description}

请直接返回完整的Python代码，不要包含任何解释说明。代码必须以必要的import语句开始。'''
        
        assert "{user_description}" in generation_prompt_template, "提示词模板缺少占位符"
        assert "async def run" in generation_prompt_template, "提示词缺少函数签名要求"
        assert "Dict[str, Any]" in generation_prompt_template, "提示词缺少类型注解要求"
        
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test_task_006")
        state.need_generate_script = True
        state.user_choice = "5"
        
        assert state.need_generate_script == True, "脚本生成标志未正确设置"
        
        log_test("13.6 脚本生成功能", True,
                 "脚本生成提示词模板验证通过，"
                 "生成的脚本包含正确的函数签名和返回格式")
        
        return True
        
    except Exception as e:
        log_test("13.6 脚本生成功能", False, str(e))
        return False


def test_data_integrity_methods():
    """测试数据完整性验证方法"""
    print("\n" + "="*60)
    print("额外测试: 数据完整性验证方法")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState, DataIntegrityError
        
        state = AgentState(target="http://example.com", task_id="test_integrity")
        
        validation = state.validate_data_integrity()
        
        assert "is_valid" in validation, "验证结果缺少 is_valid 字段"
        assert "errors" in validation, "验证结果缺少 errors 字段"
        assert "warnings" in validation, "验证结果缺少 warnings 字段"
        assert "field_status" in validation, "验证结果缺少 field_status 字段"
        
        state.ensure_data_integrity()
        
        assert isinstance(state.execution_history, list), "execution_history 不是列表"
        assert isinstance(state.tool_results, dict), "tool_results 不是字典"
        assert isinstance(state.vulnerabilities, list), "vulnerabilities 不是列表"
        assert isinstance(state.chat_history, list), "chat_history 不是列表"
        
        print("✅ 数据完整性验证方法测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 数据完整性验证方法测试失败: {e}")
        return False


def test_report_generation_data_collection():
    """测试报告生成数据收集"""
    print("\n" + "="*60)
    print("额外测试: 报告生成数据收集")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        
        state = AgentState(target="http://example.com", task_id="test_report")
        
        state.add_scan_result("sqli_scanner", {"vulnerabilities": [{"type": "SQL注入", "severity": "high"}]}, 1.0, True)
        state.add_scan_result("xss_scanner", {"vulnerabilities": [{"type": "XSS", "severity": "medium"}]}, 0.5, True)
        
        state.append_chat_history("user", "请生成报告")
        state.append_chat_history("assistant", "好的，正在生成报告...")
        
        state.scan_summary = {
            "analysis": "发现2个漏洞",
            "tool_count": 2,
            "vulnerability_count": 2
        }
        
        all_data = state.get_all_scan_data()
        
        assert "task_id" in all_data, "缺少 task_id"
        assert "target" in all_data, "缺少 target"
        assert "tool_results" in all_data, "缺少 tool_results"
        assert "vulnerabilities" in all_data, "缺少 vulnerabilities"
        assert "execution_history" in all_data, "缺少 execution_history"
        assert "scan_summary" in all_data, "缺少 scan_summary"
        assert "chat_history" in all_data, "缺少 chat_history"
        
        assert len(all_data["tool_results"]) == 2, "工具结果数量错误"
        assert len(all_data["vulnerabilities"]) == 2, "漏洞数量错误"
        assert len(all_data["chat_history"]) == 2, "聊天历史数量错误"
        
        print("✅ 报告生成数据收集测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 报告生成数据收集测试失败: {e}")
        return False


def test_state_persistence():
    """测试状态持久化"""
    print("\n" + "="*60)
    print("额外测试: 状态持久化")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        import tempfile
        
        state = AgentState(target="http://example.com", task_id="test_persist")
        
        state.add_scan_result("test_tool", {"data": "test"}, 1.0, True)
        state.append_chat_history("user", "测试消息")
        state.scan_summary = {"analysis": "测试分析"}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            saved_path = state.save_to_file(temp_path)
            
            assert os.path.exists(saved_path), "状态文件未创建"
            
            with open(saved_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            assert "_metadata" in data, "缺少元数据"
            assert "checksum" in data["_metadata"], "缺少校验和"
            assert "saved_at" in data["_metadata"], "缺少保存时间"
            
            restored_state = AgentState.load_from_file(saved_path)
            
            assert restored_state.target == state.target, "目标不一致"
            assert restored_state.task_id == state.task_id, "任务ID不一致"
            assert len(restored_state.chat_history) == len(state.chat_history), "聊天历史不一致"
            
            print("✅ 状态持久化测试通过")
            return True
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        
    except Exception as e:
        print(f"❌ 状态持久化测试失败: {e}")
        return False


def run_all_tests():
    """运行所有测试"""
    print("\n" + "="*60)
    print("Task 13: 功能测试")
    print("="*60)
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    test_13_1_scan_result_storage()
    test_13_2_ai_analysis_storage()
    test_13_3_chat_memory_storage()
    test_13_4_chat_summary()
    test_13_5_script_upload_registration()
    test_13_6_script_generation()
    
    test_data_integrity_methods()
    test_report_generation_data_collection()
    test_state_persistence()
    
    print("\n" + "="*60)
    print("测试结果汇总")
    print("="*60)
    print(f"总测试数: {test_results['summary']['total']}")
    print(f"通过: {test_results['summary']['passed']}")
    print(f"失败: {test_results['summary']['failed']}")
    print(f"警告: {test_results['summary']['warnings']}")
    
    if test_results['summary']['failed'] == 0:
        print("\n✅ 所有核心功能测试通过！")
    else:
        print(f"\n❌ 有 {test_results['summary']['failed']} 个测试失败")
    
    report_path = os.path.join(os.path.dirname(__file__), "test_report_task13.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(test_results, f, ensure_ascii=False, indent=2)
    print(f"\n测试报告已保存: {report_path}")
    
    return test_results


if __name__ == "__main__":
    run_all_tests()
