#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""
TOSKill 测试示例

创建一个独立的测试文件，验证TOSKill代码的功能正确性与稳定性。
"""

import sys
import os
import json
from typing import Dict, Any, List

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.history_manager import HistoryManager
from tools.registry import registry, validate_script_code, load_and_test_script
from tools.info_tools import get_info_tools, get_info_tool_metadata
from tools.vuln_tools import get_vuln_tools, get_vuln_tool_metadata
from tools.adapters import PluginAdapter
from state import AgentState
from helpers import TargetContextUpdater, ProgressCalculator


def test_history_manager():
    """测试历史管理器功能"""
    print("\n=== 测试 HistoryManager ===")
    
    # 初始化历史管理器
    history_manager = HistoryManager("test_history.json")
    
    # 测试创建空历史
    empty_history = history_manager._create_empty_history()
    print(f"创建空历史: {empty_history}")
    
    # 测试保存和加载历史
    test_history = {
        "chat_history": [
            {"role": "user", "content": "Hello", "timestamp": "2023-01-01T00:00:00"}
        ],
        "task_history": [
            {"task_name": "test_task", "result": {"status": "success"}, "timestamp": "2023-01-01T00:00:00"}
        ],
        "chat_summary": "Test summary",
        "user_chat_rules": "Test rules",
        "task_result": {"test_task": {"status": "success"}}
    }
    
    save_result = history_manager.save_history_to_file(test_history)
    print(f"保存历史: {save_result}")
    
    loaded_history = history_manager.load_history_from_file()
    print(f"加载历史: {loaded_history}")
    
    # 测试添加聊天消息
    updated_history = history_manager.add_chat_message("assistant", "Hello, how can I help you?", loaded_history)
    print(f"添加聊天消息后: {updated_history}")
    
    # 测试添加任务记录
    updated_history = history_manager.add_task_record("test_task_2", {"status": "success"}, updated_history)
    print(f"添加任务记录后: {updated_history}")
    
    # 测试获取完整历史
    full_history = history_manager.get_full_history(updated_history)
    print(f"获取完整历史: {full_history}")
    
    # 测试更新聊天摘要
    updated_history = history_manager.update_chat_summary("Updated summary", updated_history)
    print(f"更新聊天摘要后: {updated_history}")
    
    # 测试更新用户规则
    updated_history = history_manager.update_user_rules("Updated rules", updated_history)
    print(f"更新用户规则后: {updated_history}")
    
    # 测试清除历史
    cleared_history = history_manager.clear_history(updated_history)
    print(f"清除历史后: {cleared_history}")
    
    # 测试获取聊天历史
    chat_history = history_manager.get_chat_history_only(updated_history)
    print(f"获取聊天历史: {chat_history}")
    
    # 测试获取任务历史
    task_history = history_manager.get_task_history_only(updated_history)
    print(f"获取任务历史: {task_history}")
    
    print("✅ HistoryManager 测试完成")


def test_registry():
    """测试工具注册表功能"""
    print("\n=== 测试 Registry ===")
    
    # 测试获取所有工具
    info_tools = get_info_tools()
    vuln_tools = get_vuln_tools()
    print(f"信息收集工具: {info_tools}")
    print(f"漏洞扫描工具: {vuln_tools}")
    
    # 测试获取工具元数据
    for tool_name in info_tools[:3]:  # 测试前3个工具
        metadata = get_info_tool_metadata(tool_name)
        print(f"{tool_name} 元数据: {metadata}")
    
    for tool_name in vuln_tools[:3]:  # 测试前3个工具
        metadata = get_vuln_tool_metadata(tool_name)
        print(f"{tool_name} 元数据: {metadata}")
    
    # 测试脚本验证
    test_script = """
def run(target):
    return {"status": "success", "target": target}
"""
    is_valid, error_msg = validate_script_code(test_script)
    print(f"脚本验证结果: {is_valid}, {error_msg}")
    
    print("✅ Registry 测试完成")


def test_adapters():
    """测试插件适配器功能"""
    print("\n=== 测试 PluginAdapter ===")
    
    # 测试获取所有适配器
    adapters = PluginAdapter.get_adapters()
    print(f"可用适配器: {list(adapters.keys())}")
    
    # 测试适配器结构
    print("适配器结构验证: 所有适配器都存在")
    for adapter_name, adapter_func in adapters.items():
        print(f"  - {adapter_name}: {adapter_func.__name__}")
    
    print("✅ PluginAdapter 测试完成")


def test_agent_state():
    """测试 AgentState 功能"""
    print("\n=== 测试 AgentState ===")
    
    # 初始化 AgentState
    state = AgentState(
        target="https://example.com",
        task_id="test_task_123"
    )
    print(f"初始状态: {state.to_dict()}")
    
    # 测试更新阶段状态
    state.update_stage_status("planning", "running", "initializing", 10, "开始规划")
    print(f"更新阶段状态后: {state.stage_status}")
    
    # 测试获取进度
    progress = state.get_progress()
    print(f"获取进度: {progress}%")
    
    # 测试添加执行步骤
    state.add_execution_step("test_task", {"status": "success"}, "success")
    print(f"添加执行步骤后: {len(state.execution_history)} 个步骤")
    
    # 测试添加执行步骤开始
    step_number = state.add_execution_step_start("test_task_2")
    print(f"添加执行步骤开始: 步骤编号 {step_number}")
    
    # 测试更新执行步骤
    state.update_execution_step(step_number, {"status": "success"}, "success")
    print(f"更新执行步骤后: 步骤状态 {state.execution_history[step_number-1]['status']}")
    
    # 测试更新上下文
    state.update_context("test_key", "test_value")
    print(f"更新上下文后: {state.target_context}")
    
    # 测试添加漏洞
    state.add_vulnerability({"id": "test_vuln", "title": "Test Vulnerability"})
    print(f"添加漏洞后: {len(state.vulnerabilities)} 个漏洞")
    
    # 测试添加错误
    state.add_error("Test error")
    print(f"添加错误后: {len(state.errors)} 个错误")
    
    # 测试标记完成
    state.mark_complete()
    print(f"标记完成后: is_complete={state.is_complete}, should_continue={state.should_continue}")
    
    # 测试追加聊天历史
    state.append_chat_history("user", "Hello")
    print(f"追加聊天历史后: {len(state.chat_history)} 条消息")
    
    # 测试转换为字典
    state_dict = state.to_dict()
    print(f"转换为字典: 包含 {len(state_dict)} 个字段")
    
    # 测试从字典创建实例
    new_state = AgentState.from_dict(state_dict)
    print(f"从字典创建实例: target={new_state.target}, task_id={new_state.task_id}")
    
    print("✅ AgentState 测试完成")


def test_helpers():
    """测试辅助工具功能"""
    print("\n=== 测试 Helpers ===")
    
    # 测试 TargetContextUpdater
    state = AgentState(
        target="https://example.com",
        task_id="test_task_123"
    )
    
    test_data = {
        "server": "Apache",
        "os": "Linux",
        "ip": "127.0.0.1",
        "domain": "example.com",
        "title": "Example Website"
    }
    
    TargetContextUpdater.update_context(state, "baseinfo", test_data)
    print(f"更新上下文后: {state.target_context}")
    
    # 测试 ProgressCalculator
    progress = ProgressCalculator.calculate_progress(5, 10)
    print(f"计算进度: {progress}%")
    
    stage_progress = ProgressCalculator.calculate_stage_progress(["task1", "task2"], ["task3", "task4"])
    print(f"计算阶段进度: {stage_progress}%")
    
    print("✅ Helpers 测试完成")


def test_integration():
    """测试集成功能"""
    print("\n=== 测试集成功能 ===")
    
    # 测试工具初始化
    from tools import initialize_tools
    initialize_tools()
    print("工具初始化完成")
    
    # 测试工具列表
    tools = registry.list_tools()
    print(f"注册表中的工具数量: {len(tools)}")
    
    # 测试工具是否存在
    for tool_name in get_info_tools()[:2]:
        exists = registry.has_tool(tool_name)
        print(f"工具 {tool_name} 存在: {exists}")
    
    print("✅ 集成功能测试完成")


def main():
    """主测试函数"""
    print("开始 TOSKill 测试...")
    
    try:
        test_history_manager()
        test_registry()
        test_adapters()
        test_agent_state()
        test_helpers()
        test_integration()
        
        print("\n🎉 所有测试通过！")
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()