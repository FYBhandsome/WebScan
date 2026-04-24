"""
TOSKill AI - 终端交互式漏洞智能扫描系统

使用方法:
    python demo.py

功能:
    - 信息收集模式: 收集目标域名/IP的基本信息
    - 漏洞扫描模式: 检测SQL注入、XSS等漏洞
    - 报告生成: 生成AI分析报告
    - 实时对话: 与AI助手交互
    - 脚本管理: 上传或生成自定义扫描脚本
"""
import asyncio
import logging
import sys
import os
import time
import uuid
from datetime import datetime
from typing import Dict, List, TypedDict, Optional, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')


def stream_print(text: str, delay: float = 0.01):
    """流式输出文本"""
    for char in str(text):
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


class TOSKillState(TypedDict):
    """TOSKill工作流状态"""
    target: str
    task_id: str
    mode: str
    planned_tasks: List[str]
    completed_tasks: List[str]
    tool_results: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    target_context: Dict[str, Any]
    execution_history: List[Dict[str, Any]]
    is_complete: bool
    should_continue: bool
    next_action: str
    decision_history: List[Dict[str, Any]]
    errors: List[str]
    vuln_scan_results: Dict[str, Any]
    scan_summary: Dict[str, Any]
    report: str
    user_choice: str
    chat_history: List[Dict[str, str]]
    chat_summary: str
    user_name: str
    need_generate_script: bool
    next_task: str
    task_result: Dict[str, Any]
    task_history: List[str]
    stage_status: Dict[str, Dict[str, Any]]


def validate_state_integrity(state: TOSKillState) -> Dict[str, Any]:
    """
    验证状态数据完整性
    
    Args:
        state: 当前状态
        
    Returns:
        验证结果字典
    """
    result = {
        "is_valid": True,
        "errors": [],
        "warnings": [],
        "field_status": {}
    }
    
    required_fields = {
        "target": str,
        "task_id": str,
        "mode": str,
        "execution_history": list,
        "tool_results": dict,
        "vulnerabilities": list,
        "chat_history": list,
        "scan_summary": dict,
        "completed_tasks": list
    }
    
    for field_name, expected_type in required_fields.items():
        if field_name not in state:
            result["errors"].append(f"缺少必要字段: {field_name}")
            result["field_status"][field_name] = "missing"
            result["is_valid"] = False
        elif not isinstance(state[field_name], expected_type):
            result["errors"].append(
                f"字段 {field_name} 类型错误: 期望 {expected_type.__name__}, 实际 {type(state[field_name]).__name__}"
            )
            result["field_status"][field_name] = "type_error"
            result["is_valid"] = False
        else:
            result["field_status"][field_name] = "valid"
    
    return result


def ensure_state_fields(state: TOSKillState) -> TOSKillState:
    """
    确保状态包含所有必要字段，缺失字段使用默认值
    
    Args:
        state: 当前状态
        
    Returns:
        完整的状态字典
    """
    default_values = {
        "target": "",
        "task_id": "",
        "mode": "info_collection",
        "planned_tasks": [],
        "completed_tasks": [],
        "tool_results": {},
        "vulnerabilities": [],
        "target_context": {},
        "execution_history": [],
        "is_complete": False,
        "should_continue": True,
        "next_action": "",
        "decision_history": [],
        "errors": [],
        "vuln_scan_results": {},
        "scan_summary": {},
        "report": "",
        "user_choice": "",
        "chat_history": [],
        "chat_summary": "无",
        "user_name": "用户",
        "need_generate_script": False,
        "next_task": "",
        "task_result": {},
        "task_history": [],
        "stage_status": {
            "planning": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []},
            "tool_execution": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []},
            "report": {"status": "pending", "sub_status": "pending", "progress": 0, "logs": []}
        }
    }
    
    complete_state = default_values.copy()
    complete_state.update(state)
    
    return complete_state


def merge_state_data(base_state: TOSKillState, new_data: Dict[str, Any]) -> TOSKillState:
    """
    合并状态数据，确保数据正确累积
    
    Args:
        base_state: 基础状态
        new_data: 新数据
        
    Returns:
        合并后的状态
    """
    result = base_state.copy()
    
    for key, value in new_data.items():
        if key in ["tool_results", "target_context", "scan_summary", "vuln_scan_results"]:
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = {**result[key], **value}
            else:
                result[key] = value
        elif key in ["vulnerabilities", "execution_history", "completed_tasks", "errors", "chat_history", "task_history", "planned_tasks"]:
            if isinstance(value, list) and isinstance(result.get(key), list):
                existing_items = result[key]
                for item in value:
                    if item not in existing_items:
                        existing_items.append(item)
            else:
                result[key] = value
        else:
            result[key] = value
    
    return result


def create_agent_state_from_toskill(state: TOSKillState) -> "AgentState":
    """
    从 TOSKillState 创建 AgentState 实例
    
    Args:
        state: TOSKillState 字典
        
    Returns:
        AgentState 实例
    """
    from TOSKill.AI.state import AgentState
    
    return AgentState(
        target=state.get("target", ""),
        task_id=state.get("task_id", ""),
        planned_tasks=state.get("planned_tasks", []),
        completed_tasks=state.get("completed_tasks", []),
        tool_results=state.get("tool_results", {}),
        vulnerabilities=state.get("vulnerabilities", []),
        target_context=state.get("target_context", {}),
        execution_history=state.get("execution_history", []),
        is_complete=state.get("is_complete", False),
        should_continue=state.get("should_continue", True),
        next_action=state.get("next_action", ""),
        decision_history=state.get("decision_history", []),
        errors=state.get("errors", []),
        vuln_scan_results=state.get("vuln_scan_results", {}),
        scan_summary=state.get("scan_summary", {}),
        report=state.get("report", ""),
        user_choice=state.get("user_choice", ""),
        chat_history=state.get("chat_history", []),
        chat_summary=state.get("chat_summary", "无"),
        user_name=state.get("user_name", "用户"),
        need_generate_script=state.get("need_generate_script", False),
        next_mode=state.get("mode", "info_collection"),
        task_history=state.get("task_history", [])
    )


def extract_state_from_agent(agent_state: "AgentState", base_state: TOSKillState) -> TOSKillState:
    """
    从 AgentState 提取数据更新 TOSKillState
    
    Args:
        agent_state: AgentState 实例
        base_state: 基础 TOSKillState
        
    Returns:
        更新后的 TOSKillState
    """
    return {
        **base_state,
        "planned_tasks": agent_state.planned_tasks,
        "completed_tasks": agent_state.completed_tasks,
        "tool_results": agent_state.tool_results,
        "vulnerabilities": agent_state.vulnerabilities,
        "target_context": agent_state.target_context,
        "execution_history": agent_state.execution_history,
        "is_complete": agent_state.is_complete,
        "should_continue": agent_state.should_continue,
        "next_action": agent_state.next_action,
        "decision_history": agent_state.decision_history,
        "errors": agent_state.errors,
        "vuln_scan_results": agent_state.vuln_scan_results,
        "scan_summary": agent_state.scan_summary,
        "report": agent_state.report,
        "chat_history": agent_state.chat_history,
        "chat_summary": agent_state.chat_summary,
        "user_name": agent_state.user_name,
        "need_generate_script": agent_state.need_generate_script,
        "task_history": agent_state.task_history
    }


def append_chat_history(state: TOSKillState, role: str, content: str) -> TOSKillState:
    """追加聊天历史"""
    new_hist = state["chat_history"].copy()
    new_hist.append({"role": role, "content": content, "timestamp": datetime.now().isoformat()})
    return {**state, "chat_history": new_hist}


def format_scan_result(tool_name: str, target: str, result: Dict) -> str:
    """格式化扫描结果输出"""
    success = result.get("success", False)
    execution_time = result.get("execution_time", 0)
    data = result.get("data", {})
    error = result.get("error")
    
    lines = [
        "=" * 60,
        "📊 扫描结果报告",
        "=" * 60,
        f"🔧 工具名称: {tool_name}",
        f"🎯 扫描目标: {target}",
        f"⏱️  执行时间: {execution_time:.2f}秒",
        f"📋 执行状态: {'✅ 成功' if success else '❌ 失败'}",
    ]
    
    if not success and error:
        lines.append(f"❌ 错误信息: {error}")
    
    if data:
        lines.append("-" * 40)
        lines.append("📄 扫描结果:")
        
        import json
        if isinstance(data, dict):
            for key, value in list(data.items())[:10]:
                if isinstance(value, (list, dict)):
                    value_str = json.dumps(value, ensure_ascii=False)[:200]
                    if len(json.dumps(value, ensure_ascii=False)) > 200:
                        value_str += "..."
                else:
                    value_str = str(value)[:200]
                lines.append(f"  • {key}: {value_str}")
        else:
            lines.append(f"  {str(data)[:500]}")
    
    lines.append("=" * 60)
    return "\n".join(lines)


def generate_result_summary(tool_name: str, result: Dict) -> str:
    """生成扫描结果摘要"""
    import json
    success = result.get("success", False)
    execution_time = result.get("execution_time", 0)
    data = result.get("data", {})
    error = result.get("error")
    
    summary_parts = [f"工具 {tool_name} 执行{'成功' if success else '失败'}"]
    
    if execution_time > 0:
        summary_parts.append(f"耗时 {execution_time:.2f}秒")
    
    if data and isinstance(data, dict):
        key_findings = []
        if "vulnerabilities" in data:
            vulns = data["vulnerabilities"]
            if isinstance(vulns, list) and len(vulns) > 0:
                key_findings.append(f"发现 {len(vulns)} 个漏洞")
        if "ports" in data:
            ports = data["ports"]
            if isinstance(ports, list) and len(ports) > 0:
                key_findings.append(f"发现 {len(ports)} 个开放端口")
        if "subdomains" in data:
            subs = data["subdomains"]
            if isinstance(subs, list) and len(subs) > 0:
                key_findings.append(f"发现 {len(subs)} 个子域名")
        if "directories" in data:
            dirs = data["directories"]
            if isinstance(dirs, list) and len(dirs) > 0:
                key_findings.append(f"发现 {len(dirs)} 个目录")
        
        if key_findings:
            summary_parts.append("，".join(key_findings))
    
    if not success and error:
        summary_parts.append(f"错误: {error}")
    
    return " | ".join(summary_parts)


def format_analysis_report(analysis: str, tool_count: int, vulnerability_count: int, timestamp: str) -> str:
    """格式化AI分析报告输出"""
    try:
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        formatted_time = timestamp
    
    lines = [
        "=" * 60,
        "🧾 AI综合分析报告",
        "=" * 60,
        f"📊 扫描统计: 执行 {tool_count} 个工具，发现 {vulnerability_count} 个漏洞",
        f"⏱️  分析时间: {formatted_time}",
        "-" * 40,
        "🔍 分析结果:",
        analysis,
        "=" * 60
    ]
    return "\n".join(lines)


async def ai_decision_atom(state: TOSKillState) -> TOSKillState:
    """原子1: AI全局决策"""
    stream_print("\n" + "="*60)
    stream_print("🔹 原子1：AI全局决策")
    
    from TOSKill.AI.nodes import AIDecisionNode
    
    state = ensure_state_fields(state)
    
    validation = validate_state_integrity(state)
    if not validation["is_valid"]:
        logger.warning(f"状态验证警告: {validation['errors']}")
    
    agent_state = create_agent_state_from_toskill(state)
    
    agent_state.track_data_flow("input", "ai_decision_atom")
    
    decision_node = AIDecisionNode()
    result_state = await decision_node(agent_state)
    
    result_state.track_data_flow("ai_decision_atom", "output")
    
    next_task = result_state.planned_tasks[0] if result_state.planned_tasks else "无"
    need_gen = result_state.need_generate_script
    
    if need_gen:
        stream_print("⚠️ 当前无对应任务脚本，AI将引导您上传或生成脚本")
    else:
        stream_print(f"✅ 决策任务：【{next_task}】")
        stream_print(f"📊 推荐模式：【{result_state.next_mode}】")
    
    new_state = extract_state_from_agent(result_state, state)
    new_state["next_task"] = next_task
    new_state["need_generate_script"] = need_gen
    
    return ensure_state_fields(new_state)


async def user_interact_atom(state: TOSKillState) -> TOSKillState:
    """原子2: 用户交互"""
    stream_print("\n" + "="*60)
    stream_print(f"🎯 目标：{state['target']} | 模式：{state['mode']} | 任务：{state['next_task']}")
    stream_print("【1】执行扫描 【2】停止扫描 【3】和AI聊天 【4】上传脚本 【5】生成脚本 【0】切换模式")
    
    choice = input("请输入指令：").strip()
    logger.info(f"用户选择: {choice}")
    
    return {**state, "user_choice": choice}


async def execute_analyze_atom(state: TOSKillState) -> TOSKillState:
    """原子3: 执行任务并分析"""
    stream_print("\n" + "="*60)
    stream_print("🔹 原子3：执行任务并分析")
    
    from TOSKill.AI.nodes import ExecuteAnalyzeNode
    from TOSKill.tools import get_tool_by_name
    
    state = ensure_state_fields(state)
    
    validation = validate_state_integrity(state)
    if not validation["is_valid"]:
        logger.warning(f"状态验证警告: {validation['errors']}")
    
    agent_state = create_agent_state_from_toskill(state)
    
    agent_state.track_data_flow("input", "execute_analyze_atom")
    
    execute_node = ExecuteAnalyzeNode()
    result_state = await execute_node(agent_state)
    
    execution_history = list(state.get("execution_history", []))
    
    if result_state.planned_tasks:
        stream_print(f"开始执行计划任务: {', '.join(result_state.planned_tasks)}")
        
        for task in result_state.planned_tasks:
            if task not in result_state.completed_tasks:
                tool = get_tool_by_name(task)
                start_time = time.time()
                
                if tool:
                    try:
                        if hasattr(tool, 'invoke'):
                            tool_result = tool.invoke(state["target"])
                        elif hasattr(tool, 'run'):
                            tool_result = tool.run(state["target"])
                        elif callable(tool):
                            tool_result = tool(state["target"])
                        else:
                            tool_result = {"success": False, "error": f"工具 {task} 不可调用"}
                    except Exception as e:
                        tool_result = {"success": False, "error": str(e)}
                else:
                    tool_result = {"success": False, "error": f"工具 {task} 不存在"}
                
                execution_time = time.time() - start_time
                timestamp = datetime.now().isoformat()
                
                if isinstance(tool_result, dict):
                    tool_result["execution_time"] = execution_time
                else:
                    tool_result = {
                        "success": True,
                        "data": tool_result,
                        "execution_time": execution_time
                    }
                
                execution_record = {
                    "task": task,
                    "tool_name": task,
                    "target": state["target"],
                    "result": tool_result.get("data", {}),
                    "success": tool_result.get("success", False),
                    "timestamp": timestamp,
                    "execution_time": tool_result.get("execution_time", execution_time),
                    "error": tool_result.get("error")
                }
                execution_history.append(execution_record)
                
                formatted_result = format_scan_result(task, state["target"], tool_result)
                logger.info(f"\n{formatted_result}")
                stream_print(formatted_result)
                
                if tool_result.get("success"):
                    result_state.add_scan_result(
                        tool_name=task,
                        result=tool_result.get("data", {}),
                        execution_time=execution_time,
                        success=True
                    )
                    result_state.completed_tasks.append(task)
                    
                    if "vulnerabilities" in tool_result.get("data", {}):
                        vulns = tool_result["data"]["vulnerabilities"]
                        if isinstance(vulns, list):
                            for vuln in vulns:
                                vuln["_source_tool"] = task
                                vuln["_detected_at"] = timestamp
                            result_state.vulnerabilities.extend(vulns)
                else:
                    error_msg = tool_result.get("error", "未知错误")
                    result_state.errors.append(f"{task}: {error_msg}")
                
                result_summary = generate_result_summary(task, tool_result)
                result_state.append_chat_history("system", f"[扫描完成] {result_summary}")
    
    if result_state.tool_results:
        analysis = await _analyze_results_with_llm(result_state.tool_results)
        
        tool_count = len(result_state.completed_tasks)
        vulnerability_count = len(result_state.vulnerabilities)
        success_count = sum(1 for t in result_state.completed_tasks if t in result_state.tool_results)
        success_rate = (success_count / tool_count * 100) if tool_count > 0 else 0
        
        scan_summary = {
            "analysis": analysis,
            "timestamp": datetime.now().isoformat(),
            "tool_count": tool_count,
            "vulnerability_count": vulnerability_count,
            "success_rate": round(success_rate, 2)
        }
        
        result_state.scan_summary = scan_summary
        result_state.append_chat_history("assistant", analysis)
        
        formatted_report = format_analysis_report(
            analysis=analysis,
            tool_count=tool_count,
            vulnerability_count=vulnerability_count,
            timestamp=scan_summary["timestamp"]
        )
        logger.info(f"\n{formatted_report}")
        stream_print(formatted_report)
        
        execution_history.append({
            "task": "tool_chain_analysis",
            "tool_name": "ai_analysis",
            "target": state["target"],
            "result": result_state.tool_results,
            "analysis": analysis,
            "success": True,
            "timestamp": datetime.now().isoformat()
        })
    
    result_state.execution_history = execution_history
    
    result_state.track_data_flow("execute_analyze_atom", "output")
    
    new_state = extract_state_from_agent(result_state, state)
    new_state["execution_history"] = execution_history
    
    try:
        result_state.save_to_file()
        logger.info("状态已自动保存")
    except Exception as e:
        logger.warning(f"状态保存失败: {e}")
    
    return ensure_state_fields(new_state)


async def _analyze_results_with_llm(results: Dict) -> str:
    """AI分析多个工具的结果"""
    import json
    from TOSKill.AI.agent_config import agent_config
    from langchain_openai import ChatOpenAI
    
    try:
        llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        
        results_summary = {}
        for tool_name, data in results.items():
            if isinstance(data, dict):
                results_summary[tool_name] = {
                    k: v for k, v in list(data.items())[:5]
                }
            else:
                results_summary[tool_name] = str(data)[:200]
        
        prompt = f"""简要分析以下扫描结果（3-5点）：
{json.dumps(results_summary, ensure_ascii=False, indent=2)}

重点关注：
1. 发现的安全问题
2. 需要进一步探测的点
3. 整体安全评估"""
        
        analysis = await llm.ainvoke(prompt)
        return analysis.content
    except Exception as e:
        return f"分析失败: {str(e)}"


MAX_CHAT_HISTORY_LENGTH = 10


def _get_recent_chat_history(state: TOSKillState, limit: int = None) -> List[Dict]:
    """获取最近的聊天历史，限制长度避免上下文过长"""
    if limit is None:
        limit = MAX_CHAT_HISTORY_LENGTH
    return state["chat_history"][-limit:] if state["chat_history"] else []


def _build_chat_context(state: TOSKillState) -> str:
    """构建聊天上下文字符串"""
    recent_history = _get_recent_chat_history(state)
    if not recent_history:
        return "暂无历史对话"
    
    context_lines = []
    for msg in recent_history:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        role_display = {"user": "用户", "assistant": "AI", "system": "系统"}.get(role, role)
        context_lines.append(f"[{role_display}]: {content}")
    
    return "\n".join(context_lines)


def _extract_user_name(user_msg: str) -> Optional[str]:
    """从用户消息中提取名字"""
    import re
    patterns = [
        r"我叫([^\s，。！？,\.!?]+)",
        r"我是([^\s，。！？,\.!?]+)",
        r"名字是([^\s，。！？,\.!?]+)",
        r"我的名字叫([^\s，。！？,\.!?]+)",
    ]
    
    for pattern in patterns:
        match = re.search(pattern, user_msg)
        if match:
            name = match.group(1).strip()
            if len(name) <= 10:
                return name
    return None


async def _generate_chat_summary(state: TOSKillState) -> str:
    """调用LLM生成对话总结"""
    from TOSKill.AI.agent_config import agent_config
    from langchain_openai import ChatOpenAI
    
    chat_context = _build_chat_context(state)
    
    summary_prompt = f"""请总结以下对话内容，包括：
1. 主要讨论话题
2. 关键结论和建议
3. 用户偏好和关注点
4. 后续行动建议

对话历史：
{chat_context}

请用简洁清晰的语言进行总结，每个部分用换行分隔。"""
    
    try:
        llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        summary_response = await llm.ainvoke(summary_prompt)
        return summary_response.content
    except Exception as e:
        logger.error(f"对话总结生成失败: {e}")
        return "对话总结生成失败，请查看聊天历史。"


def _format_summary_output(summary: str) -> str:
    """格式化对话总结输出"""
    return f"""============================================================
📝 对话总结
============================================================
{summary}
============================================================"""


async def chat_negotiate_atom(state: TOSKillState) -> TOSKillState:
    """原子4: 聊天协商 - 支持多轮对话记忆存储
    
    功能特性：
    - 用户输入后立即保存到 chat_history
    - AI回复后立即保存到 chat_history
    - 使用最新的 chat_history 作为下一次对话的上下文
    - 实现对话历史长度限制（最近10条）
    - 用户输入 "stop" 时生成对话总结
    - 记住用户名字
    """
    stream_print("\n" + "="*60)
    stream_print("🔹 原子4：实时记忆聊天")
    stream_print("============================================================")
    
    from TOSKill.AI.agent_config import agent_config
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
    
    state = ensure_state_fields(state)
    
    llm = ChatOpenAI(
        model=agent_config.MODEL_ID,
        temperature=agent_config.TEMPERATURE,
        api_key=agent_config.OPENAI_API_KEY,
        base_url=agent_config.OPENAI_BASE_URL
    )
    
    current_state = state.copy()
    user_name = current_state.get("user_name", "用户")
    
    stream_print(f"👤 当前用户: {user_name}")
    stream_print(f"📊 对话历史: {len(current_state['chat_history'])} 条")
    stream_print(f"📋 操作指引: 输入 'stop' 结束对话并生成总结")
    stream_print("============================================================")
    
    while True:
        try:
            user_input = input(f"\n💬 {user_name}> ").strip()
            
            if not user_input:
                stream_print("⚠️ 请输入有效内容，或输入 'stop' 结束对话")
                continue
            
            if user_input.lower() == "stop":
                stream_print("\n🔄 正在生成对话总结...")
                
                if current_state["chat_history"]:
                    summary = await _generate_chat_summary(current_state)
                    
                    current_state["chat_summary"] = summary
                    
                    current_state = append_chat_history(current_state, "system", f"[对话总结] {summary[:200]}...")
                    
                    formatted_summary = _format_summary_output(summary)
                    stream_print(f"\n{formatted_summary}")
                    
                    logger.info(f"[聊天协商] 对话总结已生成并保存")
                else:
                    stream_print("📭 暂无对话历史，无需生成总结")
                
                stream_print("\n👋 感谢您的对话，再见！")
                break
            
            extracted_name = _extract_user_name(user_input)
            if extracted_name:
                user_name = extracted_name
                current_state["user_name"] = user_name
                stream_print(f"✅ 已记住您的名字: {user_name}")
                logger.info(f"[聊天协商] 更新用户名字: {extracted_name}")
            
            current_state = append_chat_history(current_state, "user", user_input)
            logger.info(f"[聊天协商] 用户消息已保存到chat_history")
            
            recent_history = _get_recent_chat_history(current_state)
            chat_context = _build_chat_context(current_state)
            
            system_prompt = f"""你是专业的Web安全助手，正在协助用户进行安全扫描任务。

## 基本信息
- 用户称呼: {user_name}
- 当前目标: {current_state['target']}
- 已完成任务: {', '.join(current_state['completed_tasks']) if current_state['completed_tasks'] else '暂无'}

## 对话历史（最近{MAX_CHAT_HISTORY_LENGTH}条）
{chat_context}

## 行为准则
1. 称呼用户为 {user_name}
2. 回复简洁专业，避免冗长
3. 如果用户提到自己的名字，请记住并在后续对话中使用
4. 提供有价值的安全建议和分析"""
            
            messages = [SystemMessage(content=system_prompt)]
            
            for msg in recent_history:
                role = msg.get("role", "")
                content = msg.get("content", "")
                if role == "user":
                    messages.append(HumanMessage(content=content))
                elif role == "assistant":
                    messages.append(AIMessage(content=content))
            
            stream_print("\n🤖 AI> ", delay=0)
            
            try:
                ai_response = await llm.ainvoke(messages)
                ai_content = ai_response.content
                
                print(ai_content)
                
                current_state = append_chat_history(current_state, "assistant", ai_content)
                logger.info(f"[聊天协商] AI回复已保存到chat_history")
                
                if len(current_state["chat_history"]) > 0:
                    try:
                        brief_summary_prompt = f"请用一句话总结以下对话的关键信息：\n{chat_context}"
                        brief_summary = await llm.ainvoke(brief_summary_prompt)
                        current_state["chat_summary"] = brief_summary.content
                    except Exception as e:
                        logger.warning(f"简要总结生成失败: {e}")
                        current_state["chat_summary"] = "对话进行中"
                
            except Exception as e:
                logger.error(f"AI调用失败: {e}")
                error_msg = "抱歉，我遇到了一些问题，请稍后再试。"
                print(error_msg)
                current_state = append_chat_history(current_state, "assistant", error_msg)
            
        except KeyboardInterrupt:
            stream_print("\n\n🛑 对话被中断")
            break
        except Exception as e:
            logger.error(f"聊天协商异常: {e}")
            stream_print(f"\n❌ 发生错误: {e}")
            break
    
    new_state = merge_state_data(state, {
        "chat_history": current_state["chat_history"],
        "chat_summary": current_state["chat_summary"],
        "user_name": current_state.get("user_name", "用户")
    })
    
    return ensure_state_fields(new_state)


async def script_tool_atom(state: TOSKillState) -> TOSKillState:
    """原子5: 脚本管理"""
    stream_print("\n" + "="*60)
    stream_print("🔹 原子5：自定义脚本管理")
    
    from langchain_openai import ChatOpenAI
    from TOSKill.AI.agent_config import agent_config
    
    state = ensure_state_fields(state)
    
    llm = ChatOpenAI(
        model=agent_config.MODEL_ID,
        temperature=agent_config.TEMPERATURE,
        api_key=agent_config.OPENAI_API_KEY,
        base_url=agent_config.OPENAI_BASE_URL
    )
    
    res = {}
    user_choice = state["user_choice"]
    
    if user_choice == "4":
        stream_print("\n📁 脚本上传自动注册功能")
        stream_print("-" * 40)
        
        script_path = input("请输入脚本文件路径: ").strip()
        
        if script_path and os.path.exists(script_path):
            stream_print("⏳ 正在处理上传的脚本文件...")
            
            try:
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                stream_print("🤖 正在使用AI分析脚本功能...")
                
                analysis_prompt = f"""请分析以下Python脚本的功能，并提供简洁的描述（不超过100字）：

```python
{script_content[:2000]}
```

请直接返回功能描述，不要包含其他内容。重点关注：
1. 脚本的主要功能
2. 输入参数
3. 输出结果
"""
                
                analysis_result = await llm.ainvoke(analysis_prompt)
                tool_description = analysis_result.content.strip()
                
                script_name = os.path.basename(script_path).replace('.py', '')
                tool_name = f"custom_{script_name}"
                
                stream_print(f"✅ 脚本功能分析完成：{tool_description}")
                
                from TOSKill.tools import create_tool_from_script, register_dynamic_tool
                
                tool = create_tool_from_script(
                    script_path=script_path,
                    tool_name=tool_name,
                    description=tool_description
                )
                
                if tool:
                    success = register_dynamic_tool(tool, category="custom")
                    
                    if success:
                        stream_print("\n" + "=" * 50)
                        stream_print("🎉 工具注册成功！")
                        stream_print("=" * 50)
                        stream_print(f"🔧 工具名称: {tool_name}")
                        stream_print(f"📋 工具描述: {tool_description}")
                        stream_print(f"📁 脚本路径: {script_path}")
                        stream_print("-" * 50)
                        stream_print("💡 提示: 您现在可以在扫描中使用此工具")
                        stream_print("=" * 50)
                        
                        from TOSKill.AI.nodes import AIDecisionNode
                        AIDecisionNode._instance = None
                        
                        res = {
                            "status": "registered",
                            "tool_name": tool_name,
                            "description": tool_description,
                            "script_path": script_path
                        }
                        
                        logger.info(f"脚本工具注册成功: {tool_name}")
                    else:
                        stream_print("❌ 工具注册失败，请检查脚本格式")
                        stream_print("💡 提示: 确保脚本包含 run(target) 函数")
                        res = {"status": "registration_failed"}
                else:
                    stream_print("❌ 工具创建失败，请确保脚本包含 run(target) 函数")
                    stream_print("💡 提示: 脚本必须定义 async def run(target: str) -> Dict 作为入口")
                    res = {"status": "creation_failed"}
                    
            except Exception as e:
                logger.error(f"脚本处理失败: {str(e)}")
                stream_print(f"❌ 脚本处理失败: {str(e)}")
                stream_print("💡 请检查文件路径和脚本格式")
                res = {"status": "error", "error": str(e)}
        else:
            stream_print("❌ 文件不存在或路径无效")
            stream_print("💡 请提供有效的脚本文件路径")
            res = {"status": "file_not_found"}
    
    elif user_choice == "5":
        stream_print("\n🔧 脚本生成功能")
        stream_print("-" * 40)
        
        user_description = input("请描述您需要生成的脚本功能\n（例如：检测目标网站的敏感目录、扫描特定端口服务等）\n> ").strip()
        
        if not user_description:
            user_description = "用户自定义扫描脚本"
        
        stream_print("⏳ 正在生成脚本，请稍候...")
        
        generation_prompt = f"""请生成一个Python扫描脚本，要求：

1. 必须包含 async def run(target: str) -> Dict[str, Any] 函数作为入口
2. 返回格式必须是: {{"success": bool, "data": Any, "error": str}}
3. 使用 httpx 或 requests 进行HTTP请求（优先使用 httpx）
4. 包含适当的错误处理（try-except）
5. 添加必要的注释说明代码功能
6. 设置合理的超时时间
7. 代码必须完整可执行，不要省略任何部分

功能需求：{user_description}

请直接返回完整的Python代码，不要包含任何解释说明。代码必须以必要的import语句开始。"""

        try:
            code_response = await llm.ainvoke(generation_prompt)
            code_content = code_response.content.strip()
            
            code_content = code_content.replace("```python", "").replace("```Python", "").replace("```", "").strip()
            
            if not code_content.startswith("import") and not code_content.startswith("from"):
                code_content = "import asyncio\nimport httpx\nfrom typing import Dict, Any\n\n" + code_content
            
            script_name = f"custom_script_{int(time.time())}"
            save_dir = "custom_scripts/generated"
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, f"{script_name}.py")
            
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(code_content)
            
            stream_print(f"✅ 脚本保存成功: {save_path}")
            stream_print("⏳ 正在进行工具注册...")
            
            from TOSKill.AI.dynamic_tools import register_script_as_tool_async, analyze_script_with_llm
            
            analysis = await analyze_script_with_llm(code_content)
            tool_name = analysis.get("name", script_name) if analysis.get("success") else script_name
            tool_description = analysis.get("description", user_description) if analysis.get("success") else user_description
            
            register_result = await register_script_as_tool_async(
                script_code=code_content,
                name=tool_name,
                description=tool_description
            )
            
            if register_result.get("success"):
                tool_name = register_result.get("tool_name", tool_name)
                
                code_lines = code_content.split('\n')[:20]
                preview_lines = '\n'.join(code_lines)
                if len(code_content.split('\n')) > 20:
                    preview_lines += "\n... (更多内容省略)"
                
                stream_print("\n" + "=" * 50)
                stream_print("🎉 脚本生成成功")
                stream_print("=" * 50)
                stream_print(f"📁 保存路径: {save_path}")
                stream_print(f"🔧 工具名称: {tool_name}")
                stream_print(f"📋 工具描述: {tool_description}")
                stream_print("-" * 50)
                stream_print("📄 脚本预览:")
                stream_print(preview_lines)
                stream_print("-" * 50)
                stream_print("💡 提示: 您现在可以在扫描中使用此工具")
                stream_print("=" * 50)
                
                from TOSKill.AI.nodes import AIDecisionNode
                if hasattr(AIDecisionNode, '_instance'):
                    AIDecisionNode._instance = None
                
                res = {
                    "status": "success",
                    "path": save_path,
                    "tool_name": tool_name,
                    "description": tool_description
                }
                
                logger.info(f"脚本生成并注册成功: {tool_name} -> {save_path}")
            else:
                error_msg = register_result.get("error", "未知错误")
                stream_print(f"❌ 工具注册失败: {error_msg}")
                stream_print(f"💡 脚本已保存到: {save_path}")
                res = {
                    "status": "registration_failed",
                    "path": save_path,
                    "error": error_msg
                }
                
        except Exception as e:
            logger.error(f"脚本生成失败: {str(e)}")
            stream_print(f"❌ 脚本生成失败: {str(e)}")
            stream_print("💡 请重试或检查网络连接")
            res = {"status": "error", "error": str(e)}
    
    else:
        stream_print("\n📋 脚本管理菜单")
        stream_print("-" * 40)
        stream_print("【4】上传脚本 - 上传现有脚本并自动注册")
        stream_print("【5】生成脚本 - AI自动生成自定义脚本")
        stream_print("-" * 40)
        res = {"status": "menu_displayed"}
    
    new_state = append_chat_history(state, "system", f"脚本管理完成: {res}")
    new_state["need_generate_script"] = False
    new_state["task_history"] = state.get("task_history", []) + [f"[脚本管理] {res}"]
    
    return ensure_state_fields(new_state)


async def report_generation_atom(state: TOSKillState) -> TOSKillState:
    """原子6: 报告生成 - 增强版
    
    功能增强：
    - 收集所有 execution_history 数据
    - 收集所有 chat_history 数据
    - 收集所有 tool_results 数据
    - 收集 vulnerabilities 数据
    - 生成表格格式的报告
    """
    stream_print("\n" + "="*60)
    stream_print("🔹 原子6：生成AI分析报告（增强版）")
    
    from TOSKill.AI.nodes import ReportGenerationNode
    
    state = ensure_state_fields(state)
    
    validation = validate_state_integrity(state)
    if not validation["is_valid"]:
        logger.warning(f"状态验证警告: {validation['errors']}")
    
    agent_state = create_agent_state_from_toskill(state)
    
    agent_state.track_data_flow("input", "report_generation_atom")
    
    stream_print("📊 [阶段1/5] 收集扫描数据...")
    stream_print(f"   • 执行历史: {len(state['execution_history'])} 条记录")
    stream_print(f"   • 聊天记录: {len(state['chat_history'])} 条记录")
    stream_print(f"   • 工具结果: {len(state['tool_results'])} 个工具")
    stream_print(f"   • 漏洞数据: {len(state['vulnerabilities'])} 个漏洞")
    
    try:
        report_node = ReportGenerationNode()
        result_state = await report_node(agent_state)
        
        if result_state.report:
            stream_print("\n✅ [阶段5/5] 报告生成成功！")
            stream_print(f"📄 报告长度: {len(result_state.report)} 字符")
            
            report_file = f"reports/report_{state['task_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            os.makedirs("reports", exist_ok=True)
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(result_state.report)
            stream_print(f"📁 报告已保存: {report_file}")
            
            stream_print("\n" + "="*50)
            stream_print("📊 报告内容预览:")
            stream_print("="*50)
            preview_lines = result_state.report.split('\n')[:30]
            for line in preview_lines:
                stream_print(line)
            if len(result_state.report.split('\n')) > 30:
                stream_print("... (更多内容请查看完整报告)")
            stream_print("="*50)
        else:
            stream_print("\n❌ 报告生成失败")
            
    except Exception as e:
        logger.error(f"报告生成异常: {e}")
        stream_print(f"\n❌ 报告生成异常: {str(e)}")
        stream_print("💡 提示: 请检查日志获取详细信息")
        result_state = agent_state
        result_state.report = f"报告生成失败: {str(e)}"
    
    result_state.track_data_flow("report_generation_atom", "output")
    
    try:
        result_state.save_to_file()
        logger.info("最终状态已保存")
    except Exception as e:
        logger.warning(f"状态保存失败: {e}")
    
    new_state = extract_state_from_agent(result_state, state)
    new_state["is_complete"] = True
    
    return ensure_state_fields(new_state)


def atom_router(state: TOSKillState) -> str:
    """路由决策"""
    if state["need_generate_script"]:
        return "script_tool_atom"
    
    c = state["user_choice"]
    if c == "1": 
        return "execute_analyze_atom"
    if c == "2": 
        return "report_generation_atom"
    if c == "3": 
        return "chat_negotiate_atom"
    if c in ["4", "5"]: 
        return "script_tool_atom"
    if c == "0":
        current_mode = state["mode"]
        new_mode = "vuln_scan" if current_mode == "info_collection" else "info_collection"
        state["mode"] = new_mode
        stream_print(f"\n🔄 已切换到【{new_mode}】模式")
        return "ai_decision_atom"
    
    return "user_interact_atom"


async def build_workflow():
    """构建工作流"""
    from langgraph.graph import StateGraph, END
    from TOSKill.tools import ALL_TOOLS
    
    logger.info(f"✅ 工具初始化完成，已加载 {len(ALL_TOOLS)} 个工具 (Function Calling 模式)")
    
    workflow = StateGraph(TOSKillState)
    
    workflow.add_node("ai_decision_atom", ai_decision_atom)
    workflow.add_node("user_interact_atom", user_interact_atom)
    workflow.add_node("execute_analyze_atom", execute_analyze_atom)
    workflow.add_node("chat_negotiate_atom", chat_negotiate_atom)
    workflow.add_node("script_tool_atom", script_tool_atom)
    workflow.add_node("report_generation_atom", report_generation_atom)
    
    workflow.set_entry_point("ai_decision_atom")
    workflow.add_edge("ai_decision_atom", "user_interact_atom")
    workflow.add_conditional_edges("user_interact_atom", atom_router)
    
    workflow.add_edge("execute_analyze_atom", "ai_decision_atom")
    workflow.add_edge("chat_negotiate_atom", "ai_decision_atom")
    workflow.add_edge("script_tool_atom", "ai_decision_atom")
    workflow.add_edge("report_generation_atom", END)
    
    return workflow.compile()


async def main():
    """主函数"""
    print("=" * 60)
    print("  TOSKill AI - 终端交互式漏洞智能扫描系统")
    print("=" * 60)
    print()
    
    target = input("请输入扫描目标 (域名或URL): ").strip()
    if not target:
        print("目标不能为空!")
        return
    
    task_id = str(uuid.uuid4())[:8]
    print(f"\n任务ID: {task_id}")
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    print("请选择扫描模式:")
    print("【1】信息收集模式 - 收集目标基本信息")
    print("【2】漏洞扫描模式 - 检测安全漏洞")
    print("【3】完整扫描模式 - 信息收集+漏洞扫描")
    
    mode_choice = input("请输入选择 (默认: 1): ").strip() or "1"
    mode_map = {
        "1": "info_collection",
        "2": "vuln_scan",
        "3": "full_scan"
    }
    mode = mode_map.get(mode_choice, "info_collection")
    
    print(f"\n已选择模式: {mode}")
    print("\n初始化工作流...")
    
    initial_state = TOSKillState(
        target=target,
        task_id=task_id,
        mode=mode,
        planned_tasks=[],
        completed_tasks=[],
        tool_results={},
        vulnerabilities=[],
        target_context={},
        execution_history=[],
        is_complete=False,
        should_continue=True,
        next_action="",
        decision_history=[],
        errors=[],
        vuln_scan_results={},
        scan_summary={},
        report="",
        user_choice="",
        chat_history=[],
        chat_summary="无",
        user_name="用户",
        need_generate_script=False,
        next_task="",
        task_result={},
        task_history=[]
    )
    
    try:
        app = await build_workflow()
        stream_print("✅ 工作流构建完成！")
        
        print("\n" + "=" * 60)
        print("开始执行工作流...")
        print("=" * 60)
        
        final_state = await app.ainvoke(initial_state)
        
        print("\n" + "=" * 60)
        print("  工作流执行完成")
        print("=" * 60)
        print(f"\n目标: {final_state['target']}")
        print(f"完成任务数: {len(final_state['completed_tasks'])}")
        print(f"发现漏洞数: {len(final_state['vulnerabilities'])}")
        print(f"错误数: {len(final_state['errors'])}")
        
        if final_state['completed_tasks']:
            print(f"\n已完成任务:")
            for task in final_state['completed_tasks']:
                print(f"  - {task}")
        
        if final_state['vulnerabilities']:
            print(f"\n发现漏洞:")
            for vuln in final_state['vulnerabilities'][:10]:
                title = vuln.get('title', vuln.get('name', '未知漏洞'))
                severity = vuln.get('severity', 'info')
                print(f"  [{severity.upper()}] {title}")
        
        if final_state['tool_results']:
            print(f"\n工具结果摘要:")
            for tool_name in list(final_state['tool_results'].keys())[:5]:
                print(f"  - {tool_name}")
        
        if final_state['report']:
            print(f"\n报告已生成，长度: {len(final_state['report'])} 字符")
        
    except KeyboardInterrupt:
        stream_print("\n🛑 用户强制终止")
    except Exception as e:
        print(f"\n工作流执行出错: {e}")
        import traceback
        traceback.print_exc()
    
    stream_print("\n✅ 任务结束")


if __name__ == "__main__":
    asyncio.run(main())
