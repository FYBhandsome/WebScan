"""
LangGraph 原子化节点定义 - WebSocket交互版本

实现6个核心原子：
1. AI决策原子 - 智能决策下一步任务
2. 用户交互原子 - WebSocket用户交互
3. 执行分析原子 - 执行工具并分析结果
4. 聊天协商原子 - AI对话与记忆
5. 脚本管理原子 - 自定义脚本管理
6. 报告生成原子 - 生成AI分析报告

所有节点通过WebSocket与前端交互，不使用命令行输入。
"""
import logging
import json
import os
import time
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from .state import AgentState
from .agent_config import agent_config
from TOSKill.tools import ALL_TOOLS

logger = logging.getLogger(__name__)


def append_chat_history(state: AgentState, role: str, content: str) -> AgentState:
    """追加聊天历史"""
    state.append_chat_history(role, content)
    return state


class AIDecisionNode:
    """AI全局决策原子 - WebSocket版本"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        self.available_tool_names = [tool.name for tool in ALL_TOOLS]
        self.tools_description = self._build_tools_description()
        logger.info(f"AI决策原子初始化完成，已加载 {len(ALL_TOOLS)} 个工具")
    
    def _format_status_message(self, stage: str, progress: int, message: str) -> str:
        """格式化状态消息"""
        return f"[{stage}] 进度: {progress}% | {message}"
    
    def _build_tools_description(self) -> str:
        """构建工具描述文本"""
        descriptions = []
        for tool in ALL_TOOLS:
            desc = f"- {tool.name}: {tool.description[:100] if hasattr(tool, 'description') else '扫描工具'}"
            descriptions.append(desc)
        return "\n".join(descriptions)
    
    def _check_target_reachable(self, state: AgentState) -> Dict[str, Any]:
        """检查目标可达性
        
        基于执行历史判断目标是否可达：
        - 检查是否有成功的网络请求记录
        - 检查是否有连接超时或拒绝连接等错误
        
        Args:
            state: Agent状态
            
        Returns:
            包含可达性信息的字典
        """
        result = {
            "reachable": True,
            "confidence": "high",
            "reason": "目标可达",
            "suggestions": []
        }
        
        if not state.execution_history:
            result["confidence"] = "low"
            result["reason"] = "尚未执行任何扫描任务，无法判断目标可达性"
            return result
        
        success_count = 0
        failure_count = 0
        connection_errors = []
        
        for record in state.execution_history:
            if record.get("success"):
                success_count += 1
            else:
                failure_count += 1
                error = record.get("error", "")
                if any(keyword in error.lower() for keyword in 
                       ["timeout", "connection refused", "unreachable", "dns", "resolve"]):
                    connection_errors.append({
                        "tool": record.get("tool_name", "unknown"),
                        "error": error[:100]
                    })
        
        total = success_count + failure_count
        
        if connection_errors and len(connection_errors) >= 2:
            result["reachable"] = False
            result["confidence"] = "high"
            result["reason"] = f"检测到多个连接错误，目标可能不可达"
            result["suggestions"] = [
                "检查目标地址是否正确",
                "检查网络连接",
                "确认目标是否在线",
                "尝试使用代理或VPN"
            ]
        elif failure_count > success_count and total >= 3:
            result["reachable"] = True
            result["confidence"] = "medium"
            result["reason"] = f"部分任务失败({failure_count}/{total})，目标可能存在防护措施"
            result["suggestions"] = [
                "目标可能有WAF/CDN防护",
                "建议先进行WAF检测",
                "考虑降低扫描频率"
            ]
        elif success_count > 0:
            result["reachable"] = True
            result["confidence"] = "high"
            result["reason"] = f"已有{success_count}个任务成功执行"
        
        return result
    
    def _get_failed_tools(self, state: AgentState) -> List[str]:
        """获取已失败的工具列表
        
        从 state.errors 中提取失败的工具名称
        
        Args:
            state: Agent状态
            
        Returns:
            失败工具名称列表
        """
        failed_tools = []
        for error in state.errors:
            if ":" in error:
                tool_name = error.split(":")[0].strip()
                if tool_name and tool_name not in failed_tools:
                    failed_tools.append(tool_name)
        return failed_tools
    
    def _format_execution_history_summary(self, state: AgentState, limit: int = 5) -> str:
        """格式化执行历史摘要
        
        生成最近N条执行历史的简要描述
        
        Args:
            state: Agent状态
            limit: 最大历史条数，默认5条
            
        Returns:
            格式化的执行历史摘要
        """
        if not state.execution_history:
            return "暂无执行历史"
        
        recent_history = state.execution_history[-limit:]
        summary_lines = []
        
        for idx, record in enumerate(recent_history, 1):
            tool_name = record.get("tool_name", "unknown")
            success = record.get("success", False)
            exec_time = record.get("execution_time", 0)
            status_icon = "✅" if success else "❌"
            
            key_finding = ""
            result = record.get("result", {})
            if isinstance(result, dict):
                if result.get("vulnerabilities"):
                    vulns = result["vulnerabilities"]
                    if isinstance(vulns, list):
                        key_finding = f"发现{len(vulns)}个漏洞"
                elif result.get("ports"):
                    ports = result["ports"]
                    if isinstance(ports, list):
                        key_finding = f"发现{len(ports)}个端口"
                elif result.get("subdomains"):
                    subs = result["subdomains"]
                    if isinstance(subs, list):
                        key_finding = f"发现{len(subs)}个子域名"
            
            if not key_finding:
                key_finding = record.get("error", "无特殊发现")[:50] if not success else "执行成功"
            
            summary_lines.append(
                f"{idx}. {status_icon} {tool_name} ({exec_time:.1f}s) - {key_finding}"
            )
        
        return "\n".join(summary_lines)
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] AI决策节点开始执行")
        
        try:
            await state.send_ai_message("🔍 [阶段1/6] 正在初始化AI决策引擎...")
            await state.send_ai_message(self._format_status_message("AI决策", 10, "加载工具列表和配置"))
            
            await state.send_ai_message("📊 [阶段2/6] 分析当前扫描状态...")
            await state.send_ai_message(self._format_status_message("AI决策", 30, f"目标: {state.target}"))
            await state.send_ai_message(f"   • 已完成任务: {len(state.completed_tasks)} 个")
            await state.send_ai_message(f"   • 已发现漏洞: {len(state.vulnerabilities)} 个")
            
            failed_tools = self._get_failed_tools(state)
            reachable_info = self._check_target_reachable(state)
            execution_summary = self._format_execution_history_summary(state, limit=5)
            
            failed_tasks_list = "\n".join([f"  - {tool}: 执行失败" for tool in failed_tools]) if failed_tools else "  暂无失败任务"
            
            reachable_status = f"{'✅ 可达' if reachable_info['reachable'] else '❌ 不可达'} (置信度: {reachable_info['confidence']})"
            reachable_suggestions = "\n".join([f"  - {s}" for s in reachable_info.get("suggestions", [])]) if reachable_info.get("suggestions") else "  无"
            
            available_tools = [t for t in self.available_tool_names if t not in failed_tools]
            available_tools_str = ", ".join(available_tools) if available_tools else "baseinfo"
            
            system_prompt = f"""你是Web安全扫描调度器，负责分析当前状态并选择最合适的工具执行下一步扫描任务。

## 可用工具列表
{self.tools_description}

## 决策规则
1. 根据目标特点和已完成任务，选择最合适的工具
2. 优先执行信息收集类工具（如 baseinfo, portscan, subdomain 等）
3. 信息收集完成后，执行漏洞扫描工具（如 sqli_scan, xss_scan 等）
4. 每次只选择一个最优先的工具
5. 必须以JSON格式回复，格式为: {{"tool": "工具名称", "reason": "选择原因"}}
6. **重要**: 不要选择已失败的工具，避免重复执行失败任务

## 工具选择策略
- 首次扫描：baseinfo（基础信息收集）
- 端口探测：portscan
- 子域名收集：subdomain
- 目录扫描：dirscan
- WAF检测：waf_detect
- CDN检测：cdn_detect
- CMS识别：cms_detect
- 漏洞扫描：sqli_scan, xss_scan, csrf_scan 等"""

            user_prompt = f"""
## 当前状态
- 目标: {state.target}
- 已完成任务: {state.completed_tasks}
- 聊天历史总结: {state.chat_summary}
- 已发现漏洞: {len(state.vulnerabilities)}个

## 目标可达性检查
- 状态: {reachable_status}
- 原因: {reachable_info['reason']}
- 建议:
{reachable_suggestions}

## 失败任务列表（请勿重复选择）
{failed_tasks_list}

## 最近执行历史（最近5条）
{execution_summary}

## 可选工具（已排除失败工具）
{available_tools_str}

请分析当前状态，选择下一个要执行的工具。**注意**: 不要选择失败任务列表中的工具。只返回JSON，不要其他内容。"""
            
            await state.send_ai_message("🧠 [阶段3/6] 正在进行AI智能分析...")
            await state.send_ai_message(self._format_status_message("AI决策", 50, "调用大语言模型进行决策"))
            
            from langchain_core.messages import SystemMessage, HumanMessage
            
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            
            await state.send_ai_message("📝 [阶段4/6] 解析AI决策结果...")
            await state.send_ai_message(self._format_status_message("AI决策", 70, "解析JSON响应"))
            
            import json
            try:
                response_text = response.content.strip()
                if response_text.startswith("```"):
                    response_text = response_text.split("```")[1]
                    if response_text.startswith("json"):
                        response_text = response_text[4:]
                response_text = response_text.strip()
                
                decision = json.loads(response_text)
                tool_name = decision.get("tool", "baseinfo")
                reason = decision.get("reason", "")
                
                await state.send_ai_message("✅ [阶段5/6] 决策完成，准备执行...")
                
                if tool_name in failed_tools:
                    alternative_tools = [t for t in self.available_tool_names if t not in failed_tools and t not in state.completed_tasks]
                    if alternative_tools:
                        alternative_tool = alternative_tools[0]
                        state.planned_tasks = [alternative_tool]
                        state.need_generate_script = False
                        
                        await state.send_decision(
                            action="execute_tools",
                            reason=f"工具 {tool_name} 已失败，自动选择替代工具: {alternative_tool}",
                            tools=[alternative_tool]
                        )
                        
                        await state.send_ai_message(self._format_status_message("AI决策", 90, f"使用替代工具: {alternative_tool}"))
                        await state.send_ai_message(f"⚠️ 工具 {tool_name} 已在失败列表中")
                        await state.send_ai_message(f"📋 已自动切换为替代工具: {alternative_tool}")
                        await state.send_ai_message(f"   • 剩余可用工具: {len(alternative_tools)} 个")
                        
                        logger.warning(f"[AI决策] 工具 {tool_name} 已失败，使用替代: {alternative_tool}")
                    else:
                        state.planned_tasks = ["baseinfo"]
                        state.need_generate_script = False
                        
                        await state.send_decision(
                            action="execute_tools",
                            reason="所有工具均已失败或已完成，尝试使用默认工具 baseinfo",
                            tools=["baseinfo"]
                        )
                        
                        await state.send_ai_message(self._format_status_message("AI决策", 90, "所有工具已处理"))
                        await state.send_ai_message(f"⚠️ 所有可用工具均已失败或已完成")
                        await state.send_ai_message(f"📋 尝试使用默认工具: baseinfo")
                        
                        logger.warning(f"[AI决策] 所有工具已处理，使用默认: baseinfo")
                elif tool_name in self.available_tool_names:
                    state.planned_tasks = [tool_name]
                    state.need_generate_script = False
                    
                    await state.send_decision(
                        action="execute_tools",
                        reason=reason or f"根据当前状态分析，建议执行: {tool_name}",
                        tools=[tool_name]
                    )
                    
                    await state.send_ai_message(self._format_status_message("AI决策", 90, f"选择工具: {tool_name}"))
                    await state.send_ai_message(f"📋 决策结果:")
                    await state.send_ai_message(f"   • 推荐工具: {tool_name}")
                    await state.send_ai_message(f"   • 选择原因: {reason or '基于当前状态的最佳选择'}")
                    await state.send_ai_message(f"   • 可用工具数: {len(available_tools)}")
                    
                    logger.info(f"[AI决策] 选择工具: {tool_name}, 原因: {reason}")
                else:
                    alternative_tools = [t for t in self.available_tool_names if t not in failed_tools]
                    fallback_tool = alternative_tools[0] if alternative_tools else "baseinfo"
                    state.planned_tasks = [fallback_tool]
                    state.need_generate_script = False
                    
                    await state.send_decision(
                        action="execute_tools",
                        reason=f"工具 {tool_name} 不在可用列表中，使用替代工具 {fallback_tool}",
                        tools=[fallback_tool]
                    )
                    
                    await state.send_ai_message(self._format_status_message("AI决策", 90, f"使用替代工具: {fallback_tool}"))
                    await state.send_ai_message(f"⚠️ 工具 {tool_name} 不在可用列表中")
                    await state.send_ai_message(f"📋 已切换为替代工具: {fallback_tool}")
                    
                    logger.warning(f"[AI决策] 无效工具: {tool_name}, 使用替代: {fallback_tool}")
                    
            except json.JSONDecodeError as e:
                state.planned_tasks = ["baseinfo"]
                state.need_generate_script = False
                
                await state.send_decision(
                    action="execute_tools",
                    reason="AI响应格式解析失败，使用默认工具 baseinfo",
                    tools=["baseinfo"]
                )
                
                await state.send_ai_message(self._format_status_message("AI决策", 90, "JSON解析失败，使用默认工具"))
                await state.send_ai_message(f"⚠️ AI响应格式解析失败")
                await state.send_ai_message(f"📋 已切换为默认工具: baseinfo")
                await state.send_ai_message(f"💡 提示: 将继续执行默认扫描任务")
                
                logger.warning(f"[AI决策] JSON解析失败，使用默认: baseinfo, 错误: {e}")
            
            await state.send_ai_message("✅ [阶段6/6] AI决策流程完成")
            await state.send_ai_message(self._format_status_message("AI决策", 100, "决策完成，准备执行任务"))
            
        except Exception as e:
            logger.error(f"AI决策失败: {e}")
            state.planned_tasks = ["baseinfo"]
            state.need_generate_script = False
            
            await state.send_error(f"❌ AI决策异常: {str(e)}")
            await state.send_error(f"📋 已自动切换为默认工具: baseinfo")
            await state.send_error(f"💡 提示: 系统将使用默认扫描策略继续执行")
        
        return state


class UserInteractNode:
    """用户交互原子 - WebSocket版本"""
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 用户交互节点开始执行")
        
        try:
            await state.send_ai_message("👤 [阶段1/3] 准备用户交互...")
            
            next_task = state.planned_tasks[0] if state.planned_tasks else "无"
            
            await state.send_ai_message("📋 [阶段2/3] 显示当前状态和选项...")
            await state.send_ai_message(f"")
            await state.send_ai_message(f"════════════════════════════════════════")
            await state.send_ai_message(f"📌 当前扫描状态")
            await state.send_ai_message(f"════════════════════════════════════════")
            await state.send_ai_message(f"🎯 目标地址: {state.target}")
            await state.send_ai_message(f"🔄 扫描模式: {state.next_mode}")
            await state.send_ai_message(f"📋 下一步任务: {next_task}")
            await state.send_ai_message(f"✅ 已完成任务: {len(state.completed_tasks)} 个")
            await state.send_ai_message(f"🔍 发现漏洞: {len(state.vulnerabilities)} 个")
            await state.send_ai_message(f"════════════════════════════════════════")
            
            prompt = f"""请确认是否继续执行以下操作：

**目标**: {state.target}
**模式**: {state.next_mode}
**下一步任务**: {next_task}

请选择操作：
1. 确认执行
2. 取消执行
3. 跳过当前任务"""

            result = await state.request_user_confirmation(
                prompt=prompt,
                options=["confirm", "cancel", "skip"]
            )
            
            state.user_choice = "1" if result == "confirm" else ("2" if result == "cancel" else "3")
            
            await state.send_ai_message("✅ [阶段3/3] 用户选择已记录...")
            
            choice_messages = {
                "1": "✅ 用户确认执行任务",
                "2": "🛑 用户取消执行任务",
                "3": "⏭️ 用户跳过当前任务"
            }
            await state.send_ai_message(choice_messages.get(state.user_choice, "用户选择已记录"))
            
            logger.info(f"[用户交互] 选择: {result}")
            
        except Exception as e:
            logger.error(f"用户交互失败: {e}")
            await state.send_error(f"❌ 用户交互异常: {str(e)}")
            await state.send_error(f"💡 提示: 使用默认选择继续执行")
            state.user_choice = "1"
        
        return state


class ExecuteAnalyzeNode:
    """执行任务并分析原子 - WebSocket版本"""
    
    MAX_TOOL_CHAIN_DEPTH = 5
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        self._tools_cache: Dict[str, Any] = {}
        logger.info("执行分析原子初始化完成 (WebSocket模式)")
    
    def _get_tools_schema(self) -> List[Dict[str, Any]]:
        """获取所有工具的 OpenAI Function Calling Schema"""
        from TOSKill.tools import get_all_tool_names, get_tool_by_name
        
        schemas = []
        for tool_name in get_all_tool_names():
            tool = get_tool_by_name(tool_name)
            if tool:
                self._tools_cache[tool_name] = tool
                schema = {
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "description": tool.description if hasattr(tool, 'description') else f"执行 {tool_name} 扫描",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "目标URL、域名或IP地址"
                                }
                            },
                            "required": ["target"]
                        }
                    }
                }
                schemas.append(schema)
        
        return schemas
    
    def _get_tool_by_name(self, name: str):
        """获取工具实例"""
        if name in self._tools_cache:
            return self._tools_cache[name]
        
        from TOSKill.tools import get_tool_by_name
        tool = get_tool_by_name(name)
        if tool:
            self._tools_cache[name] = tool
        return tool
    
    def _get_failed_tools_from_errors(self, state: AgentState) -> List[str]:
        """从 errors 中提取失败的工具名称
        
        Args:
            state: Agent状态
            
        Returns:
            失败工具名称列表
        """
        failed_tools = []
        for error in state.errors:
            if ":" in error:
                tool_name = error.split(":")[0].strip()
                if tool_name and tool_name not in failed_tools:
                    failed_tools.append(tool_name)
        return failed_tools
    
    def _check_tool_suitable_for_mode(self, tool_name: str, mode: str) -> Dict[str, Any]:
        """检查工具是否适合当前模式
        
        Args:
            tool_name: 工具名称
            mode: 当前模式
            
        Returns:
            包含检查结果的字典 {"suitable": bool, "reason": str}
        """
        mode_tool_mapping = {
            "quick": {
                "allowed": ["baseinfo", "portscan", "waf_detect", "cdn_detect"],
                "description": "快速扫描模式"
            },
            "standard": {
                "allowed": ["baseinfo", "portscan", "subdomain", "dirscan", "waf_detect", "cdn_detect", "cms_detect", "sqli_scan", "xss_scan"],
                "description": "标准扫描模式"
            },
            "deep": {
                "allowed": None,
                "description": "深度扫描模式（允许所有工具）"
            },
            "stealth": {
                "allowed": ["baseinfo", "subdomain", "cdn_detect"],
                "description": "隐蔽扫描模式"
            }
        }
        
        if mode not in mode_tool_mapping:
            return {"suitable": True, "reason": f"未知模式 '{mode}'，默认允许执行"}
        
        mode_config = mode_tool_mapping[mode]
        allowed_tools = mode_config["allowed"]
        
        if allowed_tools is None:
            return {"suitable": True, "reason": f"{mode_config['description']}，允许所有工具"}
        
        if tool_name in allowed_tools:
            return {"suitable": True, "reason": f"工具 '{tool_name}' 适合 {mode_config['description']}"}
        else:
            return {
                "suitable": False,
                "reason": f"工具 '{tool_name}' 不适合 {mode_config['description']}，允许的工具: {', '.join(allowed_tools)}"
            }
    
    def _check_tool_before_execution(self, tool_name: str, state: AgentState) -> Dict[str, Any]:
        """工具执行前的综合检查
        
        Args:
            tool_name: 工具名称
            state: Agent状态
            
        Returns:
            包含检查结果的字典 {"can_execute": bool, "reason": str, "skip": bool}
        """
        if tool_name in state.completed_tasks:
            return {
                "can_execute": False,
                "reason": f"工具 '{tool_name}' 已在 completed_tasks 中，跳过执行",
                "skip": True
            }
        
        failed_tools = self._get_failed_tools_from_errors(state)
        if tool_name in failed_tools:
            return {
                "can_execute": False,
                "reason": f"工具 '{tool_name}' 在失败列表中，跳过执行",
                "skip": True
            }
        
        mode_check = self._check_tool_suitable_for_mode(tool_name, state.next_mode)
        if not mode_check["suitable"]:
            return {
                "can_execute": False,
                "reason": mode_check["reason"],
                "skip": True
            }
        
        return {
            "can_execute": True,
            "reason": f"工具 '{tool_name}' 通过所有检查，可以执行",
            "skip": False
        }
    
    async def _execute_tool(self, tool_name: str, target: str, state: AgentState) -> Dict[str, Any]:
        """执行单个工具"""
        start_time = time.time()
        
        pre_check = self._check_tool_before_execution(tool_name, state)
        if not pre_check["can_execute"]:
            logger.warning(f"[工具检查] {pre_check['reason']}")
            await state.send_ai_message(f"⏭️ [跳过工具] {tool_name}")
            await state.send_ai_message(f"   • 原因: {pre_check['reason']}")
            return {
                "success": False,
                "error": pre_check["reason"],
                "data": None,
                "execution_time": 0,
                "skipped": True
            }
        
        tool = self._get_tool_by_name(tool_name)
        
        if not tool:
            await state.send_error(f"❌ 工具 {tool_name} 不存在")
            return {
                "success": False,
                "error": f"工具 {tool_name} 不存在",
                "data": None,
                "execution_time": 0
            }
        
        await state.send_ai_message(f"🔧 [执行工具] {tool_name}")
        await state.send_ai_message(f"   • 目标: {target}")
        await state.send_ai_message(f"   • 状态: 正在执行...")
        await state.send_tool_execution_start(tool_name, f"正在执行 {tool_name} 扫描")
        
        try:
            if hasattr(tool, 'invoke'):
                result = tool.invoke(target)
            elif hasattr(tool, 'run'):
                result = tool.run(target)
            elif callable(tool):
                result = tool(target)
            else:
                await state.send_error(f"❌ 工具 {tool_name} 不可调用")
                return {
                    "success": False,
                    "error": f"工具 {tool_name} 不可调用",
                    "data": None,
                    "execution_time": time.time() - start_time
                }
            
            execution_time = time.time() - start_time
            
            if isinstance(result, dict):
                result["execution_time"] = execution_time
                await state.send_ai_message(f"   • 耗时: {execution_time:.2f}秒")
                await state.send_ai_message(f"   • 状态: ✅ 执行成功")
                return result
            
            await state.send_ai_message(f"   • 耗时: {execution_time:.2f}秒")
            await state.send_ai_message(f"   • 状态: ✅ 执行成功")
            return {
                "success": True,
                "data": result,
                "error": None,
                "execution_time": execution_time
            }
        except Exception as e:
            execution_time = time.time() - start_time
            error_str = str(e)
            
            error_info = self._analyze_error_type(error_str)
            
            failure_result = await self._handle_tool_failure(
                tool_name=tool_name,
                error_str=error_str,
                error_info=error_info,
                state=state,
                execution_time=execution_time
            )
            
            logger.error(f"工具执行失败: {tool_name} - {error_str} (类型: {error_info['type']})")
            
            return failure_result
    
    def _analyze_error_type(self, error_str: str) -> Dict[str, Any]:
        """分析错误类型
        
        根据错误信息判断错误类型，返回错误分类和处理策略
        
        Args:
            error_str: 错误信息字符串
            
        Returns:
            包含错误类型、严重程度、处理策略等信息的字典
        """
        error_lower = error_str.lower()
        
        error_patterns = {
            "network": {
                "keywords": ["connection refused", "connection reset", "network unreachable", 
                           "no route to host", "network error", "socket error", "connection error",
                           "连接被拒绝", "网络不可达", "网络错误"],
                "severity": "high",
                "retryable": True,
                "skip_similar": True,
                "suggestion": "目标主机可能不可达或网络配置问题"
            },
            "timeout": {
                "keywords": ["timeout", "timed out", "超时", "time out"],
                "severity": "medium",
                "retryable": True,
                "skip_similar": False,
                "suggestion": "请求超时，可能是目标响应慢或网络延迟高"
            },
            "permission": {
                "keywords": ["permission denied", "access denied", "forbidden", 
                           "unauthorized", "权限不足", "拒绝访问", "认证失败"],
                "severity": "medium",
                "retryable": False,
                "skip_similar": False,
                "suggestion": "权限不足，可能需要认证或更高的访问权限"
            },
            "dns": {
                "keywords": ["dns", "name resolution", "域名解析", "resolve", 
                           "getaddrinfo", "no such host"],
                "severity": "high",
                "retryable": False,
                "skip_similar": True,
                "suggestion": "DNS解析失败，目标域名可能不存在或DNS配置错误"
            },
            "ssl": {
                "keywords": ["ssl", "tls", "certificate", "cert", "ssl error",
                           "handshake", "加密"],
                "severity": "low",
                "retryable": False,
                "skip_similar": False,
                "suggestion": "SSL/TLS证书问题，可以尝试忽略证书验证"
            },
            "rate_limit": {
                "keywords": ["rate limit", "too many requests", "429", "限流", 
                           "频率限制", "请求过快"],
                "severity": "medium",
                "retryable": True,
                "skip_similar": False,
                "suggestion": "请求频率过高被限制，建议降低扫描速度"
            },
            "waf": {
                "keywords": ["waf", "web application firewall", "blocked", 
                           "拦截", "防火墙", "cloudflare", "安全防护"],
                "severity": "medium",
                "retryable": False,
                "skip_similar": True,
                "suggestion": "目标可能部署了WAF防护，建议先进行WAF检测"
            },
            "resource": {
                "keywords": ["memory", "cpu", "resource", "内存", "资源不足",
                           "out of memory", "资源耗尽"],
                "severity": "high",
                "retryable": True,
                "skip_similar": True,
                "suggestion": "系统资源不足，建议释放资源后重试"
            },
            "config": {
                "keywords": ["config", "configuration", "配置", "setting",
                           "invalid", "参数错误", "配置错误"],
                "severity": "low",
                "retryable": False,
                "skip_similar": False,
                "suggestion": "工具配置错误，请检查工具参数设置"
            },
            "target_invalid": {
                "keywords": ["invalid url", "invalid target", "invalid host",
                           "无效的目标", "目标格式错误", "malformed"],
                "severity": "high",
                "retryable": False,
                "skip_similar": True,
                "suggestion": "目标地址格式无效，请检查目标URL/域名"
            }
        }
        
        for error_type, config in error_patterns.items():
            for keyword in config["keywords"]:
                if keyword in error_lower:
                    return {
                        "type": error_type,
                        "severity": config["severity"],
                        "retryable": config["retryable"],
                        "skip_similar": config["skip_similar"],
                        "suggestion": config["suggestion"],
                        "original_error": error_str
                    }
        
        return {
            "type": "unknown",
            "severity": "medium",
            "retryable": True,
            "skip_similar": False,
            "suggestion": "未知错误类型，建议查看详细日志",
            "original_error": error_str
        }
    
    async def _handle_tool_failure(
        self, 
        tool_name: str, 
        error_str: str, 
        error_info: Dict[str, Any],
        state: AgentState,
        execution_time: float
    ) -> Dict[str, Any]:
        """处理工具失败
        
        根据错误类型选择合适的处理策略：
        1. 将失败工具添加到errors列表
        2. 根据错误类型决定是否跳过相似工具
        3. 尝试选择替代工具
        
        Args:
            tool_name: 失败的工具名称
            error_str: 错误信息
            error_info: 错误分析结果
            state: Agent状态
            execution_time: 执行时间
            
        Returns:
            处理结果字典
        """
        error_type = error_info["type"]
        severity = error_info["severity"]
        suggestion = error_info["suggestion"]
        
        state.errors.append(f"{tool_name}: {error_str}")
        
        severity_icons = {
            "high": "🔴",
            "medium": "🟠",
            "low": "🟡"
        }
        severity_icon = severity_icons.get(severity, "⚪")
        
        await state.send_error(f"❌ 工具执行失败: {tool_name}")
        await state.send_error(f"   • 错误类型: {error_type}")
        await state.send_error(f"   • 严重程度: {severity_icon} {severity}")
        await state.send_error(f"   • 错误信息: {error_str[:100]}")
        await state.send_error(f"   • 耗时: {execution_time:.2f}秒")
        await state.send_error(f"   • 建议: {suggestion}")
        
        if error_info["skip_similar"]:
            similar_tools = self._get_similar_tools(tool_name)
            for similar_tool in similar_tools:
                if similar_tool not in [e.split(":")[0].strip() for e in state.errors]:
                    state.errors.append(f"{similar_tool}: 因相关工具 {tool_name} 失败而跳过")
                    await state.send_ai_message(f"⚠️ 跳过相似工具: {similar_tool} (原因: {tool_name} 失败)")
        
        alternative_tools = self._get_alternative_tools(tool_name, error_type, state)
        if alternative_tools:
            await state.send_ai_message(f"💡 建议替代工具: {', '.join(alternative_tools[:3])}")
        
        result = {
            "success": False,
            "error": error_str,
            "error_type": error_type,
            "error_severity": severity,
            "suggestion": suggestion,
            "data": None,
            "execution_time": execution_time,
            "retryable": error_info["retryable"]
        }
        
        return result
    
    def _get_similar_tools(self, tool_name: str) -> List[str]:
        """获取相似工具列表
        
        根据工具名称和功能，返回可能受影响的相似工具
        
        Args:
            tool_name: 工具名称
            
        Returns:
            相似工具名称列表
        """
        tool_categories = {
            "portscan": ["nmap_scan", "masscan_scan"],
            "subdomain": ["subfinder", "amass_scan", "dns_enum"],
            "dirscan": ["gobuster", "dirsearch", "ffuf"],
            "sqli_scan": ["sqlmap"],
            "xss_scan": ["xsser"],
            "vuln_scan": ["nikto", "wpscan"],
            "baseinfo": ["whatweb", "waf_detect"],
            "waf_detect": ["cdn_detect"],
            "cdn_detect": ["waf_detect"]
        }
        
        similar = []
        for key, related in tool_categories.items():
            if key == tool_name:
                similar.extend(related)
            elif tool_name in related:
                similar.append(key)
                similar.extend([t for t in related if t != tool_name])
        
        return list(set(similar))
    
    def _get_alternative_tools(
        self, 
        failed_tool: str, 
        error_type: str, 
        state: AgentState
    ) -> List[str]:
        """获取替代工具列表
        
        根据失败工具和错误类型，推荐可用的替代工具
        
        Args:
            failed_tool: 失败的工具名称
            error_type: 错误类型
            state: Agent状态
            
        Returns:
            推荐的替代工具列表
        """
        failed_tools = set()
        for error in state.errors:
            if ":" in error:
                failed_tools.add(error.split(":")[0].strip())
        
        alternative_map = {
            "portscan": ["baseinfo", "subdomain", "dirscan"],
            "subdomain": ["baseinfo", "portscan", "dirscan"],
            "dirscan": ["baseinfo", "portscan", "vuln_scan"],
            "sqli_scan": ["xss_scan", "csrf_scan", "vuln_scan"],
            "xss_scan": ["sqli_scan", "csrf_scan", "vuln_scan"],
            "vuln_scan": ["baseinfo", "portscan", "dirscan"],
            "baseinfo": ["portscan", "subdomain", "waf_detect"],
            "waf_detect": ["baseinfo", "cdn_detect"],
            "cdn_detect": ["baseinfo", "waf_detect"]
        }
        
        alternatives = alternative_map.get(failed_tool, ["baseinfo"])
        
        valid_alternatives = [
            tool for tool in alternatives 
            if tool not in failed_tools 
            and tool not in state.completed_tasks
        ]
        
        if error_type in ["network", "dns", "target_invalid"]:
            network_tools = ["baseinfo", "waf_detect", "cdn_detect"]
            valid_alternatives = [
                tool for tool in valid_alternatives 
                if tool in network_tools
            ]
        
        return valid_alternatives
    
    async def _process_tool_calls(self, tool_calls: List[Any], state: AgentState) -> List[Dict[str, Any]]:
        """处理工具调用列表"""
        results = []
        
        for tool_call in tool_calls:
            tool_name = tool_call.function.name
            try:
                args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                args = {"target": state.target}
            
            target = args.get("target", state.target)
            
            await state.send_ai_message(f"正在调用工具: {tool_name}")
            
            result = await self._execute_tool(tool_name, target, state)
            result["tool_call_id"] = tool_call.id
            results.append(result)
            
            state.tool_results[tool_name] = result.get("data", {})
            
            if result.get("success") and "vulnerabilities" in result.get("data", {}):
                vulns = result["data"]["vulnerabilities"]
                if isinstance(vulns, list):
                    state.vulnerabilities.extend(vulns)
            
            await state.send_tool_execution_result(
                tool_name, 
                result.get("success", False),
                result.get("data"),
                result.get("error")
            )
            
            if result.get("success"):
                state.completed_tasks.append(tool_name)
            else:
                state.errors.append(f"{tool_name}: {result.get('error', '未知错误')}")
        
        return results
    
    def _format_scan_result(self, tool_name: str, target: str, result: Dict[str, Any]) -> str:
        """格式化扫描结果输出"""
        success = result.get("success", False)
        execution_time = result.get("execution_time", 0)
        data = result.get("data", {})
        error = result.get("error")
        
        lines = [
            "=" * 60,
            f"📊 扫描结果报告",
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
    
    def _generate_result_summary(self, tool_name: str, result: Dict[str, Any]) -> str:
        """生成扫描结果摘要"""
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

    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 执行分析节点开始执行")
        
        try:
            if state.planned_tasks:
                total_tasks = len(state.planned_tasks)
                await state.send_ai_message(f"🚀 [阶段1/4] 开始执行计划任务...")
                await state.send_ai_message(f"   • 任务总数: {total_tasks}")
                await state.send_ai_message(f"   • 任务列表: {', '.join(state.planned_tasks)}")
                
                for idx, task in enumerate(state.planned_tasks, 1):
                    progress = int((idx / total_tasks) * 100)
                    await state.send_ai_message(f"")
                    await state.send_ai_message(f"════════════════════════════════════════")
                    await state.send_ai_message(f"📋 任务进度: [{idx}/{total_tasks}] ({progress}%)")
                    await state.send_ai_message(f"════════════════════════════════════════")
                    
                    pre_check = self._check_tool_before_execution(task, state)
                    if not pre_check["can_execute"]:
                        logger.info(f"[工具检查] 跳过工具 {task}: {pre_check['reason']}")
                        await state.send_ai_message(f"⏭️ 跳过任务: {task}")
                        await state.send_ai_message(f"   • 原因: {pre_check['reason']}")
                        continue
                    
                    start_time = time.time()
                    result = await self._execute_tool(task, state.target, state)
                    execution_time = time.time() - start_time
                    
                    if result.get("skipped"):
                        logger.info(f"[工具执行] 工具 {task} 被跳过: {result.get('error')}")
                        continue
                    
                    timestamp = datetime.now().isoformat()
                    
                    execution_record = {
                        "task": task,
                        "tool_name": task,
                        "target": state.target,
                        "result": result.get("data", {}),
                        "success": result.get("success", False),
                        "timestamp": timestamp,
                        "execution_time": result.get("execution_time", execution_time),
                        "error": result.get("error")
                    }
                    state.execution_history.append(execution_record)
                    
                    formatted_result = self._format_scan_result(task, state.target, result)
                    logger.info(f"\n{formatted_result}")
                    
                    if result.get("success"):
                        state.tool_results[task] = result.get("data", {})
                        state.completed_tasks.append(task)
                        
                        await state.send_ai_message(f"✅ 任务完成: {task}")
                        
                        if "vulnerabilities" in result.get("data", {}):
                            vulns = result["data"]["vulnerabilities"]
                            if isinstance(vulns, list):
                                state.vulnerabilities.extend(vulns)
                                await state.send_ai_message(f"   • 发现漏洞: {len(vulns)} 个")
                    else:
                        error_msg = result.get("error", "未知错误")
                        state.errors.append(f"{task}: {error_msg}")
                        await state.send_error(f"❌ 任务失败: {task}")
                        await state.send_error(f"   • 错误: {error_msg}")
                    
                    result_summary = self._generate_result_summary(task, result)
                    state.append_chat_history("system", f"[扫描完成] {result_summary}")
                    
                    await state.send_ai_message(f"📊 任务摘要: {result_summary}")
            
            await state.send_ai_message(f"")
            await state.send_ai_message(f"🧠 [阶段2/4] 分析扫描结果...")
            
            if state.tool_results:
                analysis = await self._analyze_results(state.tool_results)
                
                tool_count = len(state.completed_tasks)
                vulnerability_count = len(state.vulnerabilities)
                success_count = sum(1 for t in state.completed_tasks if t in state.tool_results)
                success_rate = (success_count / tool_count * 100) if tool_count > 0 else 0
                
                state.scan_summary = {
                    "analysis": analysis,
                    "timestamp": datetime.now().isoformat(),
                    "tool_count": tool_count,
                    "vulnerability_count": vulnerability_count,
                    "success_rate": round(success_rate, 2)
                }
                
                state.append_chat_history("assistant", analysis)
                
                await state.send_ai_message(f"📈 [阶段3/4] 生成分析报告...")
                await state.send_ai_message(f"   • 执行工具数: {tool_count}")
                await state.send_ai_message(f"   • 成功率: {success_rate:.1f}%")
                await state.send_ai_message(f"   • 发现漏洞: {vulnerability_count} 个")
                
                formatted_report = self._format_analysis_report(
                    analysis=analysis,
                    tool_count=tool_count,
                    vulnerability_count=vulnerability_count,
                    timestamp=state.scan_summary["timestamp"]
                )
                logger.info(f"\n{formatted_report}")
                
                await state.send_ai_message(formatted_report)
                
                state.execution_history.append({
                    "task": "tool_chain_analysis",
                    "tool_name": "ai_analysis",
                    "target": state.target,
                    "result": state.tool_results,
                    "analysis": analysis,
                    "success": True,
                    "timestamp": datetime.now().isoformat()
                })
            
            await state.send_ai_message(f"✅ [阶段4/4] 执行分析流程完成")
            await state.send_ai_message(f"")
            await state.send_ai_message(f"════════════════════════════════════════")
            await state.send_ai_message(f"📊 执行统计")
            await state.send_ai_message(f"════════════════════════════════════════")
            await state.send_ai_message(f"✅ 完成任务: {len(state.completed_tasks)} 个")
            await state.send_ai_message(f"🔍 发现漏洞: {len(state.vulnerabilities)} 个")
            await state.send_ai_message(f"❌ 错误数量: {len(state.errors)} 个")
            await state.send_ai_message(f"════════════════════════════════════════")
            
        except Exception as e:
            logger.error(f"执行分析失败: {e}")
            await state.send_error(f"❌ 执行分析异常: {str(e)}")
            await state.send_error(f"💡 提示: 请检查日志获取详细信息")
        
        return state
    
    def _format_analysis_report(self, analysis: str, tool_count: int, vulnerability_count: int, timestamp: str) -> str:
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
    
    async def _analyze_results(self, results: Dict[str, Any]) -> str:
        """AI分析多个工具的结果"""
        try:
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
            
            analysis = await self.llm.ainvoke(prompt)
            return analysis.content
        except Exception as e:
            return f"分析失败: {str(e)}"


class ChatNegotiateNode:
    """聊天协商原子 - WebSocket版本
    
    支持多轮对话记忆存储：
    - 用户输入后立即保存到 chat_history
    - AI回复后立即保存到 chat_history
    - 每次对话使用最新的 chat_history 作为上下文
    - 实现对话历史长度限制，避免上下文过长
    """
    
    MAX_CHAT_HISTORY_LENGTH = 10
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        logger.info("聊天协商原子初始化完成")
    
    def _get_recent_chat_history(self, state: AgentState, limit: int = None) -> List[Dict]:
        """获取最近的聊天历史，限制长度避免上下文过长
        
        Args:
            state: Agent状态
            limit: 最大历史条数，默认使用 MAX_CHAT_HISTORY_LENGTH
            
        Returns:
            最近N条聊天历史
        """
        if limit is None:
            limit = self.MAX_CHAT_HISTORY_LENGTH
        
        return state.chat_history[-limit:] if state.chat_history else []
    
    def _build_chat_context(self, state: AgentState) -> str:
        """构建聊天上下文字符串
        
        Args:
            state: Agent状态
            
        Returns:
            格式化的聊天上下文
        """
        recent_history = self._get_recent_chat_history(state)
        if not recent_history:
            return "暂无历史对话"
        
        context_lines = []
        for msg in recent_history:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            role_display = {"user": "用户", "assistant": "AI", "system": "系统"}.get(role, role)
            context_lines.append(f"[{role_display}]: {content}")
        
        return "\n".join(context_lines)
    
    def _extract_user_name(self, user_msg: str, state: AgentState) -> Optional[str]:
        """从用户消息中提取名字
        
        Args:
            user_msg: 用户消息
            state: Agent状态
            
        Returns:
            提取到的名字，如果没找到返回None
        """
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
    
    async def _generate_chat_summary(self, state: AgentState) -> str:
        """调用LLM生成对话总结
        
        Args:
            state: Agent状态
            
        Returns:
            生成的对话总结内容
        """
        chat_context = self._build_chat_context(state)
        
        summary_prompt = f"""请总结以下对话内容，包括：
1. 主要讨论话题
2. 关键结论和建议
3. 用户偏好和关注点
4. 后续行动建议

对话历史：
{chat_context}

请用简洁清晰的语言进行总结，每个部分用换行分隔。"""
        
        try:
            summary_response = await self.llm.ainvoke(summary_prompt)
            return summary_response.content
        except Exception as e:
            logger.error(f"对话总结生成失败: {e}")
            return "对话总结生成失败，请查看聊天历史。"
    
    def _format_summary_output(self, summary: str) -> str:
        """格式化对话总结输出
        
        Args:
            summary: 总结内容
            
        Returns:
            格式化后的输出字符串
        """
        return f"""============================================================
📝 对话总结
============================================================
{summary}
============================================================"""
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 聊天协商节点开始执行")
        
        name = state.user_name
        
        recent_history = self._get_recent_chat_history(state)
        chat_context = self._build_chat_context(state)
        
        system_prompt = f"""你是专业的Web安全助手，正在协助用户进行安全扫描任务。

## 基本信息
- 用户称呼: {name}
- 当前目标: {state.target}
- 已完成任务: {', '.join(state.completed_tasks) if state.completed_tasks else '暂无'}

## 对话历史（最近{self.MAX_CHAT_HISTORY_LENGTH}条）
{chat_context}

## 行为准则
1. 称呼用户为 {name}
2. 回复简洁专业，避免冗长
3. 如果用户提到自己的名字，请记住并在后续对话中使用
4. 如果用户说"stop"或"停止"，表示用户想结束对话
5. 提供有价值的安全建议和分析"""
        
        from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
        
        messages = [SystemMessage(content=system_prompt)]
        
        for msg in recent_history:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user":
                messages.append(HumanMessage(content=content))
            elif role == "assistant":
                messages.append(AIMessage(content=content))
        
        if not any(isinstance(m, HumanMessage) for m in messages[1:]):
            messages.append(HumanMessage(content="请开始协助我进行安全扫描"))
        
        try:
            ai_msg = await self.llm.ainvoke(messages)
            ai_content = ai_msg.content
            
            state.append_chat_history("assistant", ai_content)
            
            await state.send_message_to_frontend("ai_message", {
                "content": ai_content,
                "message_type": "text"
            })
            
            logger.info(f"[聊天协商] AI回复已保存到chat_history")
            
        except Exception as e:
            logger.error(f"AI调用失败: {e}")
            error_msg = "抱歉，我遇到了一些问题，请稍后再试。"
            state.append_chat_history("assistant", error_msg)
            await state.send_message_to_frontend("ai_message", {
                "content": error_msg,
                "message_type": "text"
            })
        
        if len(state.chat_history) > 0:
            try:
                summary_prompt = f"请用一句话总结以下对话的关键信息：\n{chat_context}"
                summary = await self.llm.ainvoke(summary_prompt)
                state.chat_summary = summary.content
            except Exception as e:
                logger.warning(f"总结生成失败: {e}")
                state.chat_summary = "对话进行中"
        
        return state
    
    async def handle_user_message(self, state: AgentState, user_msg: str) -> AgentState:
        """处理用户消息（供外部调用）
        
        Args:
            state: Agent状态
            user_msg: 用户消息内容
            
        Returns:
            更新后的状态
        """
        if user_msg.lower().strip() == "stop":
            logger.info(f"[{state.task_id}] 用户请求停止对话")
            state.append_chat_history("user", user_msg)
            return state
        
        extracted_name = self._extract_user_name(user_msg, state)
        if extracted_name:
            state.user_name = extracted_name
            logger.info(f"[聊天协商] 更新用户名字: {extracted_name}")
        
        state.append_chat_history("user", user_msg)
        logger.info(f"[聊天协商] 用户消息已保存到chat_history")
        
        return await self.__call__(state)


class ScriptToolNode:
    """脚本管理原子 - WebSocket版本"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        logger.info("脚本管理原子初始化完成")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 脚本管理节点开始执行")
        
        res = {}
        
        if state.user_choice == "4":
            if state.uploaded_script_path and os.path.exists(state.uploaded_script_path):
                await state.send_ai_message("正在处理上传的脚本文件...")
                
                try:
                    with open(state.uploaded_script_path, 'r', encoding='utf-8') as f:
                        script_content = f.read()
                    
                    await state.send_ai_message("正在使用AI分析脚本功能...")
                    
                    analysis_prompt = f"""请分析以下Python脚本的功能，并提供简洁的描述（不超过100字）：

```python
{script_content[:2000]}
```

请直接返回功能描述，不要包含其他内容。重点关注：
1. 脚本的主要功能
2. 输入参数
3. 输出结果
"""
                    
                    analysis_result = await self.llm.ainvoke(analysis_prompt)
                    tool_description = analysis_result.content.strip()
                    
                    script_name = os.path.basename(state.uploaded_script_path).replace('.py', '')
                    tool_name = f"custom_{script_name}"
                    
                    await state.send_ai_message(f"脚本功能分析完成：{tool_description}")
                    
                    from TOSKill.tools import create_tool_from_script, register_dynamic_tool
                    
                    tool = create_tool_from_script(
                        script_path=state.uploaded_script_path,
                        tool_name=tool_name,
                        description=tool_description
                    )
                    
                    if tool:
                        success = register_dynamic_tool(tool, category="custom")
                        
                        if success:
                            await state.send_ai_message(f"✅ 工具注册成功！")
                            await state.send_ai_message(f"工具名称: {tool_name}")
                            await state.send_ai_message(f"工具描述: {tool_description}")
                            await state.send_ai_message(f"脚本路径: {state.uploaded_script_path}")
                            
                            from TOSKill.AI.nodes import AIDecisionNode
                            AIDecisionNode._instance = None
                            
                            res = {
                                "status": "registered",
                                "tool_name": tool_name,
                                "description": tool_description,
                                "script_path": state.uploaded_script_path
                            }
                            
                            logger.info(f"脚本工具注册成功: {tool_name}")
                        else:
                            await state.send_error("工具注册失败，请检查脚本格式")
                            res = {"status": "registration_failed"}
                    else:
                        await state.send_error("工具创建失败，请确保脚本包含 run(target) 函数")
                        res = {"status": "creation_failed"}
                        
                except Exception as e:
                    logger.error(f"脚本处理失败: {str(e)}")
                    await state.send_error(f"脚本处理失败: {str(e)}")
                    res = {"status": "error", "error": str(e)}
            else:
                await state.send_ai_message("请通过前端上传脚本文件")
                res = {"status": "waiting_upload"}
        
        elif state.user_choice == "5":
            result = await state.request_user_confirmation(
                prompt="请描述您需要生成的脚本功能（例如：检测目标网站的敏感目录、扫描特定端口服务等）：",
                options=["confirm"]
            )
            
            if result == "confirm":
                user_description = state.user_input if hasattr(state, 'user_input') and state.user_input else "用户自定义扫描脚本"
                
                await state.send_ai_message("正在生成脚本，请稍候...")
                
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
                    code_response = await self.llm.ainvoke(generation_prompt)
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
                    
                    await state.send_ai_message("脚本保存成功，正在进行工具注册...")
                    
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
                        
                        success_message = f"""
============================================================
📝 脚本生成成功
============================================================
📁 保存路径: {save_path}
🔧 工具名称: {tool_name}
📋 工具描述: {tool_description}
----------------------------------------
📄 脚本预览:
{preview_lines}
============================================================"""
                        
                        await state.send_ai_message(success_message)
                        
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
                        await state.send_error(f"工具注册失败: {error_msg}")
                        res = {
                            "status": "registration_failed",
                            "path": save_path,
                            "error": error_msg
                        }
                        
                except Exception as e:
                    logger.error(f"脚本生成失败: {str(e)}")
                    await state.send_error(f"脚本生成失败: {str(e)}")
                    res = {"status": "error", "error": str(e)}
        
        append_chat_history(state, "system", f"脚本管理完成: {res}")
        state.need_generate_script = False
        state.task_history.append(f"[脚本管理] {res}")
        
        return state


class VulnerabilityAnalysisNode:
    """漏洞分析原子 - WebSocket版本"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        logger.info("漏洞分析原子初始化完成")
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 漏洞分析节点开始执行")
        
        if not state.vulnerabilities:
            await state.send_ai_message("未发现漏洞")
            return state
        
        await state.send_ai_message(f"发现 {len(state.vulnerabilities)} 个漏洞，正在进行深入分析...")
        
        vuln_summary = json.dumps(state.vulnerabilities[:10], ensure_ascii=False, indent=2)
        analysis = await self.llm.ainvoke(f"""
分析以下漏洞，提供：
1. 漏洞严重程度排序
2. 修复优先级建议
3. 关键风险点

漏洞列表：
{vuln_summary}
""")
        
        await state.send_ai_message(f"漏洞分析结果：\n{analysis.content}")
        
        state.scan_summary = {
            "total_vulnerabilities": len(state.vulnerabilities),
            "analysis": analysis.content,
            "timestamp": datetime.now().isoformat()
        }
        
        return state


class ReportGenerationNode:
    """报告生成原子 - WebSocket版本
    
    增强功能：
    - 收集所有 execution_history 数据
    - 收集所有 chat_history 数据
    - 收集所有 tool_results 数据
    - 收集 vulnerabilities 数据
    - 生成表格格式的报告
    """
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=agent_config.MODEL_ID,
            temperature=agent_config.TEMPERATURE,
            api_key=agent_config.OPENAI_API_KEY,
            base_url=agent_config.OPENAI_BASE_URL
        )
        logger.info("报告生成原子初始化完成")
    
    def _format_execution_history_table(self, execution_history: List[Dict]) -> str:
        """格式化执行历史为表格"""
        if not execution_history:
            return "| 工具名 | 目标 | 状态 | 执行时间 | 关键发现 |\n|--------|------|------|----------|----------|\n| 暂无数据 | - | - | - | - |"
        
        table_lines = [
            "| 工具名 | 目标 | 状态 | 执行时间 | 关键发现 |",
            "|--------|------|------|----------|----------|"
        ]
        
        for record in execution_history[:20]:
            tool_name = record.get("tool_name", "未知")
            target = record.get("target", "-")[:30]
            status = "✅ 成功" if record.get("success") else "❌ 失败"
            exec_time = f"{record.get('execution_time', 0):.2f}s"
            
            key_findings = ""
            result = record.get("result", {})
            if isinstance(result, dict):
                if "vulnerabilities" in result:
                    vulns = result["vulnerabilities"]
                    if isinstance(vulns, list) and len(vulns) > 0:
                        key_findings = f"发现{len(vulns)}个漏洞"
                elif "ports" in result:
                    ports = result["ports"]
                    if isinstance(ports, list) and len(ports) > 0:
                        key_findings = f"发现{len(ports)}个端口"
                elif "subdomains" in result:
                    subs = result["subdomains"]
                    if isinstance(subs, list) and len(subs) > 0:
                        key_findings = f"发现{len(subs)}个子域名"
            
            if not key_findings:
                key_findings = record.get("error", "无")[:30] if not record.get("success") else "无异常"
            
            table_lines.append(f"| {tool_name} | {target} | {status} | {exec_time} | {key_findings} |")
        
        return "\n".join(table_lines)
    
    def _format_vulnerabilities_table(self, vulnerabilities: List[Dict]) -> str:
        """格式化漏洞列表为表格"""
        if not vulnerabilities:
            return "| 编号 | 类型 | 严重程度 | 位置 | 描述 |\n|------|------|----------|------|------|\n| 暂无数据 | - | - | - | - |"
        
        table_lines = [
            "| 编号 | 类型 | 严重程度 | 位置 | 描述 |",
            "|------|------|----------|------|------|"
        ]
        
        severity_map = {
            "critical": "🔴 严重",
            "high": "🟠 高危",
            "medium": "🟡 中危",
            "low": "🟢 低危",
            "info": "ℹ️ 信息"
        }
        
        for idx, vuln in enumerate(vulnerabilities[:30], 1):
            vuln_type = vuln.get("type", vuln.get("name", "未知"))
            severity = vuln.get("severity", "info").lower()
            severity_display = severity_map.get(severity, severity)
            location = vuln.get("location", vuln.get("url", "-"))[:40]
            description = vuln.get("description", vuln.get("details", "-"))[:50]
            
            table_lines.append(f"| {idx} | {vuln_type} | {severity_display} | {location} | {description} |")
        
        return "\n".join(table_lines)
    
    def _format_statistics_table(self, state: AgentState) -> str:
        """格式化统计信息为表格"""
        tool_count = len(state.completed_tasks)
        vuln_count = len(state.vulnerabilities)
        error_count = len(state.errors)
        success_rate = (tool_count / (tool_count + error_count) * 100) if (tool_count + error_count) > 0 else 0
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in state.vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        table_lines = [
            "### 工具执行统计",
            "",
            "| 指标 | 数值 |",
            "|------|------|",
            f"| 执行工具总数 | {tool_count} |",
            f"| 成功率 | {success_rate:.1f}% |",
            f"| 错误数量 | {error_count} |",
            "",
            "### 漏洞统计",
            "",
            "| 严重程度 | 数量 |",
            "|----------|------|",
            f"| 🔴 严重 | {severity_counts['critical']} |",
            f"| 🟠 高危 | {severity_counts['high']} |",
            f"| 🟡 中危 | {severity_counts['medium']} |",
            f"| 🟢 低危 | {severity_counts['low']} |",
            f"| ℹ️ 信息 | {severity_counts['info']} |",
            f"| **总计** | **{vuln_count}** |"
        ]
        
        return "\n".join(table_lines)
    
    def _format_chat_summary(self, chat_history: List[Dict]) -> str:
        """格式化聊天记录摘要"""
        if not chat_history:
            return "暂无聊天记录"
        
        summary_lines = []
        user_msgs = [m for m in chat_history if m.get("role") == "user"]
        assistant_msgs = [m for m in chat_history if m.get("role") == "assistant"]
        system_msgs = [m for m in chat_history if m.get("role") == "system"]
        
        summary_lines.append(f"- 用户消息: {len(user_msgs)} 条")
        summary_lines.append(f"- AI回复: {len(assistant_msgs)} 条")
        summary_lines.append(f"- 系统消息: {len(system_msgs)} 条")
        summary_lines.append(f"- 总计: {len(chat_history)} 条")
        
        if user_msgs:
            recent_user = user_msgs[-3:] if len(user_msgs) > 3 else user_msgs
            summary_lines.append("\n最近用户提问:")
            for msg in recent_user:
                content = msg.get("content", "")[:100]
                summary_lines.append(f"  - {content}")
        
        return "\n".join(summary_lines)
    
    async def __call__(self, state: AgentState) -> AgentState:
        logger.info(f"[{state.task_id}] 报告生成节点开始执行")
        
        try:
            await state.send_ai_message("📄 [阶段1/5] 开始生成扫描报告...")
            await state.send_ai_message(f"   • 收集执行历史: {len(state.execution_history)} 条记录")
            await state.send_ai_message(f"   • 收集聊天记录: {len(state.chat_history)} 条记录")
            await state.send_ai_message(f"   • 收集工具结果: {len(state.tool_results)} 个工具")
            await state.send_ai_message(f"   • 收集漏洞数据: {len(state.vulnerabilities)} 个漏洞")
            
            await state.send_ai_message("📊 [阶段2/5] 格式化数据为表格...")
            
            execution_history_table = self._format_execution_history_table(state.execution_history)
            vulnerabilities_table = self._format_vulnerabilities_table(state.vulnerabilities)
            statistics_table = self._format_statistics_table(state)
            chat_summary = self._format_chat_summary(state.chat_history)
            
            await state.send_ai_message("🧠 [阶段3/5] AI分析并生成报告...")
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            tool_count = len(state.completed_tasks)
            vuln_count = len(state.vulnerabilities)
            
            prompt = f"""请基于以下扫描数据生成完整的安全扫描报告：

## 扫描概览
- 目标: {state.target}
- 扫描时间: {timestamp}
- 执行工具数: {tool_count}
- 发现漏洞数: {vuln_count}

## 执行历史表格
{execution_history_table}

## 漏洞发现表格
{vulnerabilities_table}

## 统计信息
{statistics_table}

## 聊天记录摘要
{chat_summary}

## 工具结果详情
{json.dumps(state.tool_results, ensure_ascii=False, indent=2)[:3000]}

请生成包含以下部分的完整Markdown格式报告：

# 安全扫描报告

## 1. 执行摘要
以表格形式展示扫描概览，包括目标、时间、工具数、漏洞数等关键指标。

## 2. 执行历史详情
展示所有工具的执行情况表格，包括工具名、目标、状态、执行时间、关键发现。

## 3. 漏洞详情
以表格形式展示所有发现的漏洞，包含编号、类型、严重程度、位置、描述。
对每个漏洞提供详细分析和影响评估。

## 4. 风险评估
- 整体风险等级评估
- 关键风险点分析
- 攻击面分析

## 5. 修复建议
按优先级排序的修复建议，针对每个漏洞类型提供具体的修复方案。

## 6. 后续建议
下一步安全测试建议和长期安全改进措施。

请确保报告专业、详细、可操作。"""
            
            report = await self.llm.ainvoke(prompt)
            
            await state.send_ai_message("📝 [阶段4/5] 保存报告文件...")
            
            state.report = report.content
            state.is_complete = True
            
            report_file = f"reports/report_{state.task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            os.makedirs("reports", exist_ok=True)
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report.content)
            
            await state.send_ai_message(f"✅ 报告已保存: {report_file}")
            
            await state.send_ai_message("📤 [阶段5/5] 发送报告完成通知...")
            await state.send_report_ready(
                report_id=state.task_id,
                report_name=f"扫描报告_{state.target}",
                download_url=f"/api/reports/download/{os.path.basename(report_file)}"
            )
            
            await state.send_ai_message(f"")
            await state.send_ai_message(f"════════════════════════════════════════")
            await state.send_ai_message(f"📊 报告生成完成")
            await state.send_ai_message(f"════════════════════════════════════════")
            await state.send_ai_message(f"📄 报告文件: {report_file}")
            await state.send_ai_message(f"📏 报告长度: {len(state.report)} 字符")
            await state.send_ai_message(f"📊 包含数据:")
            await state.send_ai_message(f"   • 执行历史: {len(state.execution_history)} 条")
            await state.send_ai_message(f"   • 聊天记录: {len(state.chat_history)} 条")
            await state.send_ai_message(f"   • 工具结果: {len(state.tool_results)} 个")
            await state.send_ai_message(f"   • 漏洞数据: {len(state.vulnerabilities)} 个")
            await state.send_ai_message(f"════════════════════════════════════════")
            
        except Exception as e:
            logger.error(f"报告生成失败: {e}")
            await state.send_error(f"❌ 报告生成异常: {str(e)}")
            await state.send_error(f"💡 提示: 请检查日志获取详细信息")
            state.report = f"报告生成失败: {str(e)}"
            state.is_complete = True
        
        return state
