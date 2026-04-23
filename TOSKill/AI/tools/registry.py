'''
工具注册模块
'''

from typing import TypedDict, List, Dict, Optional
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain.tools import tool, StructuredTool
import importlib.util
import os
import sys
import json
import time
import shutil
import logging
from .history_manager import HistoryManager

logger = logging.getLogger(__name__)

# ==================== 系统基础配置 ====================
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

# 目录配置
BASE_DIR = "custom_scripts"
TOOL_CONFIG = "tool_registry.json"
os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(f"{BASE_DIR}/port_scan", exist_ok=True)
os.makedirs(f"{BASE_DIR}/dir_brute", exist_ok=True)
os.makedirs(f"{BASE_DIR}/custom", exist_ok=True)
os.makedirs(f"{BASE_DIR}/generated", exist_ok=True)

# 大模型配置
API_KEY = "341787347bdc5374dc6374dc6374f29a192907:Nzk5NTk4OTFkYmE5MTUzODI1YTM0MjNj"
BASE_URL = "https://maas-api.cn-huabei-1.xf-yun.com/v2"
MODEL_ID = "xop5qwen1.5-7b-chat"
llm = ChatOpenAI(model=MODEL_ID, temperature=0.1, api_key=API_KEY, base_url=BASE_URL)

# 流式输出
def stream_print(text: str, delay=0.01):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

# ==================== 工具注册/持久化核心 ====================
def init_tool_registry():
    """初始化工具注册列表（持久化）"""
    default_tools = {
        "port_scan": "端口扫描",
        "dir_brute": "敏感目录扫描"
    }
    if not os.path.exists(TOOL_CONFIG):
        with open(TOOL_CONFIG, "w", encoding="utf-8") as f:
            json.dump(default_tools, f, ensure_ascii=False, indent=2)
    with open(TOOL_CONFIG, "r", encoding="utf-8") as f:
        return json.load(f)

def save_tool_registry(tools: dict):
    """保存工具到持久化文件"""
    with open(TOOL_CONFIG, "w", encoding="utf-8") as f:
        json.dump(tools, f, ensure_ascii=False, indent=2)

# 全局工具注册列表
registered_tools = init_tool_registry()

# 全局历史记录管理器实例
history_manager = HistoryManager()

# ==================== 内置扫描工具 ====================
@tool
def port_scan(target: str) -> Dict:
    """端口扫描"""
    stream_print(f"\n[+] 执行端口扫描：{target}")
    time.sleep(0.5)
    return {"target": target, "开放端口": [80, 443, 22], "状态": "成功"}

@tool
def dir_brute(target: str) -> Dict:
    """敏感目录扫描"""
    stream_print(f"\n[+] 执行敏感目录扫描：{target}")
    time.sleep(0.5)
    return {"target": target, "敏感目录": ["/admin", "/.git", "/login"], "状态": "成功"}

tool_map = {t.name: t for t in [port_scan, dir_brute]}

# ==================== 自定义脚本工具 ====================
def save_custom_script(task_name: str, code: str):
    """保存自定义脚本到分类目录"""
    path = f"{BASE_DIR}/custom/{task_name}.py"
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    return path

def upload_custom_script(src_path: str, task_name: str):
    """上传用户脚本"""
    dest_path = f"{BASE_DIR}/custom/{task_name}.py"
    shutil.copy(src_path, dest_path)
    return dest_path

def validate_script_path(path: str) -> tuple[bool, str]:
    """验证脚本路径是否有效"""
    if not path or not path.strip():
        return False, "脚本路径不能为空"

    path = path.strip()

    if not os.path.exists(path):
        return False, f"文件不存在：{path}"

    if not os.path.isfile(path):
        return False, f"路径不是文件：{path}"

    if not path.endswith('.py'):
        return False, "脚本文件必须是 .py 格式"

    return True, "路径验证通过"

def validate_script_code(code: str) -> tuple:
    """验证脚本代码是否有效"""
    import ast
    import re
    
    if not code or not code.strip():
        return False, "脚本代码为空"
    
    if "def run(" not in code:
        return False, "脚本缺少 run(target) 函数定义"
    
    run_func_pattern = r'def\s+run\s*\(\s*\w+\s*\)'
    if not re.search(run_func_pattern, code):
        return False, "run 函数签名不正确，应为 run(target)"
    
    try:
        ast.parse(code)
    except SyntaxError as e:
        return False, f"脚本语法错误: {e.msg} (行 {e.lineno})"
    
    return True, "脚本验证通过"

def load_and_test_script(script_path: str, target: str):
    """加载并测试脚本"""
    import inspect
    
    try:
        if not os.path.exists(script_path):
            return None, f"脚本文件不存在: {script_path}"
        
        with open(script_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        is_valid, error_msg = validate_script_code(code)
        if not is_valid:
            return None, f"脚本验证失败: {error_msg}"
        
        spec = importlib.util.spec_from_file_location("task_module", script_path)
        if spec is None or spec.loader is None:
            return None, "无法加载脚本模块"
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if not hasattr(module, "run"):
            return None, "脚本缺少 run 函数"
        
        run_func = getattr(module, "run")
        if not callable(run_func):
            return None, "run 不是可调用函数"
        
        sig = inspect.signature(run_func)
        params = list(sig.parameters.keys())
        if len(params) < 1:
            return None, "run 函数缺少参数，应为 run(target)"
        
        result = module.run(target)
        
        if result is None:
            return None, "run 函数返回值为 None，应返回字典类型结果"
        
        if not isinstance(result, dict):
            return None, f"run 函数返回类型错误: 期望 dict，实际 {type(result).__name__}"
        
        return result, "脚本执行成功"
        
    except SyntaxError as e:
        return None, f"语法错误: {e.msg} (文件 {e.filename}, 行 {e.lineno})"
    except ImportError as e:
        return None, f"导入错误: {str(e)}"
    except NameError as e:
        return None, f"名称错误: {str(e)}"
    except TypeError as e:
        return None, f"类型错误: {str(e)}"
    except AttributeError as e:
        return None, f"属性错误: {str(e)}"
    except Exception as e:
        return None, f"脚本执行异常: {type(e).__name__}: {str(e)}"

# ==================== 全局状态（扩充记忆字段） ====================
class ScanState(TypedDict):
    target: str
    task_result: Dict
    task_history: List[str]
    chat_history: List[Dict]         # 全量聊天历史（永久记忆）
    next_task: str
    user_choice: str
    chat_summary: str
    user_chat_rules: str
    user_specified_task: str
    # 新增核心字段
    missing_tool: bool              # 是否缺失工具
    user_consent: str               # 用户是否同意扩充能力 (yes/no)
    script_choice: str              # 脚本选择：upload/generate

# ==================== 原子0：历史记录管理 ====================
def history_manager_atom(state: ScanState, action: str, data: dict = None) -> ScanState:
    """
    历史记录管理原子操作
    action: 'add_chat' | 'add_task' | 'load' | 'save'
    data: 根据action不同，传递不同的数据
    """
    if data is None:
        data = {}
    
    try:
        if action == 'add_chat':
            role = data.get('role', 'user')
            content = data.get('content', '')
            if content:
                history_data = {
                    "chat_history": state.get("chat_history", []),
                    "task_history": state.get("task_history", []),
                    "chat_summary": state.get("chat_summary", ""),
                    "user_chat_rules": state.get("user_chat_rules", ""),
                    "task_result": state.get("task_result", {})
                }
                updated_history = history_manager.add_chat_message(role, content, history_data)
                logger.info(f"历史记录管理：添加聊天消息 role={role}")
                return {
                    **state,
                    "chat_history": updated_history.get("chat_history", [])
                }
        
        elif action == 'add_task':
            task_name = data.get('task_name', '')
            result = data.get('result', {})
            if task_name:
                history_data = {
                    "chat_history": state.get("chat_history", []),
                    "task_history": state.get("task_history", []),
                    "chat_summary": state.get("chat_summary", ""),
                    "user_chat_rules": state.get("user_chat_rules", ""),
                    "task_result": state.get("task_result", {})
                }
                updated_history = history_manager.add_task_record(task_name, result, history_data)
                logger.info(f"历史记录管理：添加任务记录 task_name={task_name}")
                return {
                    **state,
                    "task_history": updated_history.get("task_history", []),
                    "task_result": updated_history.get("task_result", {})
                }
        
        elif action == 'load':
            loaded_history = history_manager.load_history_from_file()
            logger.info("历史记录管理：从文件加载历史记录")
            return {
                **state,
                "chat_history": loaded_history.get("chat_history", []),
                "task_history": loaded_history.get("task_history", []),
                "chat_summary": loaded_history.get("chat_summary", ""),
                "user_chat_rules": loaded_history.get("user_chat_rules", ""),
                "task_result": loaded_history.get("task_result", {})
            }
        
        elif action == 'save':
            history_data = {
                "chat_history": state.get("chat_history", []),
                "task_history": state.get("task_history", []),
                "chat_summary": state.get("chat_summary", ""),
                "user_chat_rules": state.get("user_chat_rules", ""),
                "task_result": state.get("task_result", {})
            }
            history_manager.save_history_to_file(history_data)
            logger.info("历史记录管理：保存历史记录到文件")
            return state
        
        else:
            logger.warning(f"历史记录管理：未知操作 action={action}")
            return state
            
    except Exception as e:
        logger.error(f"历史记录管理操作失败: {e}")
        return state

# ==================== 原子1：AI智能决策（禁止擅自END） ====================
def ai_decision_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 原子操作1：AI 基于全量历史决策中...")

    history_context = ""

    if state.get('task_history'):
        history_context += "【任务执行历史】\n"
        for task in state['task_history']:
            history_context += f"- {task}\n"

    if state.get('chat_history'):
        history_context += "\n【聊天历史】\n"
        for msg in state['chat_history']:
            role = msg.get('role', '')
            content = msg.get('content', '')
            if role == 'user':
                history_context += f"用户：{content}\n"
            elif role == 'assistant':
                history_context += f"AI：{content}\n"
            elif role == 'system':
                history_context += f"系统：{content}\n"

    if state.get('chat_summary'):
        history_context += f"\n【聊天总结】{state['chat_summary']}\n"

    if state.get('user_chat_rules'):
        history_context += f"\n【用户自定义规则】{state['user_chat_rules']}\n"

    if state.get('task_result'):
        history_context += "\n【任务执行结果】\n"
        for task_name, result in state['task_result'].items():
            history_context += f"- {task_name}: {result}\n"

    prompt = f"""你是Web安全扫描调度器，严格遵守：
    1. 最高优先级：执行用户指定的任务
    2. 可选任务：port_scan(端口扫描)、dir_brute(敏感目录扫描)
    3. 禁止输出end/停止/终止等指令！
    4. 无对应工具 → 标记缺失工具
    5. 仅输出任务名，无其他文字

{history_context}

用户指定任务：{state['user_specified_task']}
注册工具：{registered_tools}
扫描目标：{state['target']}"""

    next_task = llm.invoke(prompt).content.strip()
    missing_tool = next_task not in registered_tools and next_task != ""

    stream_print(f"✅ AI 决策完成 → 下一步任务：【{next_task}】")
    if missing_tool:
        stream_print(f"⚠️ 未找到【{next_task}】工具，需要扩充能力！")

    return {
        **state,
        "next_task": next_task,
        "missing_tool": missing_tool
    }

# ==================== 原子2：用户交互 ====================
def user_interact_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print(f"🎯 目标：{state['target']} | 待执行任务：{state['next_task']}")
    stream_print("【1】执行任务 【2】停止扫描 【3】聊天协商 【4】上传脚本 【5】生成脚本")
    choice = input("请输入指令：")
    return {**state, "user_choice": choice}

# ==================== 原子3：执行任务+分析 ====================
def execute_analyze_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 原子操作3：执行任务 → 输出结果 → AI分析")
    task = state["next_task"]
    result = tool_map[task].func(state["target"]) if task in tool_map else {}

    exec_log = f"【执行】{task}：{result}"
    analyze_prompt = f"分析扫描结果：{result}，分3点：结果/风险/建议"
    analysis = llm.invoke(analyze_prompt).content
    stream_print("\n🧾 结果智能分析：")
    stream_print(analysis)
    analyze_log = f"【分析】{analysis}"

    return {
        **state,
        "task_result": {**state["task_result"], task: result},
        "task_history": state["task_history"] + [exec_log, analyze_log],
        "chat_history": state["chat_history"] + [{"role": "system", "content": exec_log + analyze_log}]
    }

# ==================== 原子4：全记忆聊天（修复历史记忆+实时持久化） ====================
def chat_negotiate_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 原子操作4：带全记忆聊天（输入 stop 结束聊天）")

    while True:
        user_msg = input("👤 你：")
        
        if user_msg.lower() == "stop":
            break
        
        state = history_manager_atom(state, 'add_chat', {'role': 'user', 'content': user_msg})
        
        chat_history = state.get("chat_history", [])
        history_text = ""
        for msg in chat_history:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if role == "user":
                history_text += f"用户：{content}\n"
            elif role == "assistant":
                history_text += f"AI：{content}\n"
        
        chat_prompt = f"""严格遵守规则：{state['user_chat_rules']}
历史聊天总结：{state['chat_summary']}
扫描任务历史：{state['task_history']}
注册工具：{registered_tools}
目标：{state['target']}

完整聊天历史：
{history_text}

请根据完整聊天历史回复用户，记住用户告诉你的所有信息（如姓名、偏好等）。
简洁1句话回复用户。"""
        
        ai_msg = llm.invoke(chat_prompt).content
        stream_print(f"\n🤖 AI：{ai_msg}")
        
        state = history_manager_atom(state, 'add_chat', {'role': 'assistant', 'content': ai_msg})

    chat_history = state.get("chat_history", [])
    summary = llm.invoke(f"总结聊天，提取用户的扫描指令：{chat_history}").content
    specified_task = llm.invoke(f"从文本提取扫描任务名：{user_msg}").content
    
    stream_print(f"\n✅ 聊天总结：{summary}")
    stream_print(f"✅ 用户指定任务：{specified_task if specified_task else '无'}")
    stream_print("✅ 全量历史已实时持久化")

    return {
        **state,
        "chat_summary": summary,
        "user_specified_task": specified_task
    }

# ==================== 原子5：工具缺失→征求用户同意 ====================
def confirm_tool_extend(state: ScanState):
    """原子：缺失工具时征求用户同意"""
    stream_print("\n" + "="*60)
    stream_print(f"🔹 原子操作5：能力扩充确认")
    task = state["user_specified_task"]
    consent = input(f"⚠️ 未找到【{task}】工具，是否扩充能力？(yes/no)：").lower()
    return {**state, "user_consent": consent}

# ==================== 原子6：选择脚本方式（上传/生成） ====================
def choose_script_mode(state: ScanState):
    """原子：选择脚本上传/生成"""
    stream_print("\n" + "="*60)
    stream_print(f"🔹 原子操作6：选择脚本创建方式")
    choice = input("请选择：1-上传本地脚本 | 2-AI生成脚本：")
    return {**state, "script_choice": "upload" if choice == "1" else "generate"}

# ==================== 原子7：上传脚本+注册+分析 ====================
def upload_script_atom(state: ScanState):
    """原子：上传脚本全流程"""
    stream_print("\n" + "="*60)
    stream_print(f"🔹 原子操作7：上传自定义脚本")
    task_name = state["user_specified_task"]
    src_path = input("请输入本地脚本路径：")

    is_valid, error_msg = validate_script_path(src_path)
    if not is_valid:
        stream_print(f"❌ {error_msg}")
        return {
            **state,
            "chat_history": state["chat_history"] + [{"role": "system", "content": f"脚本上传失败：{error_msg}"}]
        }

    desc = input("请输入脚本功能描述：")

    try:
        script_path = upload_custom_script(src_path.strip(), task_name)
        test_result, msg = load_and_test_script(script_path, state["target"])
        
        if test_result is None:
            analyze = f"❌ 脚本【{task_name}】执行失败 | {msg}"
            stream_print(analyze)
            return {
                **state,
                "chat_history": state["chat_history"] + [{"role": "system", "content": analyze}],
                "missing_tool": False
            }

        registered_tools[task_name] = desc
        save_tool_registry(registered_tools)

        analyze = f"✅ 脚本【{task_name}】上传成功 | {msg} | 已注册到工具列表"
        stream_print(analyze)
        return {
            **state,
            "chat_history": state["chat_history"] + [{"role": "system", "content": analyze}],
            "missing_tool": False
        }
        
    except PermissionError:
        error_msg = f"权限不足，无法访问文件：{src_path}"
        stream_print(f"❌ {error_msg}")
        return {
            **state,
            "chat_history": state["chat_history"] + [{"role": "system", "content": f"脚本上传失败：{error_msg}"}]
        }
    except Exception as e:
        error_msg = f"上传过程发生错误：{type(e).__name__}: {str(e)}"
        stream_print(f"❌ {error_msg}")
        return {
            **state,
            "chat_history": state["chat_history"] + [{"role": "system", "content": f"脚本上传失败：{error_msg}"}]
        }

# ==================== 原子8：AI生成脚本+注册+分析 ====================
def generate_script_atom(state: ScanState):
    """原子：AI生成脚本全流程"""
    stream_print("\n" + "="*60)
    stream_print(f"🔹 原子操作8：AI生成自定义脚本")
    task_name = state["user_specified_task"]
    desc = input("请描述脚本功能：")

    prompt = f"""生成Python扫描脚本，必须严格遵守以下要求：
1. 必须包含 run(target) 函数，target 是扫描目标URL
2. run 函数必须返回字典类型的结果
3. 不要包含任何注释和说明，只返回纯代码
4. 使用 try-except 捕获异常并返回错误信息

功能：{desc}
目标：{state['target']}

示例格式：
def run(target):
    try:
        # 扫描逻辑
        return {{"status": "success", "data": ...}}
    except Exception as e:
        return {{"error": str(e)}}

请直接输出代码，不要有任何其他文字。"""

    code = llm.invoke(prompt).content
    
    code = code.strip()
    if code.startswith("```python"):
        code = code[9:]
    elif code.startswith("```"):
        code = code[3:]
    if code.endswith("```"):
        code = code[:-3]
    code = code.strip()
    
    is_valid, error_msg = validate_script_code(code)
    if not is_valid:
        stream_print(f"⚠️ 生成的代码验证失败: {error_msg}")
        stream_print("🔄 尝试修复代码...")
        
        fix_prompt = f"""修复以下Python代码，确保：
1. 包含正确的 run(target) 函数
2. 返回字典类型结果
3. 使用 try-except 捕获异常

原始代码：
{code}

错误信息：{error_msg}

请直接输出修复后的代码，不要有任何其他文字。"""
        code = llm.invoke(fix_prompt).content
        
        code = code.strip()
        if code.startswith("```python"):
            code = code[9:]
        elif code.startswith("```"):
            code = code[3:]
        if code.endswith("```"):
            code = code[:-3]
        code = code.strip()
        
        is_valid, error_msg = validate_script_code(code)
        if not is_valid:
            analyze = f"❌ 脚本【{task_name}】生成失败 | 验证错误: {error_msg}"
            stream_print(analyze)
            return {
                **state,
                "chat_history": state["chat_history"] + [{"role": "system", "content": analyze}],
                "missing_tool": False
            }
    
    timestamp = int(time.time())
    script_filename = f"{timestamp}_{task_name}.py"
    script_path = f"{BASE_DIR}/generated/{script_filename}"
    
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(code)
    
    stream_print(f"📁 脚本已保存: {script_path}")
    
    test_result, msg = load_and_test_script(script_path, state["target"])
    
    if test_result is None:
        analyze = f"❌ 脚本【{task_name}】执行失败 | {msg}"
        stream_print(analyze)
        stream_print(f"📝 生成的脚本代码：\n{code}")
        return {
            **state,
            "chat_history": state["chat_history"] + [{"role": "system", "content": analyze}],
            "missing_tool": False
        }
    
    registered_tools[task_name] = desc
    save_tool_registry(registered_tools)

    analyze = f"✅ 脚本【{task_name}】生成成功 | {msg} | 已注册到工具列表"
    stream_print(analyze)
    stream_print(f"📝 脚本代码：\n{code}")
    stream_print(f"📊 执行结果：{test_result}")

    return {
        **state,
        "chat_history": state["chat_history"] + [{"role": "system", "content": analyze}],
        "missing_tool": False
    }

# ==================== 路由调度（核心分支逻辑） ====================
def atom_router(state: ScanState) -> str:
    # 1. 用户手动停止
    if state["user_choice"] == "2":
        return END
    # 2. 执行任务
    if state["user_choice"] == "1":
        return "execute_analyze_atom"
    # 3. 聊天协商
    if state["user_choice"] == "3":
        return "chat_negotiate_atom"
    # 4. 缺失工具 → 征求用户同意
    if state["missing_tool"]:
        return "confirm_tool_extend"
    # 5. 用户同意扩充 → 选择脚本方式
    if state["user_consent"] == "yes":
        return "choose_script_mode"
    # 6. 用户不同意 → 结束
    if state["user_consent"] == "no":
        return END
    # 7. 脚本方式路由
    if state["script_choice"] == "upload":
        return "upload_script_atom"
    if state["script_choice"] == "generate":
        return "generate_script_atom"
    # 8. 默认交互
    return "user_interact_atom"

# ==================== 工作流编排（完整闭环） ====================
workflow = StateGraph(ScanState)
# 注册所有原子
workflow.add_node("ai_decision_atom", ai_decision_atom)
workflow.add_node("user_interact_atom", user_interact_atom)
workflow.add_node("execute_analyze_atom", execute_analyze_atom)
workflow.add_node("chat_negotiate_atom", chat_negotiate_atom)
workflow.add_node("confirm_tool_extend", confirm_tool_extend)
workflow.add_node("choose_script_mode", choose_script_mode)
workflow.add_node("upload_script_atom", upload_script_atom)
workflow.add_node("generate_script_atom", generate_script_atom)

# 流程编排
workflow.set_entry_point("ai_decision_atom")
workflow.add_edge("ai_decision_atom", "user_interact_atom")

# 条件路由（核心）
workflow.add_conditional_edges("user_interact_atom", atom_router)
workflow.add_conditional_edges("confirm_tool_extend", atom_router)
workflow.add_conditional_edges("choose_script_mode", atom_router)

# 闭环循环：所有操作完成 → 重新AI决策
workflow.add_edge("execute_analyze_atom", "ai_decision_atom")
workflow.add_edge("chat_negotiate_atom", "ai_decision_atom")
workflow.add_edge("upload_script_atom", "ai_decision_atom")
workflow.add_edge("generate_script_atom", "ai_decision_atom")

app = workflow.compile()

# ==================== 启动程序 ====================
if __name__ == '__main__':
    temp_state = ScanState(
        target="",
        task_result={},
        task_history=[],
        chat_history=[],
        next_task="",
        user_choice="",
        chat_summary="",
        user_chat_rules="称呼用户为樊意彬，每次回复开头加你好",
        user_specified_task="",
        missing_tool=False,
        user_consent="",
        script_choice=""
    )
    
    temp_state = history_manager_atom(temp_state, 'load')
    
    stream_print("🚀 原子化智能Web安全扫描系统（永久全域记忆版）", 0.03)
    target = input("请输入扫描目标：")
    
    initial_state = ScanState(
        target=target,
        task_result=temp_state.get('task_result', {}),
        task_history=temp_state.get('task_history', []),
        chat_history=temp_state.get('chat_history', []),
        next_task="",
        user_choice="",
        chat_summary=temp_state.get('chat_summary', ""),
        user_chat_rules=temp_state.get('user_chat_rules', "称呼用户为樊意彬，每次回复开头加你好"),
        user_specified_task="",
        missing_tool=False,
        user_consent="",
        script_choice=""
    )

    try:
        app.invoke(initial_state)
    except KeyboardInterrupt:
        stream_print("\n🛑 程序强制终止")
    stream_print("\n✅ 扫描任务全部结束")