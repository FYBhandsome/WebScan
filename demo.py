from typing import TypedDict, List, Dict, Optional
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain.tools import tool, StructuredTool
import importlib.util
import os
import sys
import time

# ==================== 系统基础配置 ====================
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

# 脚本目录
os.makedirs("custom_scripts", exist_ok=True)

# 大模型配置
API_KEY = "001aa457c2c63574b2799bf1e3342e72:YTRkOGU4NWU3NjRiZjk5Y2E5OTMzZTBl"
BASE_URL = "https://maas-api.cn-huabei-1.xf-yun.com/v2"
MODEL_ID = "xop3qwen1b7"
llm = ChatOpenAI(model=MODEL_ID, temperature=0.1, api_key=API_KEY, base_url=BASE_URL)

# 流式输出（修复：只接受1个参数）
def stream_print(text: str, delay: float = 0.01):
    for char in str(text):
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

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
    stream_print(f"\n[+] 执行目录扫描：{target}")
    time.sleep(0.5)
    return {"target": target, "敏感目录": ["/admin", "/.git", "/login"], "状态": "成功"}

tool_map = {t.name: t for t in [port_scan, dir_brute]}
available_task_names = list(tool_map.keys())

# ==================== 脚本管理 ====================
def save_script(script_name: str, code: str) -> str:
    path = f"custom_scripts/{script_name}.py"
    with open(path, "w", encoding="utf-8") as f:
        f.write(code.strip())
    return path

def run_script(path: str, target: str) -> Dict:
    try:
        spec = importlib.util.spec_from_file_location("custom_task", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "run"):
            return module.run(target)
        return {"错误": "脚本必须包含 run(target) 函数"}
    except Exception as e:
        return {"错误": f"脚本异常：{str(e)}"}

# ==================== 全局状态 ====================
class ScanState(TypedDict):
    target: str
    task_result: Dict
    task_history: List[str]
    chat_history: List[Dict]
    next_task: str
    user_choice: str
    chat_summary: str
    user_name: str
    need_generate_script: bool

# ==================== 统一追加聊天历史 ====================
def append_chat_history(state: ScanState, role: str, content: str):
    new_hist = state["chat_history"].copy()
    new_hist.append({"role": role, "content": content})
    return {**state, "chat_history": new_hist}

# ==================== 原子1：AI决策 ====================
def ai_decision_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 原子1：AI全局决策")

    prompt = f"""
你是Web安全扫描调度器。
当前可用任务：{available_task_names}
用户目标：{state['target']}
历史任务：{state['task_history']}
聊天历史：{state['chat_history']}
聊天总结：{state['chat_summary']}

规则：
1. 如果任务不存在/不支持，只输出：need_script
2. 否则只输出任务名：port_scan / dir_brute / custom_script
3. 绝对不输出 end / 停止 / 多余文字
"""

    res = llm.invoke(prompt).content.strip()
    need_gen = res == "need_script" or res not in available_task_names

    if need_gen:
        stream_print("⚠️ 当前无对应任务脚本，AI将引导您上传或生成脚本")
    else:
        stream_print(f"✅ 决策任务：【{res}】")

    return {
        **state,
        "next_task": res,
        "need_generate_script": need_gen
    }

# ==================== 原子2：用户交互 ====================
def user_interact_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print(f"🎯 目标：{state['target']} | 任务：{state['next_task']}")
    stream_print("【1】执行 【2】停止 【3】聊天 【4】上传脚本 【5】生成脚本")
    return {**state, "user_choice": input("请输入指令：")}

# ==================== 原子3：执行任务 ====================
def execute_analyze_atom(state: ScanState):
    stream_print("\n" + "="*60)
    task = state["next_task"]
    res = tool_map[task].func(state["target"]) if task in tool_map else {}

    exec_log = f"[执行] {task} → {res}"
    analysis = llm.invoke(f"简要3点分析：{res}").content
    analyze_log = f"[分析] {analysis}"

    stream_print("\n🧾 分析：\n" + analysis)

    new_state = append_chat_history(state, "system", exec_log + "\n" + analyze_log)
    new_state["task_history"].append(exec_log)
    new_state["task_history"].append(analyze_log)
    new_state["task_result"][task] = res

    return new_state

# ==================== 原子4：聊天协商 ====================
def chat_negotiate_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 原子4：实时记忆聊天（stop退出）")
    name = state["user_name"]
    chat_hist = state["chat_history"].copy()

    while True:
        prompt = f"""
你是安全助手，称呼用户为 {name}
上下文：
任务历史：{state['task_history']}
聊天历史：{chat_hist}
目标：{state['target']}
简洁回复。
"""
        ai_msg = llm.invoke(prompt).content
        stream_print(f"\n🤖 AI：{ai_msg}")
        chat_hist.append({"role": "assistant", "content": ai_msg})

        user_msg = input("👤 你：")
        chat_hist.append({"role": "user", "content": user_msg})

        if "我叫" in user_msg:
            name = user_msg.replace("我叫", "").strip()
            stream_print(f"✅ 已记住名字：{name}")

        if user_msg.lower() == "stop":
            break

    summary = llm.invoke(f"总结聊天内容：{chat_hist}").content
    stream_print(f"\n✅ 聊天总结：{summary}")

    return {
        **state,
        "chat_history": chat_hist,
        "chat_summary": summary,
        "user_name": name
    }

# ==================== 原子5：脚本管理（修复报错） ====================
def script_tool_atom(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 原子5：自定义脚本管理")
    res = {}

    if state["user_choice"] == "4":
        path = input("输入脚本路径：")
        if os.path.exists(path):
            new_path = save_script("uploaded_script", open(path, encoding='utf-8').read())
            res = run_script(new_path, state["target"])
            stream_print("✅ 脚本上传完成")
        else:
            stream_print("❌ 文件不存在")

    elif state["user_choice"] == "5":
        desc = input("描述脚本功能：")
        code = llm.invoke(f"""
生成Python扫描脚本，纯代码无解释，必须包含 run(target) 函数，返回字典。
功能：{desc}
""").content.replace("```python", "").replace("```", "")
        new_path = save_script("generated_script", code)
        stream_print(f"\n📝 脚本已保存：{new_path}")
        res = run_script(new_path, state["target"])
        # 修复：合并成一个字符串输出
        stream_print(f"执行结果：{res}")

    new_state = append_chat_history(state, "system", f"自定义脚本执行结果：{res}")
    new_state["task_result"]["custom_script"] = res
    new_state["task_history"].append(f"[脚本任务] {res}")
    return new_state

# ==================== 路由 ====================
def atom_router(state: ScanState):
    if state["need_generate_script"]:
        return "script_tool_atom"

    c = state["user_choice"]
    if c == "1": return "execute_analyze_atom"
    if c == "2": return END
    if c == "3": return "chat_negotiate_atom"
    if c in ["4", "5"]: return "script_tool_atom"
    return "user_interact_atom"

# ==================== 工作流 ====================
workflow = StateGraph(ScanState)
workflow.add_node("ai_decision_atom", ai_decision_atom)
workflow.add_node("user_interact_atom", user_interact_atom)
workflow.add_node("execute_analyze_atom", execute_analyze_atom)
workflow.add_node("chat_negotiate_atom", chat_negotiate_atom)
workflow.add_node("script_tool_atom", script_tool_atom)

workflow.set_entry_point("ai_decision_atom")
workflow.add_edge("ai_decision_atom", "user_interact_atom")
workflow.add_conditional_edges("user_interact_atom", atom_router)

workflow.add_edge("execute_analyze_atom", "ai_decision_atom")
workflow.add_edge("chat_negotiate_atom", "ai_decision_atom")
workflow.add_edge("script_tool_atom", "ai_decision_atom")

app = workflow.compile()

# ==================== 启动 ====================
if __name__ == '__main__':
    stream_print("🚀 原子化智能扫描系统（脚本缺失自动引导版）", 0.03)
    target = input("请输入扫描目标：").strip()

    initial = ScanState(
        target=target,
        task_result={},
        task_history=[],
        chat_history=[],
        next_task="",
        user_choice="",
        chat_summary="无",
        user_name="樊意彬",
        need_generate_script=False
    )

    try:
        app.invoke(initial)
    except KeyboardInterrupt:
        stream_print("\n🛑 强制终止")
    stream_print("\n✅ 任务结束")