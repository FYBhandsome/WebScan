from typing import TypedDict, List, Dict, Optional
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain.tools import tool
import importlib.util
import os
import sys
import time
from urllib.parse import urlparse

# ==================== 导入真实工具 ====================
from TOSKill.tools.info_collection.portscan import portscan
from TOSKill.tools.info_collection.dirscan import dirscan
from TOSKill.tools.info_collection.subdomain import subdomain
from TOSKill.tools.info_collection.waf import waf_detect
from TOSKill.tools.info_collection.baseinfo import baseinfo
from TOSKill.tools.info_collection.cdnexist import cdn_detect
from TOSKill.tools.info_collection.infoleak import infoleak_scan
from TOSKill.tools.info_collection.iplocating import ip_locate
from TOSKill.tools.info_collection.webside import webside_query
from TOSKill.tools.info_collection.webweight import web_weight
from TOSKill.tools.info_collection.whatcms import cms_detect

# ==================== 系统配置 ===================
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
os.makedirs("custom_scripts", exist_ok=True)

# ==================== LLM ====================
API_KEY = "001aa457c2c63574b2799bf1e3342e72:YTRkOGU4NWU3NjRiZjk5Y2E5OTMzZTBl"
BASE_URL = "https://maas-api.cn-huabei-1.xf-yun.com/v2"
MODEL_ID = "xop3qwen1b7"
llm = ChatOpenAI(model=MODEL_ID, temperature=0.1, api_key=API_KEY, base_url=BASE_URL)

# ==================== 流式输出 ====================
def stream_print(text: str, delay: float = 0.01):
    for char in str(text):
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

# ==================== URL 自动清洗 ====================
def clean_target(target: str) -> str:
    parsed = urlparse(target)
    return parsed.netloc.strip() if parsed.netloc else target.strip()

# ==================== 工具注册表 ====================
tool_map = {}
tool_sequence = [
    "port_scan",
    "dir_brute",
    "subdomain_scan",
    "cms_detect_scan",
    "waf_detect_scan",
    "baseinfo_scan",
    "cdn_detect_scan",
    "infoleak_scan",
    "ip_locate_scan",
    "webside_query_scan",
    "web_weight_scan"
]

# ==================== 注册工具（无警告版） ====================
@tool
def port_scan(target: str) -> Dict:
    """端口扫描"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行端口扫描：{t}")
    return portscan(t)

@tool
def dir_brute(target: str) -> Dict:
    """目录扫描"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行目录扫描：{t}")
    return dirscan(t)

@tool
def subdomain_scan(target: str) -> Dict:
    """子域名扫描"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行子域名扫描：{t}")
    return subdomain(t)

@tool
def waf_detect_scan(target: str) -> Dict:
    """WAF检测"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行WAF检测：{t}")
    return waf_detect(t)

@tool
def baseinfo_scan(target: str) -> Dict:
    """基础信息"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行基础信息收集：{t}")
    return baseinfo(t)

@tool
def cdn_detect_scan(target: str) -> Dict:
    """CDN检测"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行CDN检测：{t}")
    return cdn_detect(t)

@tool
def infoleak_scan(target: str) -> Dict:
    """信息泄露"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行信息泄露扫描：{t}")
    return infoleak_scan(t)

@tool
def ip_locate_scan(target: str) -> Dict:
    """IP定位"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行IP定位：{t}")
    return ip_locate(t)

@tool
def webside_query_scan(target: str) -> Dict:
    """备案查询"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行备案查询：{t}")
    return webside_query(t)

@tool
def web_weight_scan(target: str) -> Dict:
    """权重查询"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行权重查询：{t}")
    return web_weight(t)

@tool
def cms_detect_scan(target: str) -> Dict:
    """CMS识别"""
    t = clean_target(target)
    stream_print(f"\n[+] 执行CMS识别：{t}")
    return cms_detect(t)

tool_map = {t.name: t for t in [
    port_scan, dir_brute, subdomain_scan,
    waf_detect_scan, baseinfo_scan, cdn_detect_scan,
    infoleak_scan, ip_locate_scan, webside_query_scan,
    web_weight_scan, cms_detect_scan
]}

# ==================== 脚本管理（自动注册+打印结果） ====================
def save_script(name, code):
    p = f"custom_scripts/{name}.py"
    with open(p, "w", encoding="utf-8") as f:
        f.write(code.strip())
    return p

def run_script(path, target):
    try:
        spec = importlib.util.spec_from_file_location("s", path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m.run(clean_target(target)) if hasattr(m, "run") else {"err": "no run()"}
    except Exception as e:
        return {"err": str(e)}

def register_script_tool(name, path):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        if not hasattr(m, "run"): return False

        @tool(name)
        def f(t): return m.run(clean_target(t))
        tool_map[name] = f
        return True
    except:
        return False

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

# ==================== 聊天记忆 ====================
def append_chat(state, role, content):
    h = state["chat_history"].copy()
    h.append({"role": role, "content": content})
    s = llm.invoke(f"总结聊天：{h}").content.strip()
    return {**state, "chat_history": h, "chat_summary": s}

# ==================== 原子1：AI 智能决策（不重复！） ====================
def ai_decision(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 AI 全局任务决策")

    done = list(state["task_result"].keys())
    for t in tool_sequence:
        if t not in done:
            stream_print(f"✅ 分配任务：{t}")
            return {**state, "next_task": t, "need_generate_script": False}

    stream_print("✅ 所有扫描任务已完成！")
    return {**state, "next_task": "end", "need_generate_script": False}

# ==================== 原子2：交互 ====================
def user_interact(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print(f"🎯 目标：{state['target']} | 下一个任务：{state['next_task']}")
    stream_print("[1]执行 [2]停止 [3]聊天 [4]上传脚本 [5]生成脚本")
    return {**state, "user_choice": input("指令：").strip()}

# ==================== 原子3：执行任务（打印结果！） ====================
def execute_task(state: ScanState):
    stream_print("\n" + "="*60)
    task = state["next_task"]
    tool = tool_map[task]

    res = tool.invoke(state["target"])
    stream_print(f"\n📊 【{task}】结果：{res}")

    analysis = llm.invoke(f"3条简要分析：{res}").content
    stream_print(f"\n🧾 分析：{analysis}")

    new_state = append_chat(state, "system", f"任务：{task}\n结果：{res}\n分析：{analysis}")
    new_state["task_result"][task] = res
    new_state["task_history"].append(f"{task} 完成")
    return new_state

# ==================== 原子4：聊天 ====================
def chat(state: ScanState):
    stream_print("\n" + "="*60)
    stream_print("🔹 实时记忆聊天（stop 退出）")
    curr = state

    while True:
        prompt = f"""你是安全助手，用户：{curr['user_name']}
聊天总结：{curr['chat_summary']}
任务历史：{curr['task_history']}
目标：{curr['target']}
自然简洁回复。"""
        ai_msg = llm.invoke(prompt).content
        stream_print(f"\n🤖 AI：{ai_msg}")
        curr = append_chat(curr, "assistant", ai_msg)

        user_msg = input("👤 你：")
        if user_msg.lower() == "stop": break
        curr = append_chat(curr, "user", user_msg)

        if "我叫" in user_msg:
            curr["user_name"] = user_msg.replace("我叫", "").strip()
            stream_print(f"✅ 已记住：{curr['user_name']}")

    stream_print("\n✅ 聊天已保存")
    return curr

# ==================== 原子5：脚本管理（显示结果） ====================
def script_manager(state: ScanState):
    stream_print("\n" + "="*60)
    res = {}
    if state["user_choice"] == "4":
        p = input("脚本路径：")
        if os.path.exists(p):
            np = save_script("uploaded", open(p, encoding="utf-8").read())
            res = run_script(np, state["target"])
            register_script_tool("uploaded", np)
            stream_print("✅ 上传并注册成功")
        else:
            stream_print("❌ 文件不存在")

    elif state["user_choice"] == "5":
        desc = input("功能描述：")
        code = llm.invoke(f"""生成Python扫描脚本，纯代码，必须含 run(target)，返回字典。功能：{desc}""").content.replace("```python","").replace("```","")
        np = save_script("generated", code)
        res = run_script(np, state["target"])
        register_script_tool("generated", np)
        stream_print("✅ 生成并注册成功")

    stream_print(f"📦 脚本结果：{res}")
    new_state = append_chat(state, "system", f"脚本结果：{res}")
    new_state["task_result"]["custom"] = res
    return new_state

# ==================== 路由 ====================
def router(state: ScanState):
    if state["next_task"] == "end": return END
    if state["need_generate_script"]: return "script_manager"
    c = state["user_choice"]
    if c == "1": return "execute_task"
    if c == "2": return END
    if c == "3": return "chat"
    if c in ["4","5"]: return "script_manager"
    return "user_interact"

# ==================== 工作流 ====================
wf = StateGraph(ScanState)
wf.add_node("ai_decision", ai_decision)
wf.add_node("user_interact", user_interact)
wf.add_node("execute_task", execute_task)
wf.add_node("chat", chat)
wf.add_node("script_manager", script_manager)

wf.set_entry_point("ai_decision")
wf.add_edge("ai_decision", "user_interact")
wf.add_conditional_edges("user_interact", router)
wf.add_edge("execute_task", "ai_decision")
wf.add_edge("chat", "ai_decision")
wf.add_edge("script_manager", "ai_decision")

app = wf.compile()

# ==================== 启动 ====================
if __name__ == "__main__":
    stream_print("🚀 原子化智能扫描系统【完美修复版】", 0.02)
    target = clean_target(input("请输入扫描目标："))
    stream_print(f"✅ 标准化目标：{target}")

    init = ScanState(
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
        app.invoke(init)
    except KeyboardInterrupt:
        stream_print("\n🛑 强制终止")
    stream_print("\n✅ 任务结束")