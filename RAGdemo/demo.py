import os
import sys
import json
import asyncio
import importlib.util
import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from dotenv import load_dotenv

from llama_index.core import SimpleDirectoryReader, VectorStoreIndex, Settings
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.llms.openai import OpenAI

load_dotenv()

# ======================
# 路径配置
# ======================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

RAG_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(RAG_DIR, "data")

# ======================
# 模型 & 向量配置
# ======================
Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-zh-v1.5")
Settings.llm = OpenAI(
    model=os.getenv("MODEL_ID", "xop3qwen1b7"),
    api_key=os.getenv("OPENAI_API_KEY"),
    api_base=os.getenv("OPENAI_BASE_URL"),
    temperature=0.1,
    max_tokens=4096,
)

# ======================
# 加载知识库 & 检索器（每轮决策强制调用）
# ======================
documents = SimpleDirectoryReader(DATA_DIR).load_data()
index = VectorStoreIndex.from_documents(documents, show_progress=False)
retriever = index.as_retriever(similarity_top_k=8)

def get_rag_knowledge(context: str) -> str:
    """
    全局知识库查询
    每一轮智能体决策前自动调用，读取安全扫描手册、漏洞规范、攻击流程
    """
    nodes = retriever.retrieve(context)
    contents = []
    for idx, node in enumerate(nodes):
        contents.append(f"【知识参考{idx+1}】\n{node.text}")
    return "\n\n".join(contents[:6])

# ======================
# 安全黑名单 & 校验逻辑（完全保留原有）
# ======================
FORBIDDEN_NETWORKS = [
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.0.0.0", "169.254.", "::1", "fc00:", "fe80:"
]

def _validate_target(target: str) -> Optional[str]:
    if not target:
        return "错误：目标不能为空"
    if not target.startswith(("http://", "https://")):
        return "错误：目标必须以 http:// 或 https:// 开头"
    try:
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        for net in FORBIDDEN_NETWORKS:
            if hostname.startswith(net):
                return f"错误：禁止扫描内网地址 ({hostname})"
        return None
    except Exception:
        return "错误：URL解析失败"

# ======================
# 工具映射 & 原有扫描执行逻辑 完全保留
# ======================
VULN_TOOLS = ["xss", "sqli", "fileupload", "cmdi", "weakpass", "ssrf", "csrf", "lfi"]
INFO_TOOLS = ["portscan", "dirscan", "subdomain", "waf", "baseinfo", "cdnexist", "whatcms", "infoleak"]
ALL_TOOLS = VULN_TOOLS + INFO_TOOLS

tool_module_map = {
    "xss": "TOSKill.tools.vuln_scan.xss",
    "sqli": "TOSKill.tools.vuln_scan.sqli",
    "fileupload": "TOSKill.tools.vuln_scan.fileupload",
    "cmdi": "TOSKill.tools.vuln_scan.cmdi",
    "weakpass": "TOSKill.tools.vuln_scan.weakpass",
    "ssrf": "TOSKill.tools.vuln_scan.ssrf",
    "csrf": "TOSKill.tools.vuln_scan.csrf",
    "lfi": "TOSKill.tools.vuln_scan.lfi",
    "portscan": "TOSKill.tools.info_collection.portscan",
    "dirscan": "TOSKill.tools.info_collection.dirscan",
    "subdomain": "TOSKill.tools.info_collection.subdomain",
    "waf": "TOSKill.tools.info_collection.waf",
    "baseinfo": "TOSKill.tools.info_collection.baseinfo",
    "cdnexist": "TOSKill.tools.info_collection.cdnexist",
    "whatcms": "TOSKill.tools.info_collection.whatcms",
    "infoleak": "TOSKill.tools.info_collection.infoleak",
}

func_map = {
    "xss": "xss_scan","sqli": "sqli_scan","fileupload": "fileupload_scan",
    "cmdi": "cmdi_scan","weakpass": "weakpass_scan","ssrf": "ssrf_scan",
    "csrf": "csrf_scan","lfi": "lfi_scan","portscan": "portscan",
    "dirscan": "dirscan","subdomain": "subdomain","waf": "waf_detect",
    "baseinfo": "baseinfo","cdnexist": "cdn_detect","whatcms": "cms_detect",
    "infoleak": "infoleak_scan",
}

def _call_scan_tool(tool_name: str, target: str, timeout: int = 10) -> Dict[str, Any]:
    module_path = tool_module_map.get(tool_name)
    func_name = func_map.get(tool_name)
    if not module_path or not func_name:
        return {"success": False, "error": f"未知工具: {tool_name}"}
    try:
        mod = importlib.import_module(module_path)
        func = getattr(mod, func_name)
        if hasattr(func, "invoke"):
            return func.invoke({"target": target, "timeout": timeout})
        return func(target)
    except Exception as e:
        return {"success": False, "error": str(e)}

def _parse_mode_to_tools(mode: str) -> List[str]:
    if mode == "fast":
        return ["xss", "sqli"]
    elif mode == "deep":
        return VULN_TOOLS
    elif mode == "full":
        return ALL_TOOLS
    return ["xss", "sqli"]

# ======================
# 工具函数（完全不变）
# ======================
def web_vuln_scan(
    target: str,
    mode: str = "fast",
    thread: int = 5,
    timeout: int = 10
) -> str:
    error = _validate_target(target)
    if error:
        return json.dumps({"success": False, "error": error}, ensure_ascii=False)
    if mode not in ["fast", "deep", "full"]:
        return json.dumps({"success": False, "error": "模式错误"}, ensure_ascii=False)
    thread = max(1, min(10, int(thread)))
    timeout = max(1, min(60, int(timeout)))
    tools = _parse_mode_to_tools(mode)
    results = {
        "success": True,"target": target,"mode": mode,"scan_start": datetime.datetime.now().isoformat(),
        "tool_results":{},"total_vulnerabilities":0,"all_vulnerabilities":[]
    }
    for t in tools:
        results["tool_results"][t] = _call_scan_tool(t, target, timeout)
    return json.dumps(results, ensure_ascii=False, indent=2)

def run_info_collection(target: str, tools: str = "all") -> str:
    error = _validate_target(target)
    if error:
        return json.dumps({"success": False, "error": error}, ensure_ascii=False)
    selected_tools = INFO_TOOLS if tools == "all" else [x.strip() for x in tools.split(",") if x.strip() in INFO_TOOLS]
    results = {"success": True,"target": target,"tool_results":{}}
    for t in selected_tools:
        results["tool_results"][t] = _call_scan_tool(t, target)
    return json.dumps(results, ensure_ascii=False, indent=2)

# ======================
# 工具封装
# ======================
scan_tool = FunctionTool.from_defaults(
    fn=web_vuln_scan,
    name="web_vuln_scan",
    description="Web漏洞扫描，支持fast/deep/full多模式，检测XSS、SQL注入、文件上传等漏洞"
)
info_tool = FunctionTool.from_defaults(
    fn=run_info_collection,
    name="info_collection",
    description="站点信息收集，端口、目录、WAF、CMS、子域名、信息泄露探测"
)

# ======================
# 【核心强化提示词】
# 强制：每一轮思考 / 决策 / 工具调用 必须先读取知识库
# 强制：多轮渐进决策、分步执行、动态调整策略
# ======================
SYSTEM_PROMPT = """
# 你是具备多轮自主决策的网络安全智能体
## 硬性强制规则（必须严格遵守）
1. **每一轮思考、每一次工具选择、每一个参数配置，都必须优先读取并参考RAG安全知识库内容**；
2. 知识库包含：Web安全扫描手册、渗透测试标准流程、OWASP规范、漏洞检测标准、工具使用规范、修复手册；
3. 禁止一次性执行全部动作，必须采用**多轮渐进式决策**：
   轮次1：读取知识库 → 制定标准化安全执行计划
   轮次2：依据手册执行基础信息收集
   轮次3：根据收集结果+知识库，决策是否需要补充探测
   轮次4：依据漏洞检测手册，执行分层漏洞扫描
   轮次5：汇总全部工具结果，结合知识库漏洞标准进行风险研判
   轮次6：检索知识库生成对应漏洞的专业修复方案与加固建议

## 执行约束
- 严格遵循知识库中的扫描顺序：先信息收集、后漏洞检测；
- 单轮只执行**一个工具动作**，逐步推进，实现多轮迭代优化；
- 若上一轮结果数据不足，自主决策开启二次补充扫描；
- 禁止扫描内网、非法目标；
- 所有工具参数配置，严格参考知识库手册要求。

## 输出要求
1. 每一轮决策前，标注「本轮知识库参考依据」；
2. 输出清晰的多轮执行步骤；
3. 最终报告包含：执行计划、多轮执行记录、漏洞研判、知识库修复建议、风险等级评定。
"""

# ======================
# 7. 创建 ReAct Agent（含RAG检索器）
# ======================
agent = ReActAgent(
    name="Web漏洞扫描智能体",
    description="专业的Web漏洞扫描智能体，支持XSS、SQL注入等8类漏洞检测和8类信息收集",
    tools=[scan_tool, info_tool],
    llm=Settings.llm,
    verbose=True,
    system_prompt=SYSTEM_PROMPT,
    timeout=600,
)

# ======================
# 交互逻辑：输入URL → 自动多轮闭环
# ======================
def auto_security_scan(target_url: str):
    print("\n" + "="*70)
    print(f"[全自动多轮安全检测] 目标：{target_url}")
    print("="*70)

    # 全局前置读取基础知识库
    base_knowledge = get_rag_knowledge("Web安全标准扫描流程 渗透测试执行手册")
    user_prompt = f"""
目标地址：{target_url}
请严格按照系统规则：
1. 优先引用安全知识库内容；
2. 启动多轮渐进式决策；
3. 分步执行：计划制定→信息收集→补充探测→分层漏洞扫描→风险分析→修复建议；
4. 每一轮动作都参考知识库手册；
5. 单轮只调用一个工具，逐步完成全部安全检测。

基础参考知识库：
{base_knowledge}
"""
    response = asyncio.run(agent.run(user_input=user_prompt))
    print("\n【最终多轮综合检测报告】")
    print("-"*70)
    print(response)

def print_banner():
    print("""
============================================
  网络安全多轮决策智能体 | RAG知识库全程驱动
  输入任意合法URL，自动多轮渐进扫描
============================================
    """)

if __name__ == "__main__":
    print_banner()
    while True:
        user_input = input("\n请输入检测URL(exit退出)：").strip()
        if user_input in ["exit","quit"]:
            break
        if not user_input:
            continue
        auto_security_scan(user_input)