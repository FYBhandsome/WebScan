"""
RAG 引擎 - LlamaIndex 高级检索实现
提供：语义检索、元数据过滤、重排序、知识库管理
与 LangGraph 工作流解耦，推理交给 AI 节点
"""
import os
import logging
import hashlib
from typing import List, Dict, Any, Optional
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    StorageContext,
    load_index_from_storage,
    Settings,
    Document
)
from llama_index.core.retrievers import VectorIndexRetriever
from llama_index.core.schema import NodeWithScore
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

logger = logging.getLogger(__name__)

_STORAGE_DIR = Path(__file__).parent / "storage"
_KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"

TOOL_KNOWLEDGE_MAP = {
    "baseinfo_scan": ["信息收集", "资产发现", "HTTP头", "SSL证书", "技术栈识别"],
    "port_scan": ["端口扫描", "服务识别", "Nmap", "开放端口", "服务指纹"],
    "subdomain_scan": ["子域名", "DNS", "资产发现", "域名枚举", "子域名接管"],
    "dir_scan": ["目录扫描", "敏感文件", "路径遍历", "备份文件", "信息泄露"],
    "waf_detect": ["WAF检测", "防火墙绕过", "安全设备", "云WAF", "防护策略"],
    "sqli_scan": ["SQL注入", "数据库攻击", "OWASP", "盲注", "Union注入", "时间盲注"],
    "xss_scan": ["XSS", "跨站脚本", "前端安全", "DOM型", "反射型", "存储型"],
    "cmdi_scan": ["命令注入", "RCE", "管道符", "命令执行", "远程代码执行"],
    "fileupload_scan": ["文件上传", "WebShell", "绕过", "双扩展名", "图片马"],
    "ssrf_scan": ["SSRF", "云元数据", "内网访问", "协议利用", "服务端请求伪造"],
    "weakpass_scan": ["弱口令", "暴力破解", "默认密码", "字典攻击", "凭证猜测"],
    "lfi_scan": ["文件包含", "目录遍历", "路径穿越", "本地文件", "日志注入"],
    "csrf_scan": ["CSRF", "跨站请求伪造", "表单提交", "Token验证"],
    "cdn_detect": ["CDN检测", "内容分发网络", "真实IP", "绕过CDN"],
    "cms_detect": ["CMS检测", "内容管理系统", "指纹识别", "版本探测"],
}

VULN_TYPE_MAP = {
    "xss": "XSS跨站脚本",
    "sqli": "SQL注入",
    "rce": "命令执行",
    "fileupload": "文件上传",
    "ssrf": "SSRF服务端请求伪造",
    "weakpass": "弱口令",
    "lfi": "文件包含",
    "csrf": "CSRF跨站请求伪造",
    "info_leak": "信息泄露",
    "auth_bypass": "认证绕过",
}

SCENARIO_KEYWORDS = {
    "initial": ["初始扫描", "信息收集阶段", "第一步", "开始扫描"],
    "vuln_detect": ["漏洞检测", "安全测试", "渗透测试"],
    "waf_bypass": ["WAF绕过", "防火墙绕过", "编码绕过"],
    "error_handle": ["错误处理", "异常恢复", "失败重试"],
    "high_risk": ["高危漏洞", "严重漏洞", "紧急处理"],
}


class TOSKillRAGEngine:
    """LlamaIndex RAG 引擎 - 高级检索模式"""

    _instance: Optional["TOSKillRAGEngine"] = None

    def __init__(self):
        self.index: Optional[VectorStoreIndex] = None
        self.retriever: Optional[VectorIndexRetriever] = None
        self._initialized = False
        self._query_cache: Dict[str, str] = {}
        self._cache_hits = 0
        self._total_queries = 0
        self._document_count = 0
        self._initialize_rag()

    @classmethod
    def get_instance(cls) -> "TOSKillRAGEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _initialize_rag(self):
        if self._initialized:
            return
        try:
            from TOSKill.config import settings
            if not settings.RAG_ENABLED:
                logger.info("RAG 功能已在配置中禁用，跳过初始化")
                self._initialized = True
                return

            Settings.embed_model = HuggingFaceEmbedding(
                model_name="BAAI/bge-small-zh-v1.5",
                cache_folder=str(Path.home() / ".cache" / "huggingface")
            )

            _STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            _KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)

            index_files = list(_STORAGE_DIR.glob("*.json"))
            if index_files:
                try:
                    storage_context = StorageContext.from_defaults(persist_dir=str(_STORAGE_DIR))
                    self.index = load_index_from_storage(storage_context)
                    logger.info(f"RAG 索引加载成功: {_STORAGE_DIR}")
                except Exception as e:
                    logger.warning(f"索引加载失败，将重建: {e}")
                    self._build_index()
            else:
                self._build_index()

            self.retriever = VectorIndexRetriever(
                index=self.index,
                similarity_top_k=5,
            )
            self._initialized = True
            logger.info(f"TOSKillRAGEngine 初始化完成 (文档数: {self._document_count})")

        except Exception as e:
            logger.warning(f"RAG 初始化失败: {e}")
            self._initialized = True
            self.retriever = None

    def _build_index(self):
        """从知识库文件构建向量索引"""
        documents = []
        
        for md_file in _KNOWLEDGE_DIR.glob("*.md"):
            try:
                reader = SimpleDirectoryReader(
                    input_files=[str(md_file)],
                    filename_as_id=True
                )
                docs = reader.load_data()
                for doc in docs:
                    doc.metadata["file_name"] = md_file.name
                    doc.metadata["source"] = str(md_file)
                documents.extend(docs)
                logger.debug(f"加载知识库: {md_file.name}")
            except Exception as e:
                logger.warning(f"加载文档失败 {md_file}: {e}")

        if not documents:
            logger.warning("知识库为空，创建默认文档")
            documents = [Document(
                text="Web安全扫描知识库。支持XSS、SQL注入、文件上传等漏洞检测。",
                metadata={"file_name": "default.md"}
            )]

        self.index = VectorStoreIndex.from_documents(documents, show_progress=True)
        self.index.storage_context.persist(persist_dir=str(_STORAGE_DIR))
        self._document_count = len(documents)
        logger.info(f"RAG 索引创建成功: {self._document_count} 个文档")

    def _build_retrieval_query(
        self,
        target: str,
        current_task: str,
        completed_tasks: List[str],
        last_result: Dict[str, Any]
    ) -> str:
        """构建语义检索查询 - 增强版"""
        query_parts = []
        
        if not completed_tasks:
            query_parts.extend(SCENARIO_KEYWORDS["initial"])
        
        if current_task and current_task in TOOL_KNOWLEDGE_MAP:
            keywords = TOOL_KNOWLEDGE_MAP[current_task]
            query_parts.append(f"{' '.join(keywords)} 检测方法 最佳实践 决策策略")
        
        if completed_tasks:
            last_tool = completed_tasks[-1]
            if last_tool in TOOL_KNOWLEDGE_MAP:
                query_parts.append(f"刚完成{' '.join(TOOL_KNOWLEDGE_MAP[last_tool])}分析 下一步决策")
            
            if len(completed_tasks) <= 2:
                query_parts.extend(SCENARIO_KEYWORDS["initial"])
            else:
                query_parts.extend(SCENARIO_KEYWORDS["vuln_detect"])
        
        if last_result:
            vulns = last_result.get("vulnerabilities", [])
            if vulns:
                query_parts.extend(SCENARIO_KEYWORDS["high_risk"])
                for v in vulns[:2]:
                    vtype = v.get("type", "")
                    if vtype in VULN_TYPE_MAP:
                        query_parts.append(f"{VULN_TYPE_MAP[vtype]} 深度检测 绕过技术 利用链")
            
            ports = last_result.get("open_ports", []) or last_result.get("ports", [])
            if ports:
                port_services = {
                    "3306": "MySQL数据库", "5432": "PostgreSQL", "27017": "MongoDB",
                    "6379": "Redis缓存", "21": "FTP服务", "22": "SSH服务",
                    "3389": "RDP远程桌面", "8080": "Web服务"
                }
                for port in ports[:3]:
                    port_str = str(port)
                    if port_str in port_services:
                        query_parts.append(f"{port_services[port_str]} 弱口令检测 安全配置")
                query_parts.append("端口服务漏洞 弱口令检测 工具选择")
            
            if last_result.get("waf_detected"):
                query_parts.extend(SCENARIO_KEYWORDS["waf_bypass"])
            
            if last_result.get("error"):
                query_parts.extend(SCENARIO_KEYWORDS["error_handle"])
        
        if not query_parts:
            query_parts = ["Web安全扫描 漏洞检测 工具选择 决策策略"]
        
        return " ".join(query_parts)

    def _get_cache_key(self, target: str, current_task: str, completed_tasks: List[str]) -> str:
        key_str = f"{target}|{current_task}|{'|'.join(completed_tasks)}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def retrieve_scan_strategy(
        self,
        target: str,
        current_task: str,
        completed_tasks: List[str],
        last_result: Dict[str, Any]
    ) -> str:
        """
        LlamaIndex 语义检索 - 返回专业知识片段
        
        Args:
            target: 扫描目标URL
            current_task: 当前待执行任务名
            completed_tasks: 已完成的任务名列表
            last_result: 上一步工具执行结果
            
        Returns:
            str: 检索到的专业知识上下文
        """
        if not self.retriever:
            logger.warning("RAG检索器未初始化，返回空结果")
            return ""

        self._total_queries += 1
        
        cache_key = self._get_cache_key(target, current_task, completed_tasks)
        if cache_key in self._query_cache:
            self._cache_hits += 1
            logger.debug(f"RAG缓存命中: {cache_key[:8]}")
            return self._query_cache[cache_key]

        query = self._build_retrieval_query(target, current_task, completed_tasks, last_result)

        try:
            nodes: List[NodeWithScore] = self.retriever.retrieve(query)
            if not nodes:
                logger.warning(f"RAG检索无结果: query='{query[:50]}...'")
                return ""

            remaining_tasks_count = max(1, 10 - len(completed_tasks))
            max_content_length = min(2000, 800 + remaining_tasks_count * 100)
            
            parts = []
            sources = []
            total_score = 0
            
            for i, node in enumerate(nodes[:5]):
                score = getattr(node, 'score', 0) or 0
                total_score += score
                metadata = node.node.metadata if hasattr(node, 'node') else {}
                fname = metadata.get("file_name", "unknown")
                sources.append(fname)
                
                text = node.node.text if hasattr(node, 'node') else str(node)
                
                if score > 0.7:
                    text_content = text[:int(max_content_length * 0.4)]
                elif score > 0.5:
                    text_content = text[:int(max_content_length * 0.25)]
                else:
                    text_content = text[:int(max_content_length * 0.15)]
                
                parts.append(f"[知识{i+1}] 来源:{fname} 相关度:{score:.3f}\n{text_content}")
            
            avg_score = total_score / len(nodes[:5]) if nodes else 0
            result = f"【RAG检索结果】平均相关度:{avg_score:.3f}\n\n" + "\n\n---\n\n".join(parts)
            
            if len(result) > max_content_length:
                result = result[:max_content_length] + "\n\n...[内容已截断]"
            
            if len(self._query_cache) < 200:
                self._query_cache[cache_key] = result
            
            logger.info(f"RAG检索成功: query='{query[:50]}...' sources={sources} avg_score={avg_score:.3f}")
            return result
            
        except Exception as e:
            logger.error(f"RAG 检索失败: {e}")
            return ""

    def rebuild_index(self) -> bool:
        """重建向量索引（知识库更新后调用）"""
        try:
            self._build_index()
            self.retriever = VectorIndexRetriever(
                index=self.index,
                similarity_top_k=5,
            )
            self._query_cache.clear()
            logger.info("RAG 索引重建成功")
            return True
        except Exception as e:
            logger.error(f"索引重建失败: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "initialized": self._initialized,
            "ready": self.is_ready,
            "document_count": self._document_count,
            "cache_size": len(self._query_cache),
            "cache_hits": self._cache_hits,
            "total_queries": self._total_queries,
            "hit_rate": f"{self._cache_hits / max(1, self._total_queries) * 100:.1f}%",
            "knowledge_dir": str(_KNOWLEDGE_DIR),
            "storage_dir": str(_STORAGE_DIR),
        }

    @property
    def is_ready(self) -> bool:
        return self._initialized and self.retriever is not None


_rag_engine: Optional[TOSKillRAGEngine] = None


def get_rag_engine() -> TOSKillRAGEngine:
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = TOSKillRAGEngine.get_instance()
    return _rag_engine


def rebuild_knowledge_base() -> bool:
    """重建知识库索引"""
    engine = get_rag_engine()
    return engine.rebuild_index()
