"""
RAG 引擎 - LlamaIndex 高级检索实现
提供：语义检索、元数据过滤、重排序、知识库管理
与 LangGraph 工作流解耦，推理交给 AI 节点
"""
import os
import logging
import hashlib
import json
import re
import threading
import functools
import shutil
import tempfile
from typing import List, Dict, Any, Optional
from pathlib import Path

from TOSKill.config import settings

# 移除离线模式，允许首次从HuggingFace下载模型
# os.environ.setdefault("HF_HUB_OFFLINE", "1")
# os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

try:
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
    _LLAMA_INDEX_IMPORT_ERROR: Optional[Exception] = None
except ImportError as exc:
    VectorStoreIndex = SimpleDirectoryReader = StorageContext = Settings = Document = Any
    VectorIndexRetriever = NodeWithScore = HuggingFaceEmbedding = Any
    load_index_from_storage = None
    _LLAMA_INDEX_IMPORT_ERROR = exc

logger = logging.getLogger(__name__)

_STORAGE_DIR = Path(__file__).parent / "storage"
_KNOWLEDGE_DIR = Path(settings.RAG_KNOWLEDGE_DIR)
if not _KNOWLEDGE_DIR.is_absolute():
    _KNOWLEDGE_DIR = Path(__file__).parent / _KNOWLEDGE_DIR
_ALLOWED_MODES = frozenset(settings.RAG_ALLOWED_MODES)


def _knowledge_files() -> List[Path]:
    """返回按名称排序的受支持知识文档。"""
    return sorted(
        (path for path in _KNOWLEDGE_DIR.iterdir()
         if path.is_file() and path.suffix.lower() in {".md", ".txt"}),
        key=lambda path: path.name.casefold(),
    ) if _KNOWLEDGE_DIR.exists() else []

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
    MODEL_LOAD_TIMEOUT = 30
    FALLBACK_MODELS = [
        "BAAI/bge-small-zh-v1.5",
        "sentence-transformers/all-MiniLM-L6-v2",
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    ]

    def __init__(self):
        self.index: Optional[VectorStoreIndex] = None
        self.retriever: Optional[VectorIndexRetriever] = None
        self._initialized = False
        self._mapping_ready = False
        self._query_cache: Dict[str, str] = {}
        self._cache_hits = 0
        self._total_queries = 0
        self._document_count = 0
        self._embed_model = None
        self._model_load_error: Optional[str] = None
        self._mode = settings.RAG_MODE
        if self._mode not in _ALLOWED_MODES:
            raise ValueError(f"非法 RAG_MODE: {self._mode}，允许值: {sorted(_ALLOWED_MODES)}")
        self._state_lock = threading.RLock()
        self._index_stale = False
        self._index_version: Optional[str] = None
        self._indexed_at: Optional[str] = None
        self._initialize_rag()

    @classmethod
    def get_instance(cls) -> "TOSKillRAGEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_embed_model_with_timeout(self, model_name: str, cache_folder: str, timeout: int = None, local_model_path: Optional[str] = None) -> Optional[HuggingFaceEmbedding]:
        """带超时的模型加载"""
        if timeout is None:
            timeout = self.MODEL_LOAD_TIMEOUT
        
        result = [None]
        exception = [None]
        
        def _load():
            try:
                logger.info(f"正在加载嵌入模型: {model_name}")
                embed_model = HuggingFaceEmbedding(
                    model_name=local_model_path or model_name,
                    cache_folder=cache_folder,
                    local_files_only=bool(local_model_path)
                )
                result[0] = embed_model
                logger.info(f"嵌入模型加载成功: {model_name}")
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=_load, daemon=True)
        thread.start()
        thread.join(timeout=timeout)
        
        if thread.is_alive():
            logger.warning(f"模型加载超时 ({timeout}s): {model_name}")
            return None
        
        if exception[0]:
            logger.warning(f"模型加载失败: {model_name}, 错误: {exception[0]}")
            return None
        
        return result[0]

    def _find_cached_model_path(self, model_name: str, cache_folder: str) -> Optional[str]:
        """返回本地缓存模型的最新完整 snapshot 路径"""
        model_cache_path = Path(cache_folder) / "hub" / f"models--{model_name.replace('/', '--')}"
        snapshots_path = model_cache_path / "snapshots"
        if not snapshots_path.exists():
            return None
        snapshots = [path for path in snapshots_path.iterdir() if path.is_dir()]
        if not snapshots:
            return None
        return str(max(snapshots, key=lambda path: path.stat().st_mtime))

    def _check_model_cached(self, model_name: str, cache_folder: str) -> bool:
        """检查模型是否已在本地缓存"""
        model_dir_name = model_name.replace("/", "--")
        model_cache_path = Path(cache_folder) / "hub" / f"models--{model_dir_name}"
        if model_cache_path.exists():
            snapshots_path = model_cache_path / "snapshots"
            if snapshots_path.exists():
                snapshots = list(snapshots_path.iterdir())
                if snapshots:
                    logger.info(f"模型已在本地缓存: {model_name}")
                    return True
        logger.debug(f"模型未缓存: {model_name}")
        return False

    def _try_load_embed_model(self) -> Optional[HuggingFaceEmbedding]:
        """尝试加载嵌入模型，只使用本地缓存，不下载"""
        cache_folder = str(Path.home() / ".cache" / "huggingface")
        
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder, exist_ok=True)
            logger.info(f"创建模型缓存目录: {cache_folder}")
        
        for model_name in self.FALLBACK_MODELS:
            cached_model_path = self._find_cached_model_path(model_name, cache_folder)
            if not cached_model_path:
                logger.info(f"跳过未缓存模型: {model_name}")
                continue

            logger.info(f"尝试加载本地缓存模型: {model_name}")
            embed_model = self._load_embed_model_with_timeout(
                model_name=model_name,
                cache_folder=cache_folder,
                timeout=self.MODEL_LOAD_TIMEOUT,
                local_model_path=cached_model_path
            )
            if embed_model:
                logger.info(f"模型加载成功: {model_name}")
                return embed_model
            else:
                logger.warning(f"模型加载失败: {model_name}")
                continue
        
        logger.error("没有可用的本地缓存模型，RAG功能不可用")
        return None

    def _initialize_rag(self):
        if self._mapping_ready or self._initialized:
            return
        _KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
        self._document_count = len(_knowledge_files())
        self._mapping_ready = self._document_count > 0
        if self._mode == "vector":
            self.ensure_vector_ready()
        logger.info("TOSKillRAGEngine 初始化完成 (mode=%s)", self._mode)

    def set_mode(self, mode: str) -> Dict[str, Any]:
        if mode not in _ALLOWED_MODES:
            raise ValueError(f"非法 RAG 模式: {mode}，允许值: {sorted(_ALLOWED_MODES)}")
        with self._state_lock:
            self._mode = mode
            if mode == "vector":
                if self._index_stale and self.retriever is not None:
                    self.rebuild_index()
                else:
                    self.ensure_vector_ready()
            return self.get_status()

    def refresh_mapping(self) -> None:
        """知识文档变化后刷新轻量检索，并标记已有向量索引过期。"""
        with self._state_lock:
            self._document_count = len(_knowledge_files())
            self._mapping_ready = self._document_count > 0
            self._query_cache.clear()
            self._index_stale = True

    def get_status(self) -> Dict[str, Any]:
        with self._state_lock:
            return {
                "mode": self._mode,
                "model_loaded": self._embed_model is not None,
                "index_ready": self.index is not None and self.retriever is not None,
                "index_stale": self._index_stale,
                "index_version": self._index_version,
                "indexed_at": self._indexed_at,
                "last_error": self._model_load_error,
            }

    def ensure_vector_ready(self) -> bool:
        with self._state_lock:
            if _LLAMA_INDEX_IMPORT_ERROR is not None:
                self._model_load_error = f"向量依赖不可用: {_LLAMA_INDEX_IMPORT_ERROR}"
                return False
            if self.index is not None and self.retriever is not None and self._embed_model is not None:
                return True
            try:
                if self._embed_model is None:
                    self._embed_model = self._try_load_embed_model()
                if self._embed_model is None:
                    self._model_load_error = "所有嵌入模型加载失败，无法启用 vector 模式"
                    return False
                Settings.embed_model = self._embed_model
                _STORAGE_DIR.mkdir(parents=True, exist_ok=True)
                index_files = list(_STORAGE_DIR.glob("*.json"))
                if index_files:
                    storage_context = StorageContext.from_defaults(persist_dir=str(_STORAGE_DIR))
                    self.index = load_index_from_storage(storage_context)
                else:
                    self.index = self._build_index()
                self.retriever = VectorIndexRetriever(index=self.index, similarity_top_k=5)
                self._model_load_error = None
                self._initialized = True
                return True
            except Exception as e:
                self._model_load_error = f"向量索引加载失败: {e}"
                logger.error(self._model_load_error)
                return False

    def _mapping_search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """无需嵌入模型的本地文档检索，返回真实 Markdown 片段。"""
        query_lower = query.lower()
        terms: List[str] = []

        for name, keywords in TOOL_KNOWLEDGE_MAP.items():
            if name.lower() in query_lower or any(keyword.lower() in query_lower for keyword in keywords):
                terms.extend(keywords)
        for name, label in VULN_TYPE_MAP.items():
            if label.lower() in query_lower or name.lower() in query_lower:
                terms.extend([name, label])

        terms.extend(
            token.strip("：:，,。；;（）()[]【】")
            for token in re.split(r"\s+", query)
            if len(token.strip("：:，,。；;（）()[]【】")) >= 2
        )
        terms = list(dict.fromkeys(term.lower() for term in terms if term))[:40]

        matches: List[Dict[str, Any]] = []
        for md_file in _knowledge_files():
            try:
                content = md_file.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning(f"读取映射知识文档失败 {md_file.name}: {e}")
                continue

            searchable = f"{md_file.name}\n{content}".lower()
            matched_terms = [term for term in terms if term in searchable]
            if not matched_terms:
                continue

            occurrence_score = sum(min(searchable.count(term), 5) for term in matched_terms)
            score = min(0.99, 0.35 + len(matched_terms) * 0.06 + occurrence_score * 0.01)
            first_positions = [searchable.find(term) for term in matched_terms if searchable.find(term) >= 0]
            start = max(0, min(first_positions, default=0) - 120)
            snippet = content[start:start + 650].strip()
            matches.append({
                "file_name": md_file.name,
                "score": score,
                "matched_terms": matched_terms[:8],
                "text": snippet,
            })

        matches.sort(key=lambda item: item["score"], reverse=True)
        return matches[:limit]

    def _mapping_retrieve(self, query: str, limit: int = 5) -> str:
        matches = self._mapping_search(query, limit)
        if not matches:
            return ""
        parts = [
            f"[知识{i + 1}] 来源:{item['file_name']} 相关度:{item['score']:.3f}\n"
            f"匹配词:{'、'.join(item['matched_terms'])}\n{item['text']}"
            for i, item in enumerate(matches)
        ]
        return "【RAG映射检索结果】\n\n" + "\n\n---\n\n".join(parts)

    def _build_index(self, persist_dir: Optional[Path] = None):
        """从知识库文件构建向量索引"""
        documents = []
        persist_dir = persist_dir or _STORAGE_DIR
        
        for md_file in _knowledge_files():
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

        index = VectorStoreIndex.from_documents(documents, show_progress=True)
        persist_dir.mkdir(parents=True, exist_ok=True)
        index.storage_context.persist(persist_dir=str(persist_dir))
        self._document_count = len(documents)
        logger.info(f"RAG 索引创建成功: {self._document_count} 个文档")
        return index

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

    def _get_cache_key(
        self,
        target: str,
        current_task: str,
        completed_tasks: List[str],
        last_result: Optional[Dict[str, Any]] = None
    ) -> str:
        """生成包含最新扫描结果的缓存键，避免复用过期决策。"""
        try:
            result_fingerprint = json.dumps(
                last_result or {}, ensure_ascii=False, sort_keys=True, default=str
            )[:2000]
        except Exception:
            result_fingerprint = str(last_result or {})[:2000]
        key_str = f"{target}|{current_task}|{'|'.join(completed_tasks)}|{result_fingerprint}"
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
        if self._mode == "vector" and not self.retriever:
            logger.warning("RAG检索器未初始化，返回空结果")
            return ""

        self._total_queries += 1
        
        cache_key = self._get_cache_key(target, current_task, completed_tasks, last_result)
        if cache_key in self._query_cache:
            self._cache_hits += 1
            logger.debug(f"RAG缓存命中: {cache_key[:8]}")
            return self._query_cache[cache_key]

        query = self._build_retrieval_query(target, current_task, completed_tasks, last_result)

        if self._mode == "mapping":
            result = self._mapping_retrieve(query, limit=5)[:2000]
            if result and len(self._query_cache) < 200:
                self._query_cache[cache_key] = result
            return result

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
        with self._state_lock:
            temporary_dir = None
            backup_dir = None
            previous_index = self.index
            previous_retriever = self.retriever
            try:
                if _LLAMA_INDEX_IMPORT_ERROR is not None:
                    self._model_load_error = f"向量依赖不可用: {_LLAMA_INDEX_IMPORT_ERROR}"
                    return False
                if self._embed_model is None:
                    self._embed_model = self._try_load_embed_model()
                if self._embed_model is None:
                    self._model_load_error = "所有嵌入模型加载失败，无法启用 vector 模式"
                    return False
                Settings.embed_model = self._embed_model
                _STORAGE_DIR.parent.mkdir(parents=True, exist_ok=True)
                temporary_dir = Path(tempfile.mkdtemp(
                    prefix=f".{_STORAGE_DIR.name}.rebuild-",
                    dir=str(_STORAGE_DIR.parent),
                ))
                new_index = self._build_index(persist_dir=temporary_dir)
                new_retriever = VectorIndexRetriever(index=new_index, similarity_top_k=5)
                backup_dir = _STORAGE_DIR.parent / f".{_STORAGE_DIR.name}.backup-{os.getpid()}-{threading.get_ident()}"
                if backup_dir.exists():
                    shutil.rmtree(backup_dir)
                if _STORAGE_DIR.exists():
                    _STORAGE_DIR.rename(backup_dir)
                try:
                    temporary_dir.rename(_STORAGE_DIR)
                except Exception:
                    if _STORAGE_DIR.exists():
                        shutil.rmtree(_STORAGE_DIR)
                    if backup_dir.exists():
                        backup_dir.rename(_STORAGE_DIR)
                    raise
                temporary_dir = None
                if backup_dir.exists():
                    shutil.rmtree(backup_dir, ignore_errors=True)
                    backup_dir = None
                self.index = new_index
                self.retriever = new_retriever
                self._initialized = True
                self._query_cache.clear()
                self._index_stale = False
                self._index_version = hashlib.sha256(
                    "".join(sorted(path.name for path in _STORAGE_DIR.glob("*.json"))).encode()
                ).hexdigest()[:12]
                from datetime import datetime, timezone
                self._indexed_at = datetime.now(timezone.utc).isoformat()
                self._model_load_error = None
                logger.info("RAG 索引重建成功")
                return True
            except Exception as e:
                self.index = previous_index
                self.retriever = previous_retriever
                self._model_load_error = f"索引重建失败: {e}"
                logger.error(self._model_load_error)
                return False
            finally:
                if temporary_dir is not None and temporary_dir.exists():
                    shutil.rmtree(temporary_dir, ignore_errors=True)
                if backup_dir is not None and backup_dir.exists():
                    if _STORAGE_DIR.exists():
                        shutil.rmtree(backup_dir, ignore_errors=True)
                    else:
                        backup_dir.rename(_STORAGE_DIR)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "initialized": self._initialized,
            "ready": self.is_ready,
            "mode": self._mode,
            "document_count": self._document_count,
            "cache_size": len(self._query_cache),
            "cache_hits": self._cache_hits,
            "total_queries": self._total_queries,
            "hit_rate": f"{self._cache_hits / max(1, self._total_queries) * 100:.1f}%",
            "knowledge_dir": str(_KNOWLEDGE_DIR),
            "storage_dir": str(_STORAGE_DIR),
            "embed_model_loaded": self._embed_model is not None,
            "model_load_error": self._model_load_error,
            "index_stale": self._index_stale,
            "index_version": self._index_version,
            "indexed_at": self._indexed_at,
        }

    def retrieve_for_report(
        self,
        target: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """报告生成前检索知识库——获取等保标准/修复指南/案例参考

        Args:
            target: 扫描目标URL
            vulnerabilities: 漏洞列表

        Returns:
            str: 知识库检索结果（等保标准、修复指南、案例）
        """
        if self._mode == "vector" and not self.retriever:
            logger.warning("RAG检索器未初始化，报告检索返回空")
            return ""

        vuln_types = list(set(
            v.get("type") or v.get("vuln_type", "")
            for v in vulnerabilities if v.get("type") or v.get("vuln_type")
        ))
        query_parts = ["安全报告 渗透测试方案 等保标准 风险定级 修复建议"]
        if vuln_types:
            query_parts.append(f"漏洞类型: {' '.join(vuln_types[:5])} 修复方案 合规要求")
        query_parts.append("实战案例 风险等级评定 安全加固建议")
        query = " ".join(query_parts)

        if self._mode == "mapping":
            self._total_queries += 1
            return self._mapping_retrieve(query, limit=5)[:2000]

        try:
            self._total_queries += 1
            nodes: List[NodeWithScore] = self.retriever.retrieve(query)
            if not nodes:
                return ""

            parts = []
            for i, node in enumerate(nodes[:5]):
                score = getattr(node, 'score', 0) or 0
                metadata = node.node.metadata if hasattr(node, 'node') else {}
                fname = metadata.get("file_name", "unknown")
                text = node.node.text if hasattr(node, 'node') else str(node)
                text_content = text[:500]
                parts.append(f"[知识{i+1}] 来源:{fname} 相关度:{score:.3f}\n{text_content}")

            result = "【报告知识库检索】\n\n" + "\n\n---\n\n".join(parts)
            logger.info(f"报告知识库检索成功: {len(nodes)}条结果")
            return result[:2000]
        except Exception as e:
            logger.error(f"报告知识库检索失败: {e}")
            return ""

    def retrieve_for_result_analysis(
        self,
        tool_name: str,
        target: str,
        result: Any
    ) -> str:
        """检索与单个工具扫描结果解读、风险判断和处置建议相关的知识。"""
        if self._mode == "vector" and not self.retriever:
            logger.warning("RAG检索器未初始化，工具结果分析检索返回空")
            return ""

        keywords = TOOL_KNOWLEDGE_MAP.get(tool_name, [tool_name])
        result_terms: List[str] = []
        if isinstance(result, dict):
            for key in ("vuln_type", "type", "severity", "service", "technology", "title"):
                value = result.get(key)
                if value:
                    result_terms.append(str(value)[:80])
            nested_data = result.get("data")
            if isinstance(nested_data, dict):
                for key in ("vulnerabilities", "findings", "ports", "open_ports", "technologies"):
                    value = nested_data.get(key)
                    if value:
                        result_terms.append(f"{key} {str(value)[:240]}")

        query = " ".join([
            *keywords,
            *result_terms[:6],
            "扫描结果解读 风险证据 误报判断 修复建议 后续验证",
        ])

        if self._mode == "mapping":
            self._total_queries += 1
            return self._mapping_retrieve(query, limit=4)[:1800]

        try:
            self._total_queries += 1
            nodes: List[NodeWithScore] = self.retriever.retrieve(query)
            if not nodes:
                return ""

            parts = []
            for i, node in enumerate(nodes[:4]):
                score = getattr(node, "score", 0) or 0
                metadata = node.node.metadata if hasattr(node, "node") else {}
                fname = metadata.get("file_name", "unknown")
                text = node.node.text if hasattr(node, "node") else str(node)
                parts.append(
                    f"[知识{i + 1}] 来源:{fname} 相关度:{score:.3f}\n{text[:450]}"
                )

            result_text = "【工具结果分析知识库检索】\n\n" + "\n\n---\n\n".join(parts)
            logger.info("工具结果分析知识库检索成功: tool=%s, 结果=%s条", tool_name, len(nodes))
            return result_text[:1800]
        except Exception as e:
            logger.error(f"工具结果分析知识库检索失败: {e}")
            return ""

    def retrieve_for_risk_assessment(
        self,
        vuln_type: str,
        severity: str
    ) -> str:
        """风险定级前检索知识库——获取等保标准/风险分级文档

        Args:
            vuln_type: 漏洞类型
            severity: 漏洞严重度

        Returns:
            str: 知识库检索结果（风险分级标准、等保条款）
        """
        if self._mode == "vector" and not self.retriever:
            logger.warning("RAG检索器未初始化，风险检索返回空")
            return ""

        query = f"{vuln_type} {severity} 风险等级 等保标准 严重性分级 风险定级指南 安全等级判定"
        if self._mode == "mapping":
            self._total_queries += 1
            return self._mapping_retrieve(query, limit=3)[:1500]

        try:
            self._total_queries += 1
            nodes: List[NodeWithScore] = self.retriever.retrieve(query)
            if not nodes:
                return ""

            parts = []
            for i, node in enumerate(nodes[:3]):
                score = getattr(node, 'score', 0) or 0
                metadata = node.node.metadata if hasattr(node, 'node') else {}
                fname = metadata.get("file_name", "unknown")
                text = node.node.text if hasattr(node, 'node') else str(node)
                parts.append(f"[知识{i+1}] 来源:{fname} 相关度:{score:.3f}\n{text[:400]}")

            result = "【风险定级知识库检索】\n\n" + "\n\n---\n\n".join(parts)
            logger.info(f"风险定级知识库检索成功: {len(nodes)}条结果")
            return result[:1500]
        except Exception as e:
            logger.error(f"风险定级知识库检索失败: {e}")
            return ""

    def get_kb_match_score(self, query: str) -> float:
        """获取知识库匹配度评分

        Args:
            query: 检索查询字符串

        Returns:
            float: 0.0-1.0 的匹配度评分
        """
        if self._mode == "vector" and not self.retriever:
            return 0.0

        if self._mode == "mapping":
            self._total_queries += 1
            matches = self._mapping_search(query, limit=5)
            if not matches:
                return 0.0
            return sum(item["score"] for item in matches) / len(matches)

        try:
            self._total_queries += 1
            nodes: List[NodeWithScore] = self.retriever.retrieve(query)
            if not nodes:
                return 0.0

            scores = [getattr(node, 'score', 0) or 0 for node in nodes[:5]]
            avg_score = sum(scores) / len(scores) if scores else 0.0
            return max(0.0, min(1.0, avg_score))
        except Exception as e:
            logger.error(f"知识库匹配度评分失败: {e}")
            return 0.0

    @property
    def is_ready(self) -> bool:
        if self._mode == "mapping":
            return self._mapping_ready and self._document_count > 0
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
