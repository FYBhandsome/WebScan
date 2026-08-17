"""
RAG 引擎 - LlamaIndex 高级检索实现
提供：语义检索、元数据过滤、重排序、知识库管理
与 LangGraph 工作流解耦，推理交给 AI 节点
"""
import os
import json
import logging
import hashlib
import threading
import functools
import time
import shutil
import subprocess
import tempfile
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

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
from ..config import settings

logger = logging.getLogger(__name__)

_STORAGE_DIR = Path(__file__).parent / "storage"
_KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"
_MANIFEST_PATH = _STORAGE_DIR / "index_manifest.json"
_INDEX_SCHEMA_VERSION = 3

TOOL_KNOWLEDGE_MAP = {
    "baseinfo_scan": ["信息收集", "资产发现", "HTTP头", "SSL证书", "技术栈识别"],
    "port_scan": ["端口扫描", "服务识别", "Nmap", "开放端口", "服务指纹"],
    "subdomain_scan": ["子域名", "DNS", "资产发现", "域名枚举", "子域名接管"],
    "dir_brute": ["目录扫描", "敏感文件", "路径枚举", "备份文件", "信息泄露"],
    "waf_detect_scan": ["WAF检测", "防火墙识别", "安全设备", "云WAF", "防护策略"],
    "cdn_detect_scan": ["CDN检测", "内容分发网络", "资产边界", "域名解析"],
    "cms_detect_scan": ["CMS检测", "内容管理系统", "指纹识别", "技术栈识别"],
    "infoleak_scan": ["信息泄露", "敏感文件", "错误信息", "公开信息"],
    "ip_locate_scan": ["IP定位", "地理位置", "运营商", "资产归属"],
    "webside_query_scan": ["网站备案", "ICP备案", "备案主体", "站点归属"],
    "web_weight_scan": ["网站权重", "搜索引擎权重", "公开情报", "站点影响面"],
    "crawler_scan": ["Web爬虫", "站点地图", "链接", "表单", "参数", "脚本"],
    "tls_certificate_scan": ["TLS证书", "HTTPS", "证书有效期", "SAN", "加密协议"],
    "http_methods_scan": ["HTTP方法", "OPTIONS", "危险方法", "状态码", "重定向"],
    "public_metadata_scan": ["robots.txt", "sitemap.xml", "security.txt", "公开元数据"],
    "sqli_scan": ["SQL注入", "数据库攻击", "OWASP", "盲注", "Union注入", "时间盲注"],
    "xss_scan": ["XSS", "跨站脚本", "前端安全", "DOM型", "反射型", "存储型"],
    "cmdi_scan": ["命令注入", "RCE", "管道符", "命令执行", "远程代码执行"],
    "fileupload_scan": ["文件上传", "WebShell", "绕过", "双扩展名", "图片马"],
    "ssrf_scan": ["SSRF", "云元数据", "内网访问", "协议利用", "服务端请求伪造"],
    "weakpass_scan": ["弱口令", "暴力破解", "默认密码", "字典攻击", "凭证猜测"],
    "lfi_scan": ["文件包含", "目录遍历", "路径穿越", "本地文件", "日志注入"],
    "csrf_scan": ["CSRF", "跨站请求伪造", "表单提交", "Token验证"],
    "http_security_headers_scan": ["HTTP安全响应头", "CSP", "HSTS", "X-Frame-Options", "安全配置"],
    "cookie_security_scan": ["Cookie安全", "Secure", "HttpOnly", "SameSite", "会话保护"],
    "cors_misconfiguration_scan": ["CORS配置", "Origin反射", "跨域", "凭证请求", "访问控制"],
    "thinkphp_rce_scan": ["ThinkPHP", "远程代码执行", "框架漏洞", "POC验证", "授权检测"],
    "struts2_scan": ["Struts2", "远程代码执行", "框架漏洞", "POC验证", "授权检测"],
    "weblogic_scan": ["WebLogic", "中间件漏洞", "远程代码执行", "POC验证", "授权检测"],
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

MLPS_VULN_MAPPING = {
    "sqli": ["SQL注入", "8.1.3.2", "访问控制", "8.1.3.4", "入侵防范", "证据映射"],
    "xss": ["XSS", "8.1.3.4", "入侵防范", "跨站脚本", "证据映射"],
    "rce": ["命令注入", "8.1.3.4", "入侵防范", "远程代码执行", "证据映射"],
    "fileupload": ["文件上传", "8.1.3.2", "访问控制", "8.1.3.4", "入侵防范"],
    "ssrf": ["SSRF", "安全区域边界", "入侵防范", "服务端请求", "证据映射"],
    "weakpass": ["弱口令", "8.1.3.1", "身份鉴别", "密码策略", "暴力破解防护"],
    "lfi": ["文件包含", "8.1.3.2", "访问控制", "路径穿越", "文件读取"],
    "csrf": ["CSRF", "8.1.3.2", "访问控制", "跨站请求", "Token验证"],
    "info_leak": ["信息泄露", "8.1.3.3", "安全审计", "敏感信息", "错误处理"],
    "infoleak": ["信息泄露", "8.1.3.3", "安全审计", "敏感信息", "错误处理"],
    "auth_bypass": ["认证绕过", "8.1.3.1", "身份鉴别", "未授权访问", "权限控制"],
    "security_headers": ["HTTP安全响应头", "安全通信网络", "安全配置", "支持性线索"],
    "cookie_security": ["Cookie安全属性", "身份鉴别", "安全通信网络", "会话保护"],
    "cors": ["CORS错误配置", "访问控制", "安全区域边界", "跨域凭证"],
}

MLPS_SCENARIO_KEYWORDS = {
    "confidence_assessment": [
        "等保2.0", "技术证据置信度", "证据完整性", "可重复性",
        "控制项映射", "评估依据", "人工复核", "未评估范围",
    ],
    "compliance_check": [
        "等保三级", "技术证据", "安全计算环境", "安全区域边界",
        "安全通信网络", "安全管理中心", "不构成测评结论",
    ],
}


class TOSKillRAGEngine:
    """LlamaIndex RAG 引擎 - 高级检索模式"""

    _instance: Optional["TOSKillRAGEngine"] = None
    MODEL_LOAD_TIMEOUT = settings.RAG_MODEL_LOAD_TIMEOUT
    FALLBACK_MODELS = [
        "BAAI/bge-small-zh-v1.5",
        "sentence-transformers/all-MiniLM-L6-v2",
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    ]

    def __init__(self):
        self.index: Optional[VectorStoreIndex] = None
        self.retriever: Optional[VectorIndexRetriever] = None
        self._initialized = False
        self._query_cache: Dict[str, str] = {}
        self._cache_hits = 0
        self._total_queries = 0
        self._document_count = 0
        self._embed_model = None
        self._model_load_error: Optional[str] = None
        self._index_generation = 0
        # 索引重建、首次初始化和状态读取共用此锁。重建完成前绝不替换
        # 正在服务请求的内存索引。
        self._index_lock = threading.RLock()
        if settings.RAG_ENABLED:
            self._initialize_rag()

    @classmethod
    def get_instance(cls) -> "TOSKillRAGEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_embed_model_with_timeout(
        self,
        model_name: str,
        cache_folder: str,
        timeout: int = None,
        local_model_path: Optional[Path] = None,
    ) -> Optional[HuggingFaceEmbedding]:
        """加载嵌入模型；本地 snapshot 直接加载，下载路径保留超时保护。"""
        if timeout is None:
            timeout = self.MODEL_LOAD_TIMEOUT

        load_target = str(local_model_path) if local_model_path else model_name

        def _load_model() -> HuggingFaceEmbedding:
            logger.info(
                "正在加载嵌入模型: %s%s",
                model_name,
                f" (本地 snapshot: {local_model_path})" if local_model_path else "",
            )
            return HuggingFaceEmbedding(
                model_name=load_target,
                cache_folder=cache_folder,
            )

        started_at = time.monotonic()

        # 本地模型不需要网络，也不应该因为下载超时机制被误判为不可用。
        # 服务启动本身已经在 asyncio.to_thread 中执行 RAG 初始化；这里直接等待
        # 本地模型完成加载，避免留下无法取消的后台加载线程。
        if local_model_path is not None:
            try:
                embed_model = _load_model()
                logger.info(
                    "嵌入模型加载成功: %s (%.1fs)",
                    model_name,
                    time.monotonic() - started_at,
                )
                return embed_model
            except Exception as exc:
                logger.warning("本地嵌入模型加载失败: %s, 错误: %s", model_name, exc)
                return None
        
        result = [None]
        exception = [None]
        
        def _load():
            try:
                embed_model = _load_model()
                result[0] = embed_model
                logger.info(
                    "嵌入模型加载成功: %s (%.1fs)",
                    model_name,
                    time.monotonic() - started_at,
                )
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=_load, daemon=True)
        thread.start()
        thread.join(timeout=timeout)
        
        if thread.is_alive():
            logger.warning(
                "模型加载超时 (%ss): %s；后台加载线程无法被强制终止，"
                "本次 RAG 初始化将降级",
                timeout,
                model_name,
            )
            return None
        
        if exception[0]:
            logger.warning(f"模型加载失败: {model_name}, 错误: {exception[0]}")
            return None
        
        return result[0]

    @staticmethod
    def _is_valid_snapshot(snapshot_path: Path) -> bool:
        """判断 snapshot 是否包含可供 sentence-transformers 加载的核心文件。"""
        if not snapshot_path.is_dir():
            return False
        if not (snapshot_path / "config.json").is_file():
            return False
        model_files = (
            "model.safetensors",
            "pytorch_model.bin",
            "tf_model.h5",
            "model.ckpt.index",
        )
        return any((snapshot_path / filename).is_file() for filename in model_files)

    @classmethod
    def _find_cached_model_snapshot(
        cls,
        model_name: str,
        cache_folder: str,
    ) -> Optional[Path]:
        """查找 HuggingFace 的本地 snapshot，兼容不同版本的缓存布局。"""
        model_dir_name = model_name.replace("/", "--")
        cache_root = Path(cache_folder).expanduser()

        candidate_repositories = [
            cache_root / f"models--{model_dir_name}",
            cache_root / "hub" / f"models--{model_dir_name}",
        ]

        # 如果用户通过 HF_HUB_CACHE/HF_HOME 指定了其他目录，也纳入查找范围。
        hf_hub_cache = os.getenv("HF_HUB_CACHE")
        if hf_hub_cache:
            candidate_repositories.append(Path(hf_hub_cache).expanduser() / f"models--{model_dir_name}")
        hf_home = os.getenv("HF_HOME")
        if hf_home:
            hf_home_path = Path(hf_home).expanduser()
            candidate_repositories.extend([
                hf_home_path / f"models--{model_dir_name}",
                hf_home_path / "hub" / f"models--{model_dir_name}",
            ])

        seen = set()
        for model_cache_path in candidate_repositories:
            model_cache_path = model_cache_path.resolve()
            if model_cache_path in seen or not model_cache_path.is_dir():
                continue
            seen.add(model_cache_path)

            snapshots_path = model_cache_path / "snapshots"
            if not snapshots_path.is_dir():
                continue

            snapshots = [path for path in snapshots_path.iterdir() if cls._is_valid_snapshot(path)]
            if not snapshots:
                continue

            # 优先使用 refs/main 指向的 revision；没有 refs 时按修改时间选择最新 snapshot。
            revision = ""
            ref_path = model_cache_path / "refs" / "main"
            if ref_path.is_file():
                try:
                    revision = ref_path.read_text(encoding="utf-8").strip()
                except OSError:
                    revision = ""
            if revision:
                referenced = snapshots_path / revision
                if cls._is_valid_snapshot(referenced):
                    return referenced

            return max(snapshots, key=lambda path: path.stat().st_mtime)

        return None

    @classmethod
    def _check_model_cached(cls, model_name: str, cache_folder: str) -> bool:
        """检查模型是否已在本地缓存且包含可加载的 snapshot。"""
        snapshot = cls._find_cached_model_snapshot(model_name, cache_folder)
        if snapshot:
            logger.info("模型已在本地缓存: %s (%s)", model_name, snapshot)
            return True
        logger.debug("模型未缓存或缓存不完整: %s", model_name)
        return False

    def _try_load_embed_model(self) -> Optional[HuggingFaceEmbedding]:
        """优先加载本地模型，并按配置允许首次下载主模型。"""
        cache_folder = str(Path(settings.RAG_MODEL_CACHE_DIR).expanduser())

        # 只有明确禁止下载时才启用离线模式；RAG_ALLOW_DOWNLOAD=True 时不再
        # 无条件覆盖用户网络配置。已找到的本地 snapshot 始终走本地路径。
        if not settings.RAG_ALLOW_DOWNLOAD:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
        
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder, exist_ok=True)
            logger.info(f"创建模型缓存目录: {cache_folder}")
        
        model_names = list(dict.fromkeys([settings.RAG_EMBED_MODEL, *self.FALLBACK_MODELS]))
        for model_name in model_names:
            local_model_path = self._find_cached_model_snapshot(model_name, cache_folder)
            is_cached = local_model_path is not None
            can_download = settings.RAG_ALLOW_DOWNLOAD and model_name == settings.RAG_EMBED_MODEL
            if not is_cached and not can_download:
                logger.info(f"跳过未缓存模型: {model_name}")
                continue

            if is_cached:
                logger.info(f"尝试加载本地缓存模型: {model_name} ({local_model_path})")
            else:
                logger.info(f"本地未缓存，尝试下载嵌入模型: {model_name}")
            embed_model = self._load_embed_model_with_timeout(
                model_name=model_name,
                cache_folder=cache_folder,
                timeout=self.MODEL_LOAD_TIMEOUT,
                local_model_path=local_model_path,
            )
            if embed_model:
                logger.info(f"模型加载成功: {model_name}")
                return embed_model
            else:
                logger.warning(f"模型加载失败: {model_name}")
                continue
        
        logger.error("没有可用的本地缓存模型，RAG功能不可用")
        return None

    def initialize(self, force: bool = False) -> bool:
        """初始化或重新初始化 RAG 引擎。"""
        with self._index_lock:
            if force:
                self.index = None
                self.retriever = None
                self._initialized = False
                self._embed_model = None
                self._model_load_error = None
                self._query_cache.clear()
            self._initialize_rag()
            return self.is_ready

    def _knowledge_fingerprint(self) -> str:
        digest = hashlib.sha256(settings.RAG_EMBED_MODEL.encode("utf-8"))
        for md_file in sorted(_KNOWLEDGE_DIR.glob("*.md")):
            digest.update(md_file.name.encode("utf-8"))
            digest.update(md_file.read_bytes())
        return digest.hexdigest()

    def _manifest_matches(self) -> bool:
        if not _MANIFEST_PATH.exists():
            return False
        try:
            manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
            return (
                manifest.get("storage_schema") == _INDEX_SCHEMA_VERSION
                and
                manifest.get("embed_model") == settings.RAG_EMBED_MODEL
                and manifest.get("knowledge_fingerprint") == self._knowledge_fingerprint()
            )
        except Exception as e:
            logger.warning(f"读取RAG索引清单失败，将重建索引: {e}")
            return False

    def _write_manifest(self, persist_dir: Optional[Path] = None, document_count: Optional[int] = None):
        """写入索引清单；重建时写入临时目录而不是线上目录。"""
        persist_dir = persist_dir or _STORAGE_DIR
        document_count = self._document_count if document_count is None else document_count
        manifest = {
            "storage_schema": _INDEX_SCHEMA_VERSION,
            "embed_model": settings.RAG_EMBED_MODEL,
            "knowledge_fingerprint": self._knowledge_fingerprint(),
            "document_count": document_count,
            "version": f"v2.{document_count}.{datetime.now().strftime('%Y%m%d')}",
            "indexed_at": datetime.now().isoformat(),
        }
        (persist_dir / "index_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def _initialize_rag(self):
        with self._index_lock:
            if self._initialized:
                return
            try:
                self._embed_model = self._try_load_embed_model()

                if self._embed_model is None:
                    self._model_load_error = "所有嵌入模型加载失败，RAG功能不可用"
                    logger.warning(self._model_load_error)
                    logger.warning("服务将在无RAG模式下启动，工作流将跳过RAG增强步骤")
                    return

                Settings.embed_model = self._embed_model

                _STORAGE_DIR.mkdir(parents=True, exist_ok=True)
                _KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)

                index_exists = (_STORAGE_DIR / "docstore.json").exists()
                if index_exists and self._manifest_matches():
                    try:
                        storage_context = StorageContext.from_defaults(persist_dir=str(_STORAGE_DIR))
                        self.index = load_index_from_storage(storage_context)
                        self._document_count = len(list(_KNOWLEDGE_DIR.glob("*.md")))
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
                self._model_load_error = None
                logger.info(f"TOSKillRAGEngine 初始化完成 (文档数: {self._document_count})")

            except Exception as e:
                logger.error(f"RAG 初始化失败: {e}", exc_info=True)
                self._model_load_error = f"RAG初始化失败: {e}"
                logger.warning("服务将在无RAG模式下启动，工作流将跳过RAG增强步骤")

    def _build_index(self):
        """从知识库文件构建、验证并发布向量索引。"""
        index, document_count = self._build_staged_index()
        self.index = index
        self._document_count = document_count
        logger.info(f"RAG 索引创建成功: {self._document_count} 个文档")

    def _load_knowledge_documents(self) -> List[Document]:
        """读取知识库文档；构建失败不应触碰当前持久化索引。"""
        documents = []
        
        for md_file in _KNOWLEDGE_DIR.glob("*.md"):
            try:
                reader = SimpleDirectoryReader(
                    input_files=[str(md_file)],
                    filename_as_id=False,
                )
                docs = reader.load_data()
                source_id = self._portable_source_id(md_file)
                for doc in docs:
                    # SimpleDirectoryReader 会注入 file_path/document_id 等绝对路径
                    # 元数据。索引需要跨设备可用，因此只保存稳定的相对标识。
                    doc.id_ = source_id
                    doc.metadata = {
                        "file_name": md_file.name,
                        "source": source_id,
                    }
                documents.extend(docs)
                logger.debug(f"加载知识库: {md_file.name}")
            except Exception as e:
                logger.warning(f"加载文档失败 {md_file}: {e}")

        if not documents:
            logger.warning("知识库为空，创建默认文档")
            documents = [Document(
                text="Web安全扫描知识库。支持XSS、SQL注入、文件上传等漏洞检测。",
                id_="knowledge/default.md",
                metadata={"file_name": "default.md", "source": "knowledge/default.md"},
            )]

        return documents

    @staticmethod
    def _portable_source_id(knowledge_file: Path) -> str:
        """生成与项目部署位置无关的知识库文档标识。"""
        try:
            return knowledge_file.relative_to(_KNOWLEDGE_DIR.parent).as_posix()
        except ValueError:
            # 防御性回退：调用方即使传入外部路径，也绝不将该绝对路径写入索引。
            return f"knowledge/{knowledge_file.name}"

    def _create_index(self) -> tuple[VectorStoreIndex, int]:
        documents = self._load_knowledge_documents()
        return VectorStoreIndex.from_documents(documents, show_progress=True), len(documents)

    def _validate_staged_index(self, persist_dir: Path) -> None:
        """在发布前重新加载一次临时索引，确保落盘文件完整可用。"""
        storage_context = StorageContext.from_defaults(persist_dir=str(persist_dir))
        loaded_index = load_index_from_storage(storage_context)
        VectorIndexRetriever(index=loaded_index, similarity_top_k=5)

    @staticmethod
    def _enable_windows_acl_inheritance(path: Path) -> None:
        """让生成的索引继承父目录 ACL，避免跨 Windows 账户后不可访问。"""
        if os.name != "nt":
            return

        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:e", "/t", "/c"],
            capture_output=True,
            text=True,
            check=False,
            creationflags=creation_flags,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "未知错误").strip()
            raise RuntimeError(f"恢复 RAG 索引 ACL 继承失败: {detail}")

    def _promote_staged_storage(self, staged_dir: Path) -> None:
        """发布临时索引；兼容 Windows 无法重命名正在访问目录的限制。"""
        storage_parent = _STORAGE_DIR.parent
        storage_parent.mkdir(parents=True, exist_ok=True)
        backup_dir = storage_parent / f"storage-backup-{uuid.uuid4().hex}"
        staged_files = [path for path in staged_dir.iterdir() if path.is_file()]
        if not staged_files:
            raise RuntimeError("临时 RAG 索引目录为空，拒绝发布")

        # 某些受限运行环境会为新文件创建仅所有者可访问的保护 ACL。
        # os.replace 会保留源文件 ACL，因此必须在发布前恢复目录继承，否则
        # 换用普通用户启动服务后将无法读取已生成的索引。
        self._enable_windows_acl_inheritance(staged_dir)

        # manifest 是索引完整可用的提交标志，必须最后替换。这样在发布期间，
        # 新进程最多看到旧清单而非半成品清单。
        staged_files.sort(key=lambda path: path.name == "index_manifest.json")
        replaced_names: List[str] = []
        removed_names: List[str] = []
        moved_backup_names: List[str] = []

        try:
            backup_dir.mkdir()

            # 先复制现有 JSON 作为回滚备份，不重命名 storage 目录本身。
            # Windows 上目录句柄（Explorer、杀毒软件、运行中的服务）可能拒绝
            # 目录 rename，但通常不会阻止单个文件的原子替换。
            current_json_files = [
                path for path in _STORAGE_DIR.glob("*.json") if path.is_file()
            ]
            for current_file in current_json_files:
                backup_file = backup_dir / current_file.name
                try:
                    shutil.copy2(current_file, backup_file)
                except PermissionError:
                    # 兼容旧版本留下的仅原所有者可读文件。当前账户可能无法
                    # 打开文件内容，但只要拥有父目录修改权限，仍可在同卷内
                    # 原子移动文件。移动后的备份同样可用于完整回滚。
                    logger.warning(
                        "现有 RAG 索引不可读，改用原子移动备份: %s",
                        current_file,
                    )
                    os.replace(current_file, backup_file)
                    moved_backup_names.append(current_file.name)

            for staged_file in staged_files:
                target_file = _STORAGE_DIR / staged_file.name
                os.replace(staged_file, target_file)
                replaced_names.append(staged_file.name)

            staged_names = {path.name for path in staged_files}
            for current_file in current_json_files:
                if current_file.name not in staged_names and current_file.exists():
                    current_file.unlink()
                    removed_names.append(current_file.name)
        except Exception as exc:
            rollback_errors = []
            changed_names = list(dict.fromkeys(
                replaced_names + removed_names + moved_backup_names
            ))
            for file_name in reversed(changed_names):
                backup_file = backup_dir / file_name
                target_file = _STORAGE_DIR / file_name
                try:
                    if backup_file.exists():
                        os.replace(backup_file, target_file)
                    elif target_file.exists():
                        target_file.unlink()
                except OSError as rollback_exc:
                    rollback_errors.append(f"{file_name}: {rollback_exc}")

            if rollback_errors:
                logger.error("RAG 索引发布失败，且部分文件回滚失败: %s", "; ".join(rollback_errors))
            raise RuntimeError(f"发布 RAG 索引文件失败: {exc}") from exc
        finally:
            if backup_dir.exists():
                try:
                    shutil.rmtree(backup_dir)
                except OSError as exc:
                    logger.warning("清理 RAG 索引备份目录失败 %s: %s", backup_dir, exc)

    def _build_staged_index(self) -> tuple[VectorStoreIndex, int]:
        """构建到临时目录，验证成功后才替换正式索引目录。"""
        _STORAGE_DIR.parent.mkdir(parents=True, exist_ok=True)
        staged_dir = Path(tempfile.mkdtemp(prefix="storage-rebuild-", dir=str(_STORAGE_DIR.parent)))
        try:
            index, document_count = self._create_index()
            index.storage_context.persist(persist_dir=str(staged_dir))
            self._write_manifest(staged_dir, document_count)
            self._validate_staged_index(staged_dir)
            self._promote_staged_storage(staged_dir)
            return index, document_count
        finally:
            if staged_dir.exists():
                shutil.rmtree(staged_dir, ignore_errors=True)

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

    def _get_retriever_snapshot(self) -> tuple[Optional[VectorIndexRetriever], int]:
        """获取一次检索快照，使正在执行的查询可安全使用旧索引。"""
        with self._index_lock:
            return self.retriever, self._index_generation

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
        retriever, index_generation = self._get_retriever_snapshot()
        if not retriever:
            if settings.RAG_KEYWORD_FALLBACK:
                logger.warning("RAG向量检索器未初始化，使用关键词知识库检索")
                return self._retrieve_keyword_strategy(current_task, completed_tasks, last_result)
            logger.warning("RAG检索器未初始化，返回空结果")
            return ""

        self._total_queries += 1
        
        cache_key = f"{index_generation}:{self._get_cache_key(target, current_task, completed_tasks)}"
        if cache_key in self._query_cache:
            self._cache_hits += 1
            logger.debug(f"RAG缓存命中: {cache_key[:8]}")
            return self._query_cache[cache_key]

        query = self._build_retrieval_query(target, current_task, completed_tasks, last_result)

        try:
            nodes: List[NodeWithScore] = retriever.retrieve(query)
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

    def _retrieve_keyword_strategy(
        self,
        current_task: str,
        completed_tasks: List[str],
        last_result: Dict[str, Any]
    ) -> str:
        query = self._build_retrieval_query("", current_task, completed_tasks, last_result)
        keywords = [word.lower() for word in query.split() if len(word) > 1]
        matches = []
        for md_file in _KNOWLEDGE_DIR.glob("*.md"):
            try:
                content = md_file.read_text(encoding="utf-8")
                lowered = content.lower()
                score = sum(lowered.count(keyword) for keyword in keywords)
                if score:
                    matches.append((score, md_file.name, content))
            except Exception as e:
                logger.warning(f"关键词检索读取失败 {md_file}: {e}")
        if not matches:
            return ""
        matches.sort(key=lambda item: item[0], reverse=True)
        parts = [f"[知识{i + 1}] 来源:{name}\n{content[:600]}" for i, (_, name, content) in enumerate(matches[:3])]
        return "【关键词知识库检索结果】\n\n" + "\n\n---\n\n".join(parts)

    # ==================== 等保评估检索 ====================

    def retrieve_mlps_context(
        self,
        target: str,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any]
    ) -> str:
        """检索等保技术证据上下文（要求主题+证据映射+评估案例）

        供置信度评估器调用，返回等保2.0要求主题、漏洞→控制项证据映射、
        评估案例及人工复核边界。

        Args:
            target: 扫描目标URL
            vulnerabilities: 漏洞列表
            tool_results: 工具执行结果

        Returns:
            str: 检索到的等保知识上下文
        """
        retriever, index_generation = self._get_retriever_snapshot()
        if not retriever:
            if settings.RAG_KEYWORD_FALLBACK:
                logger.warning("RAG未就绪，使用关键词降级检索等保上下文")
                return self._retrieve_mlps_keyword_fallback(vulnerabilities)
            logger.warning("RAG检索器未初始化，返回空结果")
            return ""

        self._total_queries += 1

        query = self._build_mlps_query(vulnerabilities, tool_results)
        cache_key = f"{index_generation}:" + hashlib.md5(("mlps:" + query).encode()).hexdigest()
        if cache_key in self._query_cache:
            self._cache_hits += 1
            logger.debug(f"MLPS RAG缓存命中: {cache_key[:8]}")
            return self._query_cache[cache_key]

        try:
            nodes: List[NodeWithScore] = retriever.retrieve(query)
            if not nodes:
                logger.warning(f"MLPS RAG检索无结果: query='{query[:50]}...'")
                return ""

            parts = []
            sources = []
            for i, node in enumerate(nodes[:5]):
                score = getattr(node, 'score', 0) or 0
                metadata = node.node.metadata if hasattr(node, 'node') else {}
                fname = metadata.get("file_name", "unknown")
                sources.append(fname)

                text = node.node.text if hasattr(node, 'node') else str(node)

                if score > 0.7:
                    text_content = text[:1200]
                elif score > 0.5:
                    text_content = text[:800]
                else:
                    text_content = text[:400]

                parts.append(f"[知识{i+1}] 来源:{fname} 相关度:{score:.3f}\n{text_content}")

            result = "\n\n---\n\n".join(parts)

            # MLPS上下文限制3000字符（区别于扫描策略的1500-2000）
            if len(result) > 3000:
                result = result[:3000] + "\n\n...[内容已截断]"

            if len(self._query_cache) < 200:
                self._query_cache[cache_key] = result

            logger.info(f"MLPS RAG检索成功: query='{query[:50]}...' sources={sources}")
            return result

        except Exception as e:
            logger.error(f"MLPS RAG检索失败: {e}")
            return ""

    def _build_mlps_query(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tool_results: Dict[str, Any]
    ) -> str:
        """构建等保技术证据评估检索查询"""
        query_parts = []
        query_parts.extend(MLPS_SCENARIO_KEYWORDS["confidence_assessment"])
        query_parts.extend(MLPS_SCENARIO_KEYWORDS["compliance_check"])

        for v in vulnerabilities[:5]:
            vtype = str(v.get("type") or v.get("vuln_type", "")).lower()
            if vtype in MLPS_VULN_MAPPING:
                query_parts.extend(MLPS_VULN_MAPPING[vtype])

        tool_count = len(tool_results)
        if tool_count >= 8:
            query_parts.append("多工具技术证据 范围覆盖 执行状态 未评估项")
        elif tool_count >= 5:
            query_parts.append("多工具检测 证据完整性 可重复性")
        elif tool_count <= 2:
            query_parts.append("单工具检测 有限范围 禁止外推 人工复核")

        if not query_parts:
            query_parts = ["等保2.0三级 技术证据置信度 控制项映射 未评估范围 人工复核"]

        return " ".join(query_parts)

    def _retrieve_mlps_keyword_fallback(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """RAG不可用时的等保上下文关键词降级检索"""
        query = " ".join(MLPS_SCENARIO_KEYWORDS["confidence_assessment"])
        keywords = [word.lower() for word in query.split() if len(word) > 1]

        for v in vulnerabilities[:3]:
            vtype = str(v.get("type") or v.get("vuln_type", "")).lower()
            if vtype in MLPS_VULN_MAPPING:
                keywords.extend(k.lower() for k in MLPS_VULN_MAPPING[vtype])

        matches = []
        for md_file in _KNOWLEDGE_DIR.glob("*.md"):
            try:
                content = md_file.read_text(encoding="utf-8")
                lowered = content.lower()
                score = sum(lowered.count(keyword) for keyword in keywords)
                if score:
                    matches.append((score, md_file.name, content))
            except Exception as e:
                logger.warning(f"MLPS关键词检索读取失败 {md_file}: {e}")

        if not matches:
            return ""

        matches.sort(key=lambda item: item[0], reverse=True)
        parts = [
            f"[知识{i+1}] 来源:{name}\n{content[:800]}"
            for i, (_, name, content) in enumerate(matches[:3])
        ]
        return "【MLPS关键词知识库检索结果】\n\n" + "\n\n---\n\n".join(parts)

    def get_kb_version(self) -> str:
        """获取知识库版本号"""
        try:
            if _MANIFEST_PATH.exists():
                with open(_MANIFEST_PATH, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
                version = manifest.get("version", "")
                if version:
                    return version
                doc_count = manifest.get("document_count", 0)
                return f"v2.{doc_count}"
        except Exception as e:
            logger.debug(f"读取知识库版本失败: {e}")
        return ""

    def rebuild_index(self) -> bool:
        """重建向量索引；失败时保留旧索引及其检索能力。"""
        with self._index_lock:
            try:
                if self._embed_model is None:
                    self._embed_model = self._try_load_embed_model()
                    if self._embed_model is None:
                        self._model_load_error = "所有嵌入模型加载失败，无法重建 RAG 索引"
                        logger.warning(self._model_load_error)
                        return False

                Settings.embed_model = self._embed_model
                new_index, new_document_count = self._build_staged_index()
                new_retriever = VectorIndexRetriever(
                    index=new_index,
                    similarity_top_k=5,
                )

                # 持久化文件已完成验证并发布后，才一次性切换内存检索器。
                self.index = new_index
                self.retriever = new_retriever
                self._document_count = new_document_count
                self._initialized = True
                self._model_load_error = None
                self._index_generation += 1
                self._query_cache.clear()
                logger.info("RAG 索引重建成功: 文档数=%s", new_document_count)
                return True
            except Exception as e:
                logger.error("RAG 索引重建失败，继续使用旧索引: %s", e, exc_info=True)
                return False

    def get_stats(self) -> Dict[str, Any]:
        with self._index_lock:
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
                "embed_model_loaded": self._embed_model is not None,
                "model_load_error": self._model_load_error,
                "embed_model": settings.RAG_EMBED_MODEL,
                "model_cache_dir": settings.RAG_MODEL_CACHE_DIR,
                "keyword_fallback_enabled": settings.RAG_KEYWORD_FALLBACK,
            }

    @property
    def is_ready(self) -> bool:
        with self._index_lock:
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
