"""
RAG 引擎 - 纯 LlamaIndex 实现，与 LangGraph 工作流完全解耦
提供：加载知识库、语义检索、构建扫描策略查询
不依赖 LLM，纯检索模式，推理交给 LangGraph 节点
"""
import os
import logging
from typing import List, Dict, Any, Optional

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    StorageContext,
    load_index_from_storage,
    Settings
)
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

logger = logging.getLogger(__name__)

_STORAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage")
_KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge")


class TOSKillRAGEngine:
    """LlamaIndex RAG 引擎单例（纯检索，不依赖LLM）"""

    _instance: Optional["TOSKillRAGEngine"] = None

    def __init__(self):
        self.index: Optional[VectorStoreIndex] = None
        self.retriever = None
        self._initialized = False
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

            Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-zh-v1.5")

            try:
                storage_context = StorageContext.from_defaults(persist_dir=_STORAGE_DIR)
                self.index = load_index_from_storage(storage_context)
                logger.info("RAG 索引加载成功 (persisted)")
            except Exception:
                logger.info("未找到持久化索引，从知识库文件创建...")
                if not os.path.exists(_KNOWLEDGE_DIR):
                    os.makedirs(_KNOWLEDGE_DIR, exist_ok=True)
                documents = SimpleDirectoryReader(_KNOWLEDGE_DIR).load_data()
                self.index = VectorStoreIndex.from_documents(documents, show_progress=True)
                os.makedirs(_STORAGE_DIR, exist_ok=True)
                self.index.storage_context.persist(persist_dir=_STORAGE_DIR)
                logger.info(f"RAG 索引创建成功 ({len(documents)} 文档)")

            self.retriever = self.index.as_retriever(similarity_top_k=5)
            self._initialized = True
            logger.info("TOSKillRAGEngine 初始化完成（纯检索模式）")

        except Exception as e:
            logger.warning(f"RAG 初始化失败（系统将以非RAG模式运行）: {e}")
            self._initialized = True
            self.retriever = None

    def retrieve_scan_strategy(
        self,
        target: str,
        current_task: str,
        completed_tasks: List[str],
        last_result: Dict[str, Any]
    ) -> str:
        """
        安全扫描专用检索：返回相关专业知识片段
        推理判断由 graph.py 的 LLM 节点完成

        Args:
            target: 扫描目标URL
            current_task: 当前待执行任务名
            completed_tasks: 已完成的任务名列表
            last_result: 上一步工具执行结果

        Returns:
            str: 检索到的专业知识上下文
        """
        if not self.retriever:
            return ""

        query = f"""安全扫描专家知识：目标 {target}
已完成任务: {completed_tasks if completed_tasks else '无'}
上一步结果: {str(last_result)[:300]}
当前任务: {current_task if current_task else '待决策'}
请检索最相关的安全扫描策略、工具选择、漏洞检测方法等专业知识"""

        try:
            nodes = self.retriever.retrieve(query)
            if not nodes:
                return ""

            parts = []
            for i, node in enumerate(nodes[:5]):
                score = node.score if hasattr(node, 'score') else 0
                fname = node.metadata.get("file_name", "unknown")
                parts.append(f"[知识{i+1}] 来源: {fname} | 相关度: {score:.2f}\n{node.text[:500]}")
            return "\n\n---\n\n".join(parts)
        except Exception as e:
            logger.error(f"RAG 检索失败: {e}")
            return ""

    @property
    def is_ready(self) -> bool:
        return self._initialized and self.retriever is not None


_rag_engine: Optional[TOSKillRAGEngine] = None


def get_rag_engine() -> TOSKillRAGEngine:
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = TOSKillRAGEngine.get_instance()
    return _rag_engine
