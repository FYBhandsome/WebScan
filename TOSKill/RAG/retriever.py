"""
RAG 检索器 - 给 graph.py 调用的极简接口
封装 rag_engine 的调用，供 LangGraph 工作流 AI 决策使用
"""
from typing import List, Dict, Any
from .rag_engine import get_rag_engine
from ..config import settings


def get_scan_strategy(
    target: str,
    current_task: str,
    completed_tasks: List[str],
    last_result: Dict[str, Any]
) -> str:
    """
    获取扫描策略建议（供 ai_decision 节点调用）
    
    使用 LlamaIndex VectorIndexRetriever 进行语义检索，
    返回知识库中相关的专业知识片段。

    Args:
        target: 扫描目标 URL
        current_task: 当前任务名
        completed_tasks: 已完成任务列表
        last_result: 上一步结果

    Returns:
        str: RAG 检索到的专家建议
    """
    if not settings.RAG_ENABLED:
        return ""
    engine = get_rag_engine()
    return engine.retrieve_scan_strategy(
        target=target,
        current_task=current_task,
        completed_tasks=completed_tasks,
        last_result=last_result
    )


def get_rag_stats() -> Dict[str, Any]:
    """
    获取 RAG 引擎统计信息
    
    Returns:
        Dict: 包含缓存命中率、查询次数、文档数等统计信息
    """
    engine = get_rag_engine()
    return engine.get_stats()


def is_rag_ready() -> bool:
    """
    检查 RAG 引擎是否就绪
    
    Returns:
        bool: RAG 是否可用
    """
    engine = get_rag_engine()
    return engine.is_ready


def initialize_rag(force: bool = False) -> bool:
    """初始化或重新加载 RAG 引擎。"""
    if not settings.RAG_ENABLED:
        return False
    return get_rag_engine().initialize(force=force)


def rebuild_knowledge_base() -> bool:
    """
    重建知识库索引

    在添加/修改知识库文档后调用，重新生成向量索引。

    Returns:
        bool: 重建是否成功
    """
    from .rag_engine import rebuild_knowledge_base as _rebuild
    return _rebuild()


# ==================== 等保评估检索接口 ====================


def get_mlps_assessment_context(
    target: str,
    vulnerabilities: List[Dict[str, Any]],
    tool_results: Dict[str, Any]
) -> str:
    """检索等保评估上下文（供置信度评估器调用）

    返回知识库中的等保2.0标准条款、漏洞→控制项映射、历史评估案例
    等专业知识片段。RAG未就绪时降级为关键词检索。

    Args:
        target: 扫描目标URL
        vulnerabilities: 漏洞列表
        tool_results: 工具执行结果

    Returns:
        str: 检索到的等保知识上下文，失败时返回空字符串
    """
    if not settings.RAG_ENABLED:
        return ""
    engine = get_rag_engine()
    return engine.retrieve_mlps_context(
        target=target,
        vulnerabilities=vulnerabilities,
        tool_results=tool_results
    )


def get_confidence_rules() -> str:
    """检索置信度评判规则

    从知识库中检索置信度评分标准、等级阈值、评估维度权重
    等规则内容，供AI评估时参考。

    Returns:
        str: 检索到的置信度评判规则文本，失败时返回空字符串
    """
    if not settings.RAG_ENABLED:
        return ""
    engine = get_rag_engine()
    if not engine.retriever:
        return ""
    try:
        nodes = engine.retriever.retrieve(
            "技术证据置信度 证据完整性 可重复性 工具适用性 范围覆盖 映射可追溯性 人工复核"
        )
        if not nodes:
            return ""
        parts = []
        for i, node in enumerate(nodes[:3]):
            score = getattr(node, 'score', 0) or 0
            text = node.node.text if hasattr(node, 'node') else str(node)
            metadata = node.node.metadata if hasattr(node, 'node') else {}
            fname = metadata.get("file_name", "unknown")
            parts.append(f"[规则{i+1}] 来源:{fname} 相关度:{score:.3f}\n{text[:1500]}")
        return "\n\n---\n\n".join(parts)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"置信度规则检索失败: {e}")
        return ""


def get_kb_version() -> str:
    """获取知识库版本号

    返回当前知识库的版本标识，用于报告展示。
    版本号格式如 v2.17.20260806（v2.文档数.日期）。

    Returns:
        str: 知识库版本号，不可用时返回空字符串
    """
    if not settings.RAG_ENABLED:
        return ""
    return get_rag_engine().get_kb_version()
