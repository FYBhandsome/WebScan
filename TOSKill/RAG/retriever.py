"""
RAG 检索器 - 给 graph.py 调用的极简接口
封装 rag_engine 的调用，供 LangGraph 工作流 AI 决策使用
"""
from typing import List, Dict, Any
from .rag_engine import get_rag_engine


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


def rebuild_knowledge_base() -> bool:
    """
    重建知识库索引
    
    在添加/修改知识库文档后调用，重新生成向量索引。
    
    Returns:
        bool: 重建是否成功
    """
    from .rag_engine import rebuild_knowledge_base as _rebuild
    return _rebuild()
