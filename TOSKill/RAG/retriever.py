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
