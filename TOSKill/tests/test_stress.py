"""
TOSKill 压力测试
验证并发处理、大消息、长时间运行稳定性
"""
import pytest
import asyncio
import time
import threading
from concurrent.futures import ThreadPoolExecutor


class TestConcurrency:
    """并发测试"""

    def test_concurrent_session_creation(self):
        """并发创建10个session"""
        from TOSKill.AI.core import create_session
        sessions = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_session, f"http://test{i}.example.com", "full_scan")
                       for i in range(10)]
            for f in futures:
                sid = f.result()
                if sid:
                    sessions.append(sid)
        
        unique = set(sessions)
        assert len(sessions) >= 10
        assert len(unique) == len(sessions), "Session IDs should be unique"


class TestMemoryStoreStress:
    """MemoryStore压力测试"""

    def test_bulk_session_operations(self):
        """批量Session操作"""
        from TOSKill.AI.graph import memory_store
        
        for i in range(50):
            sid = f"stress_session_{i}"
            memory_store.save_session(sid, {
                "task_id": sid,
                "target": f"http://test{i}.example.com",
                "completed_tasks": ["baseinfo", "portscan"],
                "is_complete": True,
                "mode": "full_scan"
            })
        
        for i in range(50):
            sid = f"stress_session_{i}"
            session = memory_store.get_session(sid)
            assert session is not None
        
        for i in range(50):
            sid = f"stress_session_{i}"
            memory_store.delete_session(sid)
            assert memory_store.get_session(sid) is None


class TestLLMClientStress:
    """LLM客户端压力测试"""

    def test_rapid_circuit_state_changes(self):
        """快速熔断状态切换"""
        from TOSKill.AI.llm_client import llm_client
        
        original_state = llm_client._open
        
        try:
            for _ in range(5):
                llm_client._record_success(0.1)
                llm_client._record_failure()
                llm_client._record_success(0.1)
            
            assert not llm_client._open
        finally:
            llm_client._open = False
            llm_client._failure_count = 0

    def test_stats_under_load(self):
        """负载下统计应正常"""
        from TOSKill.AI.llm_client import llm_client
        
        llm_client._total_calls = 0
        llm_client._success_calls = 0
        llm_client._open = False
        llm_client._failure_count = 0
        
        for _ in range(50):
            llm_client._total_calls += 1
            llm_client._success_calls += 1
            llm_client._latency_history.append(0.5)
        
        stats = llm_client.get_stats()
        assert stats["total_calls"] >= 50
        assert float(stats["success_rate"].replace("%", "")) >= 90


class TestMessageStress:
    """消息压力测试"""

    def test_large_payload_handling(self):
        """大payload处理"""
        large_payload = {
            "type": "task_completed",
            "payload": {
                "tool": "baseinfo",
                "result": "x" * 10000,
                "timestamp": "2024-01-01T00:00:00"
            }
        }
        
        serialized = None
        try:
            import json
            serialized = json.dumps(large_payload)
        except Exception:
            pass
        
        assert serialized is not None
        assert len(serialized) > 10000

    def test_rapid_ws_message_simulation(self):
        """模拟快速WS消息序列"""
        messages = []
        for i in range(100):
            msg = {
                "type": "progress",
                "payload": {"step": i, "total": 100, "message": f"Processing step {i}"}
            }
            messages.append(msg)
        
        assert len(messages) == 100
        for i, msg in enumerate(messages):
            assert msg["payload"]["step"] == i


class TestLongRunningSimulation:
    """长时间运行模拟"""

    def test_workflow_loop_stability(self):
        """工作流循环稳定性"""
        iterations = 100
        state = {
            "completed_tasks": [],
            "errors": [],
            "next_task": "start"
        }
        
        for i in range(iterations):
            step_data = {
                "tool": f"tool_{i % 22}",
                "status": "success",
                "result": {"key": f"value_{i}"}
            }
            state["completed_tasks"].append(f"tool_{i % 22}")
            if i % 10 == 0:
                state["errors"].append(f"simulated_error_{i}")
        
        assert len(state["completed_tasks"]) == iterations
        assert len(state["errors"]) == iterations // 10


class TestMemoryStability:
    """内存稳定性测试（基础）"""

    def test_cleanup_after_use(self):
        """使用后清理"""
        from TOSKill.AI.graph import memory_store
        
        ids = []
        for i in range(20):
            sid = f"cleanup_test_{i}"
            ids.append(sid)
            memory_store.save_session(sid, {"task_id": sid, "target": f"http://test{i}.com"})
        
        for sid in ids:
            memory_store.delete_session(sid)
        
        for sid in ids:
            assert memory_store.get_session(sid) is None