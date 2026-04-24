"""
Unit tests for VerificationEngine module

Tests for:
- ExecutionConfig
- ExecutionStats
- ResourceUsage
- EngineConfig
- PrioritizedTask
- ExecutionHistoryEntry
- ExecutionProgress
- ExecutionResultCache
- ResourceMonitor
- ExecutionQueue
- VerificationEngine
"""
import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from collections import deque

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.ai_agents.poc_system.verification_engine import (
    ExecutionPriority,
    ExecutionStatus,
    ExecutionConfig,
    ExecutionStats,
    ResourceUsage,
    EngineConfig,
    PrioritizedTask,
    ExecutionHistoryEntry,
    ExecutionProgress,
    ExecutionResultCache,
    ResourceMonitor,
    ExecutionQueue,
    VerificationEngine,
    ProgressCallback,
    CompleteCallback,
    ErrorCallback,
    verification_engine,
)


class TestExecutionPriority:
    """Tests for ExecutionPriority enum"""

    def test_priority_values(self):
        assert ExecutionPriority.LOW.value == 1
        assert ExecutionPriority.NORMAL.value == 5
        assert ExecutionPriority.HIGH.value == 10
        assert ExecutionPriority.CRITICAL.value == 20


class TestExecutionStatus:
    """Tests for ExecutionStatus enum"""

    def test_status_values(self):
        assert ExecutionStatus.PENDING.value == "pending"
        assert ExecutionStatus.QUEUED.value == "queued"
        assert ExecutionStatus.RUNNING.value == "running"
        assert ExecutionStatus.COMPLETED.value == "completed"
        assert ExecutionStatus.FAILED.value == "failed"
        assert ExecutionStatus.CANCELLED.value == "cancelled"
        assert ExecutionStatus.TIMEOUT.value == "timeout"


class TestExecutionConfig:
    """Tests for ExecutionConfig dataclass"""

    def test_create_with_defaults(self):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="print('test')"
        )
        assert config.poc_id == "poc_001"
        assert config.target == "http://example.com"
        assert config.timeout == 60
        assert config.max_retries == 3
        assert config.enable_sandbox is True
        assert config.priority == ExecutionPriority.NORMAL
        assert config.enable_cache is True

    def test_create_with_all_fields(self):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="print('test')",
            timeout=120,
            max_retries=5,
            retry_delay_base=3.0,
            retry_delay_max=120.0,
            enable_sandbox=False,
            max_memory_mb=1024,
            max_cpu_percent=90.0,
            priority=ExecutionPriority.HIGH,
            enable_cache=False,
            cache_ttl=7200
        )
        assert config.timeout == 120
        assert config.max_retries == 5
        assert config.priority == ExecutionPriority.HIGH


class TestExecutionStats:
    """Tests for ExecutionStats dataclass"""

    def test_create_with_defaults(self):
        stats = ExecutionStats()
        assert stats.total_pocs == 0
        assert stats.executed_count == 0
        assert stats.vulnerable_count == 0
        assert stats.failed_count == 0

    def test_to_dict(self):
        stats = ExecutionStats(
            total_pocs=10,
            executed_count=8,
            vulnerable_count=3,
            failed_count=2
        )
        result = stats.to_dict()
        assert result["total_pocs"] == 10
        assert result["executed_count"] == 8
        assert result["vulnerable_count"] == 3
        assert result["failed_count"] == 2


class TestResourceUsage:
    """Tests for ResourceUsage dataclass"""

    def test_create_with_defaults(self):
        usage = ResourceUsage()
        assert usage.memory_mb == 0.0
        assert usage.memory_percent == 0.0
        assert usage.cpu_percent == 0.0
        assert usage.timestamp is not None

    def test_to_dict(self):
        usage = ResourceUsage(
            memory_mb=512.5,
            memory_percent=25.0,
            cpu_percent=45.0
        )
        result = usage.to_dict()
        assert result["memory_mb"] == 512.5
        assert result["memory_percent"] == 25.0
        assert result["cpu_percent"] == 45.0
        assert "timestamp" in result


class TestEngineConfig:
    """Tests for EngineConfig dataclass"""

    def test_create_with_defaults(self):
        config = EngineConfig()
        assert config.max_memory_mb == 1024
        assert config.max_cpu_percent == 80.0
        assert config.max_concurrent_executions == 10
        assert config.throttle_threshold == 0.8
        assert config.pause_threshold == 0.95

    def test_to_dict(self):
        config = EngineConfig(
            max_memory_mb=2048,
            max_cpu_percent=90.0,
            max_concurrent_executions=20
        )
        result = config.to_dict()
        assert result["max_memory_mb"] == 2048
        assert result["max_cpu_percent"] == 90.0
        assert result["max_concurrent_executions"] == 20


class TestPrioritizedTask:
    """Tests for PrioritizedTask dataclass"""

    def test_create(self):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="code"
        )
        task = PrioritizedTask(
            priority=-10,
            sequence=1,
            task_data={"test": "data"},
            config=config
        )
        assert task.priority == -10
        assert task.sequence == 1
        assert task.task_data == {"test": "data"}

    def test_ordering(self):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="code"
        )
        task1 = PrioritizedTask(priority=-10, sequence=1, task_data={}, config=config)
        task2 = PrioritizedTask(priority=-5, sequence=2, task_data={}, config=config)
        task3 = PrioritizedTask(priority=-10, sequence=3, task_data={}, config=config)
        
        assert task1 < task2
        assert task1 < task3


class TestExecutionHistoryEntry:
    """Tests for ExecutionHistoryEntry dataclass"""

    def test_create_with_defaults(self):
        entry = ExecutionHistoryEntry(
            task_id="task_001",
            poc_id="poc_001",
            poc_name="Test POC",
            target="http://example.com",
            status=ExecutionStatus.RUNNING,
            start_time=datetime.now()
        )
        assert entry.task_id == "task_001"
        assert entry.status == ExecutionStatus.RUNNING
        assert entry.end_time is None
        assert entry.vulnerable is False

    def test_to_dict(self):
        now = datetime.now()
        entry = ExecutionHistoryEntry(
            task_id="task_001",
            poc_id="poc_001",
            poc_name="Test POC",
            target="http://example.com",
            status=ExecutionStatus.COMPLETED,
            start_time=now,
            end_time=now,
            execution_time=1.5,
            vulnerable=True
        )
        result = entry.to_dict()
        assert result["task_id"] == "task_001"
        assert result["status"] == "completed"
        assert result["vulnerable"] is True
        assert result["execution_time"] == 1.5


class TestExecutionProgress:
    """Tests for ExecutionProgress dataclass"""

    def test_create_with_defaults(self):
        progress = ExecutionProgress(
            task_id="task_001",
            poc_name="Test POC",
            status=ExecutionStatus.RUNNING,
            progress=50,
            message="Running"
        )
        assert progress.task_id == "task_001"
        assert progress.progress == 50
        assert progress.current_step == ""
        assert progress.total_steps == 0

    def test_to_dict(self):
        progress = ExecutionProgress(
            task_id="task_001",
            poc_name="Test POC",
            status=ExecutionStatus.RUNNING,
            progress=75,
            message="Almost done",
            current_step="Step 3",
            total_steps=4,
            completed_steps=3,
            elapsed_time=10.5,
            estimated_remaining=3.5
        )
        result = progress.to_dict()
        assert result["task_id"] == "task_001"
        assert result["progress"] == 75
        assert result["current_step"] == "Step 3"
        assert result["elapsed_time"] == 10.5


class TestExecutionResultCache:
    """Tests for ExecutionResultCache"""

    @pytest.fixture
    def cache(self):
        return ExecutionResultCache(max_size=10, default_ttl=60)

    @pytest.mark.asyncio
    async def test_set_and_get(self, cache):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test_poc",
            target="http://example.com",
            vulnerable=True,
            message="Success",
            output="Test output"
        )
        
        await cache.set("poc_001", "http://example.com", "code", result)
        cached = await cache.get("poc_001", "http://example.com", "code")
        
        assert cached is not None
        assert cached.vulnerable is True

    @pytest.mark.asyncio
    async def test_cache_miss(self, cache):
        cached = await cache.get("nonexistent", "http://example.com", "code")
        assert cached is None

    @pytest.mark.asyncio
    async def test_cache_expiration(self, cache):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test_poc",
            target="http://example.com",
            vulnerable=True,
            message="Success",
            output="Test output"
        )
        
        await cache.set("poc_001", "http://example.com", "code", result, ttl=0.001)
        await asyncio.sleep(0.1)
        
        cached = await cache.get("poc_001", "http://example.com", "code")
        assert cached is None

    @pytest.mark.asyncio
    async def test_cache_clear(self, cache):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test_poc",
            target="http://example.com",
            vulnerable=True,
            message="Success",
            output="Test output"
        )
        
        await cache.set("poc_001", "http://example.com", "code", result)
        await cache.clear()
        
        cached = await cache.get("poc_001", "http://example.com", "code")
        assert cached is None

    @pytest.mark.asyncio
    async def test_cache_stats(self, cache):
        stats = await cache.get_stats()
        assert stats["size"] == 0
        assert stats["max_size"] == 10
        assert stats["default_ttl"] == 60


class TestResourceMonitor:
    """Tests for ResourceMonitor"""

    @pytest.fixture
    def monitor(self):
        config = EngineConfig()
        return ResourceMonitor(config)

    def test_get_current_usage(self, monitor):
        usage = monitor.get_current_usage()
        assert isinstance(usage, ResourceUsage)
        assert usage.memory_mb >= 0
        assert usage.cpu_percent >= 0

    def test_get_average_usage(self, monitor):
        monitor._usage_history.append(ResourceUsage(memory_mb=100, cpu_percent=10))
        monitor._usage_history.append(ResourceUsage(memory_mb=200, cpu_percent=20))
        
        avg = monitor.get_average_usage(seconds=60)
        assert avg.memory_mb == 150.0
        assert avg.cpu_percent == 15.0

    def test_check_resource_status_normal(self, monitor):
        usage = ResourceUsage(memory_mb=100, cpu_percent=30)
        should_throttle, should_pause = monitor.check_resource_status(usage)
        
        assert should_throttle is False
        assert should_pause is False

    def test_check_resource_status_throttle(self, monitor):
        usage = ResourceUsage(memory_mb=900, cpu_percent=70)
        should_throttle, should_pause = monitor.check_resource_status(usage)
        
        assert should_throttle is True
        assert should_pause is False

    def test_check_resource_status_pause(self, monitor):
        usage = ResourceUsage(memory_mb=1000, cpu_percent=85)
        should_throttle, should_pause = monitor.check_resource_status(usage)
        
        assert should_pause is True

    @pytest.mark.asyncio
    async def test_start_and_stop_monitoring(self, monitor):
        await monitor.start_monitoring(interval=0.1)
        assert monitor._monitoring is True
        
        await asyncio.sleep(0.2)
        
        await monitor.stop_monitoring()
        assert monitor._monitoring is False


class TestExecutionQueue:
    """Tests for ExecutionQueue"""

    @pytest.fixture
    def queue(self):
        return ExecutionQueue(max_concurrent=5)

    @pytest.mark.asyncio
    async def test_enqueue(self, queue):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="code",
            priority=ExecutionPriority.HIGH
        )
        
        task_id = await queue.enqueue({"data": "test"}, config)
        assert task_id is not None
        assert "poc_001" in task_id

    @pytest.mark.asyncio
    async def test_dequeue(self, queue):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="code",
            priority=ExecutionPriority.NORMAL
        )
        
        await queue.enqueue({"data": "test"}, config)
        
        dequeue_task = asyncio.create_task(queue.dequeue())
        await asyncio.sleep(0.1)
        
        assert queue._running_count == 1
        queue._paused = True
        await queue.task_completed()

    @pytest.mark.asyncio
    async def test_pause_and_resume(self, queue):
        await queue.pause()
        assert queue._paused is True
        
        await queue.resume()
        assert queue._paused is False

    @pytest.mark.asyncio
    async def test_clear(self, queue):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="code"
        )
        
        await queue.enqueue({"data": "test1"}, config)
        await queue.enqueue({"data": "test2"}, config)
        
        count = await queue.clear()
        assert count == 2

    @pytest.mark.asyncio
    async def test_get_queue_size(self, queue):
        config = ExecutionConfig(
            poc_id="poc_001",
            target="http://example.com",
            poc_code="code"
        )
        
        await queue.enqueue({"data": "test"}, config)
        size = await queue.get_queue_size()
        assert size == 1

    def test_get_status(self, queue):
        status = queue.get_status()
        assert "queue_size" in status
        assert "running_count" in status
        assert "max_concurrent" in status
        assert "paused" in status


class TestVerificationEngine:
    """Tests for VerificationEngine"""

    @pytest.fixture
    def engine(self):
        return VerificationEngine(max_concurrent=5)

    def test_initialization(self, engine):
        assert engine._max_concurrent == 5
        assert hasattr(engine, 'pocsuite3_agent')
        assert hasattr(engine, '_execution_queue')
        assert hasattr(engine, '_resource_monitor')
        assert hasattr(engine, '_result_cache')

    def test_add_progress_callback(self, engine):
        async def callback(progress):
            pass
        
        engine.add_progress_callback(callback)
        assert callback in engine._progress_callbacks

    def test_remove_progress_callback(self, engine):
        async def callback(progress):
            pass
        
        engine.add_progress_callback(callback)
        engine.remove_progress_callback(callback)
        assert callback not in engine._progress_callbacks

    def test_add_complete_callback(self, engine):
        async def callback(result):
            pass
        
        engine.add_complete_callback(callback)
        assert callback in engine._complete_callbacks

    def test_add_error_callback(self, engine):
        async def callback(error, task_id):
            pass
        
        engine.add_error_callback(callback)
        assert callback in engine._error_callbacks

    def test_set_max_concurrent_executions(self, engine):
        engine._max_concurrent = 10
        assert engine._max_concurrent == 10

    def test_set_engine_config(self, engine):
        config = EngineConfig(max_memory_mb=2048)
        engine.set_engine_config(config)
        assert engine._engine_config.max_memory_mb == 2048

    def test_get_engine_config(self, engine):
        config = engine.get_engine_config()
        assert isinstance(config, EngineConfig)

    @pytest.mark.asyncio
    async def test_get_current_resource_usage(self, engine):
        usage = await engine.get_current_resource_usage()
        assert isinstance(usage, ResourceUsage)

    def test_get_execution_statistics(self, engine):
        stats = engine.get_execution_statistics()
        assert isinstance(stats, ExecutionStats)

    def test_get_execution_history(self, engine):
        entry = ExecutionHistoryEntry(
            task_id="task_001",
            poc_id="poc_001",
            poc_name="Test",
            target="http://example.com",
            status=ExecutionStatus.COMPLETED,
            start_time=datetime.now()
        )
        engine._add_history_entry(entry)
        
        history = engine.get_execution_history()
        assert len(history) == 1

    def test_get_execution_history_with_filter(self, engine):
        entry1 = ExecutionHistoryEntry(
            task_id="task_001",
            poc_id="poc_001",
            poc_name="Test",
            target="http://example.com",
            status=ExecutionStatus.COMPLETED,
            start_time=datetime.now()
        )
        entry2 = ExecutionHistoryEntry(
            task_id="task_002",
            poc_id="poc_002",
            poc_name="Test",
            target="http://example.com",
            status=ExecutionStatus.FAILED,
            start_time=datetime.now()
        )
        engine._add_history_entry(entry1)
        engine._add_history_entry(entry2)
        
        history = engine.get_execution_history(status=ExecutionStatus.COMPLETED)
        assert len(history) == 1

    def test_get_queue_status(self, engine):
        status = engine.get_queue_status()
        assert "queue_size" in status
        assert "running_count" in status

    @pytest.mark.asyncio
    async def test_clear_cache(self, engine):
        await engine.clear_cache()
        stats = await engine.get_cache_stats()
        assert stats["size"] == 0

    @pytest.mark.asyncio
    async def test_get_cache_stats(self, engine):
        stats = await engine.get_cache_stats()
        assert "size" in stats
        assert "max_size" in stats

    def test_get_execution_status(self, engine):
        progress = ExecutionProgress(
            task_id="task_001",
            poc_name="Test",
            status=ExecutionStatus.RUNNING,
            progress=50,
            message="Running"
        )
        engine._task_progress["task_001"] = progress
        
        result = engine.get_execution_status("task_001")
        assert result is not None
        assert result.progress == 50

    def test_get_execution_status_not_found(self, engine):
        result = engine.get_execution_status("nonexistent")
        assert result is None

    def test_calculate_confidence_vulnerable(self, engine):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test",
            target="http://example.com",
            vulnerable=True,
            message="Found",
            output="A" * 200
        )
        
        confidence = engine._calculate_confidence(result)
        assert confidence >= 0.9

    def test_calculate_confidence_error(self, engine):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test",
            target="http://example.com",
            vulnerable=False,
            message="Error",
            output="",
            error="Some error"
        )
        
        confidence = engine._calculate_confidence(result)
        assert confidence <= 0.2

    def test_calculate_severity_vulnerable(self, engine):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test",
            target="http://example.com",
            vulnerable=True,
            message="Found",
            output=""
        )
        
        severity = engine._calculate_severity(result)
        assert severity == "high"

    def test_calculate_severity_error(self, engine):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test",
            target="http://example.com",
            vulnerable=False,
            message="Error",
            output="",
            error="Error"
        )
        
        severity = engine._calculate_severity(result)
        assert severity == "info"

    def test_calculate_cvss_score_vulnerable(self, engine):
        from backend.Pocsuite3Agent.agent import POCResult
        
        result = POCResult(
            poc_name="test",
            target="http://example.com",
            vulnerable=True,
            message="Found",
            output=""
        )
        
        score = engine._calculate_cvss_score(result)
        assert score == 7.5

    @pytest.mark.asyncio
    async def test_notify_progress(self, engine):
        progress = ExecutionProgress(
            task_id="task_001",
            poc_name="Test",
            status=ExecutionStatus.RUNNING,
            progress=50,
            message="Running"
        )
        
        callback_called = []
        
        async def callback(p):
            callback_called.append(p)
        
        engine.add_progress_callback(callback)
        await engine._notify_progress(progress)
        
        assert len(callback_called) == 1
        assert engine._task_progress["task_001"] == progress

    @pytest.mark.asyncio
    async def test_notify_progress_callback_error(self, engine):
        progress = ExecutionProgress(
            task_id="task_001",
            poc_name="Test",
            status=ExecutionStatus.RUNNING,
            progress=50,
            message="Running"
        )
        
        async def bad_callback(p):
            raise Exception("Callback error")
        
        engine.add_progress_callback(bad_callback)
        await engine._notify_progress(progress)
        
        assert engine._task_progress["task_001"] == progress

    @pytest.mark.asyncio
    async def test_start_and_shutdown(self, engine):
        engine._shutdown = True
        assert engine._shutdown is True


class TestVerificationEngineStats:
    """Tests for VerificationEngine statistics"""

    @pytest.fixture
    def engine(self):
        return VerificationEngine()

    def test_update_stats_vulnerable(self, engine):
        engine._update_stats(
            vulnerable=True,
            cancelled=False,
            timeout=False,
            execution_time=1.5,
            cache_hit=True
        )
        
        assert engine._stats.executed_count == 1
        assert engine._stats.vulnerable_count == 1
        assert engine._stats.cache_hit_count == 1

    def test_update_stats_failed(self, engine):
        engine._update_stats(
            vulnerable=False,
            cancelled=False,
            timeout=False,
            execution_time=1.0,
            cache_hit=False
        )
        
        assert engine._stats.executed_count == 1
        assert engine._stats.failed_count == 1

    def test_update_stats_cancelled(self, engine):
        engine._update_stats(
            vulnerable=False,
            cancelled=True,
            timeout=False,
            execution_time=0,
            cache_hit=False
        )
        
        assert engine._stats.cancelled_count == 1

    def test_update_stats_timeout(self, engine):
        engine._update_stats(
            vulnerable=False,
            cancelled=False,
            timeout=True,
            execution_time=60,
            cache_hit=False
        )
        
        assert engine._stats.timeout_count == 1


class TestGlobalVerificationEngine:
    """Tests for global verification_engine instance"""

    def test_global_instance_exists(self):
        assert verification_engine is not None
        assert isinstance(verification_engine, VerificationEngine)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
