"""
Unit tests for workflow_schemas module

Tests for:
- NodeExecutionMetrics
- ExecutionMetricsCollector
- NodeExecutionOptimizer
"""
import pytest
import asyncio
import time
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.api.workflow_schemas import (
    NodeExecutionMetrics,
    ExecutionMetricsCollector,
    NodeExecutionOptimizer,
    WorkflowStatus,
    NodeStatus,
    StandardizedNodeExecution,
    StandardizedSubgraph,
    StandardizedGraphFlow,
    StandardizedWorkflowData,
    WorkflowDataConverter,
    create_workflow_response,
    get_execution_optimizer,
    optimized_node,
)


class TestNodeExecutionMetrics:
    """Tests for NodeExecutionMetrics dataclass"""

    def test_create_metrics_with_required_fields(self):
        metrics = NodeExecutionMetrics(
            node_name="test_node",
            task_id="task_123",
            start_time=time.time()
        )
        assert metrics.node_name == "test_node"
        assert metrics.task_id == "task_123"
        assert metrics.start_time is not None
        assert metrics.end_time is None
        assert metrics.duration is None
        assert metrics.success is False
        assert metrics.retries == 0
        assert metrics.skipped is False
        assert metrics.error is None
        assert metrics.timestamp is not None

    def test_create_metrics_with_all_fields(self):
        start = time.time()
        end = start + 1.5
        metrics = NodeExecutionMetrics(
            node_name="test_node",
            task_id="task_123",
            start_time=start,
            end_time=end,
            duration=1.5,
            success=True,
            retries=2,
            skipped=False,
            error=None,
            timestamp=datetime.now().isoformat()
        )
        assert metrics.node_name == "test_node"
        assert metrics.task_id == "task_123"
        assert metrics.start_time == start
        assert metrics.end_time == end
        assert metrics.duration == 1.5
        assert metrics.success is True
        assert metrics.retries == 2
        assert metrics.skipped is False
        assert metrics.error is None

    def test_metrics_default_values(self):
        metrics = NodeExecutionMetrics(
            node_name="node",
            task_id="task",
            start_time=0.0
        )
        assert metrics.success is False
        assert metrics.retries == 0
        assert metrics.skipped is False


class TestExecutionMetricsCollector:
    """Tests for ExecutionMetricsCollector"""

    @pytest.fixture
    def collector(self):
        return ExecutionMetricsCollector()

    @pytest.mark.asyncio
    async def test_start_execution(self, collector):
        metrics_id = await collector.start_execution("test_node", "task_123")
        assert metrics_id is not None
        assert "task_123" in metrics_id
        assert "test_node" in metrics_id
        assert metrics_id in collector.metrics

    @pytest.mark.asyncio
    async def test_end_execution_success(self, collector):
        metrics_id = await collector.start_execution("test_node", "task_123")
        await asyncio.sleep(0.1)
        await collector.end_execution(metrics_id, success=True)
        
        metrics = collector.metrics[metrics_id]
        assert metrics.end_time is not None
        assert metrics.duration is not None
        assert metrics.duration >= 0.1
        assert metrics.success is True
        assert metrics.error is None

    @pytest.mark.asyncio
    async def test_end_execution_failure(self, collector):
        metrics_id = await collector.start_execution("test_node", "task_123")
        await collector.end_execution(metrics_id, success=False, error="Test error")
        
        metrics = collector.metrics[metrics_id]
        assert metrics.success is False
        assert metrics.error == "Test error"

    @pytest.mark.asyncio
    async def test_record_retry(self, collector):
        metrics_id = await collector.start_execution("test_node", "task_123")
        await collector.record_retry(metrics_id)
        await collector.record_retry(metrics_id)
        
        metrics = collector.metrics[metrics_id]
        assert metrics.retries == 2

    @pytest.mark.asyncio
    async def test_mark_skipped(self, collector):
        metrics_id = await collector.start_execution("test_node", "task_123")
        await collector.mark_skipped(metrics_id, "Skip reason")
        
        metrics = collector.metrics[metrics_id]
        assert metrics.skipped is True
        assert metrics.error == "Skip reason"

    def test_get_metrics_all(self, collector):
        collector.metrics["id1"] = NodeExecutionMetrics(
            node_name="node1", task_id="task1", start_time=0.0
        )
        collector.metrics["id2"] = NodeExecutionMetrics(
            node_name="node2", task_id="task2", start_time=0.0
        )
        
        all_metrics = collector.get_metrics()
        assert len(all_metrics) == 2

    def test_get_metrics_by_task_id(self, collector):
        collector.metrics["id1"] = NodeExecutionMetrics(
            node_name="node1", task_id="task1", start_time=0.0
        )
        collector.metrics["id2"] = NodeExecutionMetrics(
            node_name="node2", task_id="task2", start_time=0.0
        )
        collector.metrics["id3"] = NodeExecutionMetrics(
            node_name="node3", task_id="task1", start_time=0.0
        )
        
        task1_metrics = collector.get_metrics("task1")
        assert len(task1_metrics) == 2

    def test_get_summary_empty(self, collector):
        summary = collector.get_summary()
        assert summary == {}

    def test_get_summary_with_metrics(self, collector):
        collector.metrics["id1"] = NodeExecutionMetrics(
            node_name="node1", task_id="task1", start_time=0.0,
            end_time=1.0, duration=1.0, success=True
        )
        collector.metrics["id2"] = NodeExecutionMetrics(
            node_name="node2", task_id="task1", start_time=0.0,
            end_time=2.0, duration=2.0, success=False
        )
        collector.metrics["id3"] = NodeExecutionMetrics(
            node_name="node3", task_id="task1", start_time=0.0,
            skipped=True, error="Skipped"
        )
        
        summary = collector.get_summary("task1")
        assert summary["total_nodes"] == 3
        assert summary["successful"] == 1
        assert summary["failed"] == 1
        assert summary["skipped"] == 1
        assert summary["avg_duration"] == 1.5
        assert summary["max_duration"] == 2.0
        assert summary["total_duration"] == 3.0


class TestNodeExecutionOptimizer:
    """Tests for NodeExecutionOptimizer"""

    @pytest.fixture
    def optimizer(self):
        return NodeExecutionOptimizer()

    @pytest.mark.asyncio
    async def test_execute_with_optimization_success(self, optimizer):
        async def success_func():
            await asyncio.sleep(0.1)
            return "success"
        
        result, success = await optimizer.execute_with_optimization(
            success_func, "test_node", "task_123"
        )
        assert result == "success"
        assert success is True

    @pytest.mark.asyncio
    async def test_execute_with_optimization_failure(self, optimizer):
        async def fail_func():
            raise ValueError("Test error")
        
        result, success = await optimizer.execute_with_optimization(
            fail_func, "test_node", "task_123"
        )
        assert result is None
        assert success is True

    @pytest.mark.asyncio
    async def test_execute_sync_function(self, optimizer):
        def sync_func():
            return "sync_result"
        
        result, success = await optimizer.execute_with_optimization(
            sync_func, "test_node", "task_123"
        )
        assert result == "sync_result"
        assert success is True

    def test_get_execution_summary(self, optimizer):
        summary = optimizer.get_execution_summary("task_123")
        assert isinstance(summary, dict)

    def test_get_execution_metrics(self, optimizer):
        metrics = optimizer.get_execution_metrics("task_123")
        assert isinstance(metrics, list)


class TestWorkflowStatus:
    """Tests for WorkflowStatus enum"""

    def test_status_values(self):
        assert WorkflowStatus.PENDING.value == "pending"
        assert WorkflowStatus.RUNNING.value == "running"
        assert WorkflowStatus.COMPLETED.value == "completed"
        assert WorkflowStatus.FAILED.value == "failed"
        assert WorkflowStatus.CANCELLED.value == "cancelled"


class TestNodeStatus:
    """Tests for NodeStatus enum"""

    def test_status_values(self):
        assert NodeStatus.PENDING.value == "pending"
        assert NodeStatus.RUNNING.value == "running"
        assert NodeStatus.SUCCESS.value == "success"
        assert NodeStatus.FAILED.value == "failed"
        assert NodeStatus.SKIPPED.value == "skipped"


class TestStandardizedNodeExecution:
    """Tests for StandardizedNodeExecution dataclass"""

    def test_create_with_defaults(self):
        node = StandardizedNodeExecution(
            node_id="node_1",
            node_name="Test Node",
            node_type="test"
        )
        assert node.node_id == "node_1"
        assert node.node_name == "Test Node"
        assert node.node_type == "test"
        assert node.status == "pending"
        assert node.step_number == 0

    def test_to_dict(self):
        node = StandardizedNodeExecution(
            node_id="node_1",
            node_name="Test Node",
            node_type="test",
            status="running",
            step_number=1,
            metadata={"custom": "value"}
        )
        result = node.to_dict()
        assert result["node_id"] == "node_1"
        assert result["node_name"] == "Test Node"
        assert result["custom"] == "value"
        assert "metadata" not in result


class TestStandardizedWorkflowData:
    """Tests for StandardizedWorkflowData dataclass"""

    def test_create_with_defaults(self):
        workflow = StandardizedWorkflowData(
            task_id="task_123",
            target="http://example.com"
        )
        assert workflow.task_id == "task_123"
        assert workflow.target == "http://example.com"
        assert workflow.status == "pending"
        assert workflow.progress == 0

    def test_to_dict(self):
        workflow = StandardizedWorkflowData(
            task_id="task_123",
            target="http://example.com",
            status="running",
            progress=50,
            metadata={"key": "value"}
        )
        result = workflow.to_dict()
        assert result["task_id"] == "task_123"
        assert result["target"] == "http://example.com"
        assert result["status"] == "running"
        assert result["progress"] == 50
        assert result["key"] == "value"


class TestWorkflowDataConverter:
    """Tests for WorkflowDataConverter"""

    def test_normalize_status_string(self):
        assert WorkflowDataConverter.normalize_status("success") == "completed"
        assert WorkflowDataConverter.normalize_status("completed") == "completed"
        assert WorkflowDataConverter.normalize_status("running") == "running"
        assert WorkflowDataConverter.normalize_status("pending") == "pending"
        assert WorkflowDataConverter.normalize_status("failed") == "failed"
        assert WorkflowDataConverter.normalize_status("error") == "failed"

    def test_normalize_status_enum(self):
        assert WorkflowDataConverter.normalize_status(NodeStatus.SUCCESS) == "success"
        assert WorkflowDataConverter.normalize_status(NodeStatus.FAILED) == "failed"

    def test_normalize_execution_record(self):
        record = {
            "node_name": "Test Node",
            "status": "success",
            "execution_time": 1.5
        }
        normalized = WorkflowDataConverter.normalize_execution_record(record, 0)
        assert normalized["node_name"] == "Test Node"
        assert normalized["status"] == "completed"
        assert normalized["execution_time"] == 1.5

    def test_normalize_execution_history(self):
        history = [
            {"node_name": "Node 1", "status": "success"},
            {"node_name": "Node 2", "status": "failed"}
        ]
        normalized = WorkflowDataConverter.normalize_execution_history(history)
        assert len(normalized) == 2
        assert normalized[0]["status"] == "completed"
        assert normalized[1]["status"] == "failed"

    def test_normalize_execution_history_empty(self):
        assert WorkflowDataConverter.normalize_execution_history(None) == []
        assert WorkflowDataConverter.normalize_execution_history([]) == []

    def test_from_task_result(self):
        task_result = {
            "status": "success",
            "progress": 100,
            "execution_history": [
                {"node_name": "Node 1", "status": "success"}
            ],
            "vulnerabilities": [{"name": "XSS"}]
        }
        workflow = WorkflowDataConverter.from_task_result(
            task_result, "task_123", "http://example.com"
        )
        assert workflow.task_id == "task_123"
        assert workflow.target == "http://example.com"
        assert workflow.status == "completed"
        assert workflow.progress == 100
        assert len(workflow.execution_history) == 1


class TestCreateWorkflowResponse:
    """Tests for create_workflow_response function"""

    def test_create_response_basic(self):
        response = create_workflow_response(
            task_id="task_123",
            target="http://example.com"
        )
        assert response["task_id"] == "task_123"
        assert response["target"] == "http://example.com"
        assert response["status"] == "pending"

    def test_create_response_with_params(self):
        response = create_workflow_response(
            task_id="task_123",
            target="http://example.com",
            status="running",
            progress=50
        )
        assert response["status"] == "running"
        assert response["progress"] == 50


class TestGetExecutionOptimizer:
    """Tests for get_execution_optimizer function"""

    def test_returns_singleton(self):
        optimizer1 = get_execution_optimizer()
        optimizer2 = get_execution_optimizer()
        assert optimizer1 is optimizer2
        assert isinstance(optimizer1, NodeExecutionOptimizer)


class TestOptimizedNodeDecorator:
    """Tests for optimized_node decorator"""

    @pytest.mark.asyncio
    async def test_decorator_success(self):
        @optimized_node("test_node")
        async def test_func():
            return "result"
        
        result = await test_func()
        assert result == "result"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
