"""
TOSKill LLM统一客户端测试
验证熔断器、重试机制、统计功能
"""
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock


class TestCircuitBreaker:
    """熔断器机制测试"""

    def test_llm_client_import(self):
        """客户端应可正常导入"""
        from TOSKill.AI.llm_client import get_llm, llm_client
        assert llm_client is not None

    def test_initial_not_open(self):
        """初始状态熔断器应为关闭"""
        from TOSKill.AI.llm_client import llm_client
        llm_client._open = False
        llm_client._failure_count = 0
        assert not llm_client._open

    def test_record_failure_increments(self):
        """记录失败应递增计数"""
        from TOSKill.AI.llm_client import llm_client
        llm_client._failure_count = 0
        llm_client._open = False
        for _ in range(3):
            llm_client._record_failure()
        assert llm_client._failure_count == 3
        assert not llm_client._open  # 3次不应打开

    def test_circuit_opens_after_max_failures(self):
        """连续最大失败次数后熔断器应打开"""
        from TOSKill.AI.llm_client import llm_client
        llm_client._failure_count = 0
        llm_client._open = False
        for _ in range(llm_client.MAX_FAILURES):
            llm_client._record_failure()
        assert llm_client._open

    def test_record_success_resets(self):
        """成功应重置计数"""
        from TOSKill.AI.llm_client import llm_client
        llm_client._failure_count = 3
        llm_client._open = False
        llm_client._record_success(0.5)
        assert llm_client._failure_count == 0
        assert not llm_client._open

    def test_check_circuit_raises_when_open(self):
        """熔断器打开时应抛出异常"""
        from TOSKill.AI.llm_client import llm_client, CircuitBreakerOpenError
        llm_client._open = True
        llm_client._last_failure_time = time.time()
        with pytest.raises(CircuitBreakerOpenError):
            llm_client._check_circuit()

    def test_check_circuit_half_open_after_recovery(self):
        """恢复时间后熔断器应半开"""
        from TOSKill.AI.llm_client import llm_client
        llm_client._open = True
        llm_client._last_failure_time = time.time() - llm_client.RECOVERY_INTERVAL - 1
        llm_client._check_circuit()
        assert not llm_client._open

    def test_is_available(self):
        """is_available检查"""
        from TOSKill.AI.llm_client import llm_client
        llm_client._open = False
        assert llm_client.is_available()
        llm_client._open = True
        llm_client._last_failure_time = time.time()
        assert not llm_client.is_available()


class TestRetryMechanism:
    """重试机制测试"""

    def test_invoke_retries_on_failure(self):
        """invoke应在失败时重试"""
        from TOSKill.AI.llm_client import llm_client
        from langchain_core.messages import HumanMessage

        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = [
            Exception("Attempt 1"),
            Exception("Attempt 2"),
            MagicMock(content="success after retry")
        ]
        
        original_instance = llm_client._llm_instance
        llm_client._llm_instance = mock_llm
        llm_client._failure_count = 0
        llm_client._open = False

        try:
            result = llm_client.invoke([HumanMessage(content="test")])
            assert result.content == "success after retry"
            assert mock_llm.invoke.call_count == 3
        finally:
            llm_client._llm_instance = original_instance

    def test_invoke_fails_after_all_retries(self):
        """所有重试失败后应抛出异常"""
        from TOSKill.AI.llm_client import llm_client
        from langchain_core.messages import HumanMessage

        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = Exception("Always fails")
        
        original_instance = llm_client._llm_instance
        llm_client._llm_instance = mock_llm
        llm_client._failure_count = 0
        llm_client._open = False

        try:
            with pytest.raises(Exception):
                llm_client.invoke([HumanMessage(content="test")])
            assert mock_llm.invoke.call_count == 3
        finally:
            llm_client._llm_instance = original_instance


class TestUnifiedInterface:
    """统一接口测试"""

    def test_get_llm_returns_instance(self):
        """get_llm()应返回ChatOpenAI实例"""
        from TOSKill.AI.llm_client import get_llm, llm_client
        llm_client._open = False
        llm_client._failure_count = 0

        with patch.object(llm_client.__class__, '_create_llm') as mock_create:
            mock_llm = MagicMock()
            mock_create.return_value = mock_llm
            llm_client._llm_instance = None
            result = get_llm()
            assert result is mock_llm

    def test_get_stats_returns_dict(self):
        """get_stats应返回字典"""
        from TOSKill.AI.llm_client import get_llm_stats
        stats = get_llm_stats()
        assert "total_calls" in stats
        assert "success_rate" in stats
        assert "circuit_open" in stats

    def test_is_available_function(self):
        """is_llm_available函数应正常工作"""
        from TOSKill.AI.llm_client import is_llm_available, llm_client
        llm_client._open = False
        assert is_llm_available()


class TestLLMClientEdgeCases:
    """LLM客户端边缘情况测试"""

    def test_create_llm_params(self):
        """创建LLM时参数正确"""
        from TOSKill.AI.llm_client import llm_client
        old_instance = llm_client._llm_instance
        llm_client._llm_instance = None
        try:
            instance = llm_client._create_llm()
            assert instance is not None
        finally:
            llm_client._llm_instance = old_instance

    def test_record_success_updates_latency(self):
        """成功应更新延迟历史"""
        from TOSKill.AI.llm_client import llm_client
        llm_client._open = False
        llm_client._failure_count = 0
        initial_len = len(llm_client._latency_history)
        llm_client._record_success(1.5)
        assert len(llm_client._latency_history) == initial_len + 1


@pytest.mark.asyncio
async def test_unified_maas_client_uses_per_operation_options():
    from TOSKill.AI.maas_client import MaaSClient

    raw_client = MagicMock()
    configured_client = MagicMock()
    raw_client.with_options.return_value = configured_client
    configured_client.chat.completions.create = AsyncMock(return_value=MagicMock(
        choices=[MagicMock(message=MagicMock(content="generated content"))]
    ))
    client = MaaSClient(raw_client)

    content = await client.complete(
        [{"role": "user", "content": "hello"}],
        max_tokens=321,
        timeout=12,
        max_retries=1,
        temperature=0.2,
    )

    assert content == "generated content"
    raw_client.with_options.assert_called_once_with(timeout=12, max_retries=1)
    request = configured_client.chat.completions.create.await_args.kwargs
    assert request["max_tokens"] == 321
    assert request["model"]


@pytest.mark.asyncio
async def test_unified_maas_client_normalizes_timeout():
    import httpx
    from openai import APITimeoutError

    from TOSKill.AI.maas_client import MaaSClient, MaaSRequestError

    raw_client = MagicMock()
    configured_client = MagicMock()
    raw_client.with_options.return_value = configured_client
    configured_client.chat.completions.create = AsyncMock(
        side_effect=APITimeoutError(request=httpx.Request("POST", "https://maas.test/chat/completions"))
    )
    client = MaaSClient(raw_client)

    with pytest.raises(MaaSRequestError) as exc_info:
        await client.complete(
            [{"role": "user", "content": "hello"}],
            max_tokens=321,
            timeout=60,
            max_retries=1,
        )

    assert exc_info.value.code == "MODEL_TIMEOUT"
    assert exc_info.value.retryable is True
    assert "60秒" in str(exc_info.value)
