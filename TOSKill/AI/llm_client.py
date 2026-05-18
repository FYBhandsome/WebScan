"""
统一LLM客户端 - 带重试、熔断、超时控制
所有外部API调用统一通过此模块
"""
import time
import logging
import statistics
from typing import List, Optional, TypeVar
from collections import deque
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage

from TOSKill.config import settings

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitBreakerOpenError(Exception):
    """熔断器打开异常"""
    pass


class LLMClient:
    """带熔断和重试的统一LLM客户端"""
    
    MAX_FAILURES = 5
    RECOVERY_INTERVAL = 30
    
    def __init__(self):
        self._failure_count = 0
        self._open = False
        self._last_failure_time = 0
        self._total_calls = 0
        self._success_calls = 0
        self._latency_history = deque(maxlen=100)
        self._initialized = False
        self._llm_instance: Optional[ChatOpenAI] = None
    
    def _create_llm(self) -> ChatOpenAI:
        """创建LLM实例，统一参数"""
        logger.info("正在创建LLM客户端实例...")
        return ChatOpenAI(
            model=settings.MODEL_ID,
            temperature=settings.LLM_TEMPERATURE,
            api_key=settings.OPENAI_API_KEY,
            base_url=settings.OPENAI_BASE_URL,
            timeout=120.0,
            max_retries=2
        )
    
    def _check_circuit(self):
        """检查熔断器状态"""
        if self._open:
            now = time.time()
            if now - self._last_failure_time > self.RECOVERY_INTERVAL:
                logger.info("熔断器半开状态，允许一次尝试")
                self._open = False
            else:
                raise CircuitBreakerOpenError(
                    f"LLM服务熔断中，仍需等待 {self.RECOVERY_INTERVAL - (now - self._last_failure_time):.1f} 秒"
                )
    
    def _record_success(self, latency: float):
        """记录成功"""
        self._failure_count = 0
        self._success_calls += 1
        self._latency_history.append(latency)
        self._open = False
    
    def _record_failure(self):
        """记录失败"""
        self._failure_count += 1
        if self._failure_count >= self.MAX_FAILURES:
            logger.critical(f"连续{self._failure_count}次失败，打开熔断器")
            self._open = True
            self._last_failure_time = time.time()
    
    def is_available(self) -> bool:
        """检查LLM是否可用"""
        if self._open:
            now = time.time()
            if now - self._last_failure_time > self.RECOVERY_INTERVAL:
                return True
            return False
        return True
    
    def get_llm(self) -> ChatOpenAI:
        """获取LLM实例，检查熔断"""
        self._check_circuit()
        if self._llm_instance is None:
            self._llm_instance = self._create_llm()
        self._total_calls += 1
        return self._llm_instance
    
    def invoke(self, messages: List[BaseMessage], timeout: Optional[float] = None) -> BaseMessage:
        """同步调用，带重试"""
        start_time = time.time()
        last_exception = None
        
        for attempt in range(3):
            try:
                self._check_circuit()
                llm = self.get_llm()
                if timeout:
                    result = llm.invoke(messages, timeout=timeout)
                else:
                    result = llm.invoke(messages)
                latency = time.time() - start_time
                self._record_success(latency)
                logger.debug(f"LLM调用成功: 尝试{attempt+1}次，延迟{latency:.2f}s")
                return result
            except Exception as e:
                last_exception = e
                self._record_failure()
                delay = 1.0 * (2 ** attempt)
                logger.warning(f"LLM调用失败: 尝试{attempt+1}/3，延迟{delay}s重试，错误: {e}")
                time.sleep(delay)
        
        logger.error(f"LLM调用全部失败，最后一次错误: {last_exception}")
        raise last_exception
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        avg_latency = statistics.mean(self._latency_history) if self._latency_history else 0
        success_rate = self._success_calls / self._total_calls if self._total_calls > 0 else 0
        return {
            "total_calls": self._total_calls,
            "success_calls": self._success_calls,
            "success_rate": f"{success_rate*100:.1f}%",
            "avg_latency_ms": f"{avg_latency*1000:.1f}",
            "circuit_open": self._open,
            "failure_count": self._failure_count,
        }


llm_client = LLMClient()


def get_llm() -> ChatOpenAI:
    """统一入口，供各模块调用"""
    return llm_client.get_llm()


def is_llm_available() -> bool:
    """检查LLM服务是否可用"""
    return llm_client.is_available()


def get_llm_stats() -> dict:
    """获取LLM统计信息"""
    return llm_client.get_stats()
