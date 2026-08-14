"""Unified asynchronous client for the OpenAI-compatible MaaS endpoint."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
)

from TOSKill.config import settings

logger = logging.getLogger(__name__)


class MaaSRequestError(RuntimeError):
    """Stable provider error exposed to WebSocket and workflow callers."""

    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class MaaSClient:
    """One request surface shared by chat and script generation."""

    def __init__(self, client: Optional[AsyncOpenAI] = None):
        self._client = client

    def _get_client(self) -> AsyncOpenAI:
        if self._client is None:
            logger.info("正在创建统一 MaaS 异步客户端实例...")
            # Retry and timeout are selected per operation through with_options.
            self._client = AsyncOpenAI(
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL,
                timeout=settings.CHAT_AI_TIMEOUT,
                max_retries=0,
            )
        return self._client

    async def complete(
        self,
        messages: List[Dict[str, str]],
        *,
        max_tokens: int,
        timeout: float,
        max_retries: int,
        temperature: Optional[float] = None,
    ) -> str:
        """Return non-empty assistant text or raise a normalized error."""
        try:
            client = self._get_client().with_options(
                timeout=timeout,
                max_retries=max_retries,
            )
            response = await client.chat.completions.create(
                model=settings.MODEL_ID,
                messages=messages,
                temperature=(
                    settings.LLM_TEMPERATURE
                    if temperature is None
                    else temperature
                ),
                max_tokens=max_tokens,
            )
            if not response.choices:
                raise MaaSRequestError("MODEL_EMPTY_RESPONSE", "AI模型未返回候选回复")
            content = response.choices[0].message.content or ""
            if not isinstance(content, str):
                content = str(content)
            if not content.strip():
                raise MaaSRequestError("MODEL_EMPTY_RESPONSE", "AI模型返回空回复")
            return content
        except MaaSRequestError:
            raise
        except APITimeoutError as exc:
            raise MaaSRequestError(
                "MODEL_TIMEOUT",
                f"AI模型请求超时（{timeout:g}秒），请检查网络或稍后重试",
                retryable=True,
            ) from exc
        except AuthenticationError as exc:
            raise MaaSRequestError(
                "MODEL_AUTH_ERROR", "AI模型鉴权失败，请检查 API Key"
            ) from exc
        except NotFoundError as exc:
            raise MaaSRequestError(
                "MODEL_NOT_FOUND", "AI模型或接口地址不存在，请检查模型配置"
            ) from exc
        except RateLimitError as exc:
            raise MaaSRequestError(
                "MODEL_RATE_LIMIT", "AI模型请求频率受限，请稍后重试", retryable=True
            ) from exc
        except APIConnectionError as exc:
            raise MaaSRequestError(
                "MODEL_CONNECTION_ERROR",
                "无法连接 AI 模型服务，请检查代理和网络配置",
                retryable=True,
            ) from exc
        except APIStatusError as exc:
            status = getattr(exc, "status_code", None)
            raise MaaSRequestError(
                "MODEL_PROVIDER_ERROR",
                f"AI模型服务返回异常状态{f' {status}' if status else ''}",
                retryable=bool(status and status >= 500),
            ) from exc

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None


maas_client = MaaSClient()


def get_maas_client() -> MaaSClient:
    return maas_client


async def close_maas_client() -> None:
    await maas_client.aclose()
