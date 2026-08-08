"""Interactive scan pause/resume WebSocket protocol definitions."""

from typing import Any, Dict, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


SCAN_PROTOCOL_VERSION = "1.0"
PAUSE_FOR_CHAT_MESSAGE = "pause_for_chat"
RESUME_SCAN_MESSAGE = "resume_scan"
SCAN_PROTOCOL_REQUESTS = frozenset(
    {PAUSE_FOR_CHAT_MESSAGE, RESUME_SCAN_MESSAGE}
)


class ScanProtocolValidationError(ValueError):
    """Raised when a pause/resume request does not follow the protocol."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class _BaseScanProtocolPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    protocol_version: Literal["1.0"] = SCAN_PROTOCOL_VERSION
    request_id: str = Field(default_factory=lambda: uuid4().hex)
    client_timestamp: Optional[str] = None

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 128:
            raise ValueError("request_id 必须是 1-128 个字符")
        return value


class PauseForChatPayload(_BaseScanProtocolPayload):
    """Payload for pausing at the interactive decision boundary."""

    interaction_id: Optional[str] = None


class ResumeScanPayload(_BaseScanProtocolPayload):
    """Payload for resuming a previously paused interactive scan."""

    # Optional for backward compatibility; the server fills it from state when
    # an older client does not send pause_id.
    pause_id: Optional[str] = None


def normalize_scan_protocol_payload(
    message_type: str, payload: Any
) -> Dict[str, Any]:
    """Validate and normalize a pause/resume payload.

    Unknown fields are retained so clients can roll out additional metadata
    without breaking the current server.
    """
    if not isinstance(payload, dict):
        raise ScanProtocolValidationError(
            "协议 payload 必须是对象",
            {"message_type": message_type, "expected": "object"},
        )

    model_type = {
        PAUSE_FOR_CHAT_MESSAGE: PauseForChatPayload,
        RESUME_SCAN_MESSAGE: ResumeScanPayload,
    }.get(message_type)
    if model_type is None:
        return payload

    try:
        normalized = model_type.model_validate(payload).model_dump(exclude_none=True)
    except ValidationError as exc:
        raise ScanProtocolValidationError(
            "pause/resume 协议参数无效",
            {
                "message_type": message_type,
                "fields": exc.errors(include_url=False),
            },
        ) from exc

    return normalized


def protocol_response(
    session_id: str,
    request_id: str,
    **payload: Any,
) -> Dict[str, Any]:
    """Build a common response payload for protocol messages."""
    return {
        "protocol_version": SCAN_PROTOCOL_VERSION,
        "request_id": request_id,
        "session_id": session_id,
        **payload,
    }
