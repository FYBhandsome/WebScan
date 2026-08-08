import pytest

from TOSKill.api.scan_protocol import (
    SCAN_PROTOCOL_VERSION,
    ScanProtocolValidationError,
    normalize_scan_protocol_payload,
    protocol_response,
)


def test_pause_payload_is_normalized():
    payload = normalize_scan_protocol_payload(
        "pause_for_chat",
        {"request_id": "req-1", "interaction_id": "interaction-1"},
    )

    assert payload["protocol_version"] == SCAN_PROTOCOL_VERSION
    assert payload["request_id"] == "req-1"
    assert payload["interaction_id"] == "interaction-1"


def test_resume_payload_rejects_unsupported_version():
    with pytest.raises(ScanProtocolValidationError) as exc_info:
        normalize_scan_protocol_payload(
            "resume_scan",
            {"protocol_version": "2.0", "pause_id": "pause-1"},
        )

    assert exc_info.value.details["message_type"] == "resume_scan"


def test_protocol_response_contains_correlation_fields():
    response = protocol_response("session-1", "req-2", status="paused")

    assert response == {
        "protocol_version": SCAN_PROTOCOL_VERSION,
        "request_id": "req-2",
        "session_id": "session-1",
        "status": "paused",
    }
