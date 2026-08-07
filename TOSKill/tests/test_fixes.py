"""Compatibility entry point for the current WebSocket regression suite.

The old script asserted removed heartbeat and ping helpers. Those checks were
replaced with pytest tests in ``test_ai_chat_manager_current.py``.
"""
import pytest


pytestmark = pytest.mark.skip(
    reason="legacy fix script replaced by current AIChatManager regression tests"
)


def test_legacy_fix_script_replaced():
    """Keep the historical module discoverable without running stale checks."""
