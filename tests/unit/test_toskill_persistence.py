import json
from uuid import uuid4
from unittest.mock import AsyncMock

import pytest

from TOSKill.AI.graph import memory_store
from TOSKill.AI.state import create_initial_state
from TOSKill.api.ai_chat_websocket import AIChatManager


@pytest.fixture
def persistent_session():
    session_id = f"persist-{uuid4().hex[:12]}"
    state = create_initial_state(target="https://example.com", task_id=session_id)
    memory_store.save_session(session_id, state)
    try:
        yield session_id, state
    finally:
        memory_store.delete_session(session_id)


def test_state_save_does_not_delete_chat_history(persistent_session):
    session_id, state = persistent_session
    memory_store.append_chat(session_id, "user", "first question")
    memory_store.append_chat(session_id, "assistant", "first answer")

    memory_store.save_session(session_id, {**state, "target": "https://updated.example.com"})

    conn = memory_store._get_db_conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM chat_history WHERE session_id = ?", (session_id,)
    ).fetchone()[0]
    assert count == 2
    assert len(memory_store.get_chat_history(session_id)) == 2


def test_partial_session_update_is_persisted(persistent_session):
    session_id, _ = persistent_session

    updated = memory_store.update_session(session_id, target="https://updated.example.com")

    conn = memory_store._get_db_conn()
    state_json = conn.execute(
        "SELECT state_json FROM sessions WHERE session_id = ?", (session_id,)
    ).fetchone()[0]
    assert updated["target"] == "https://updated.example.com"
    assert json.loads(state_json)["target"] == "https://updated.example.com"


def test_pending_interaction_is_persisted_and_cleared(persistent_session):
    session_id, state = persistent_session
    interaction = {"type": "interaction_required", "options": ["continue", "stop"]}

    memory_store.set_pending_interaction(session_id, interaction)
    memory_store.save_session(session_id, {**state, "confirmed": False})

    conn = memory_store._get_db_conn()
    row = conn.execute(
        "SELECT interaction_json FROM pending_interactions WHERE session_id = ?", (session_id,)
    ).fetchone()
    assert json.loads(row[0]) == interaction

    memory_store.clear_pending_interaction(session_id)
    row = conn.execute(
        "SELECT interaction_json FROM pending_interactions WHERE session_id = ?", (session_id,)
    ).fetchone()
    assert row is None


@pytest.mark.asyncio
async def test_chat_reuses_previous_turns(persistent_session):
    session_id, _ = persistent_session
    manager = AIChatManager()
    manager.connections[session_id] = AsyncMock()
    manager.llm = AsyncMock()
    manager.llm.ainvoke.side_effect = [
        type("Response", (), {"content": "first answer"})(),
        type("Response", (), {"content": "second answer"})(),
    ]

    await manager._handle_chat(session_id, {"content": "first question"})
    await manager._handle_chat(session_id, {"content": "follow-up question"})

    second_messages = manager.llm.ainvoke.call_args_list[1].args[0]
    contents = [message.content for message in second_messages]
    assert "first question" in contents
    assert "first answer" in contents
    assert "follow-up question" in contents
