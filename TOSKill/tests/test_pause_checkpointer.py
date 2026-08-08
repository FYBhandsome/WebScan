import asyncio
from typing import TypedDict

from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from TOSKill.AI.graph import create_async_checkpointer, router
from TOSKill.AI.state import create_initial_state


class _CheckpointState(TypedDict, total=False):
    value: int
    resumed: str


def _build_checkpoint_graph(checkpointer):
    def pause_node(state: _CheckpointState):
        value = interrupt({"type": "test_pause"})
        return {
            "value": state.get("value", 0) + 1,
            "resumed": str(value),
        }

    workflow = StateGraph(_CheckpointState)
    workflow.add_node("pause", pause_node)
    workflow.set_entry_point("pause")
    workflow.add_edge("pause", END)
    return workflow.compile(checkpointer=checkpointer)


def test_router_accepts_resume_after_chat():
    state = create_initial_state("example.com", "router-test")
    state["user_choice"] = "resume_after_chat"
    assert router(state) == "ai_decision"


def test_async_sqlite_checkpoint_survives_reopen(tmp_path):
    async def scenario():
        db_path = str(tmp_path / "checkpoints.db")
        config = {"configurable": {"thread_id": "checkpoint-restart"}}

        first_checkpointer = await create_async_checkpointer(db_path)
        try:
            first_graph = _build_checkpoint_graph(first_checkpointer)
            result = await first_graph.ainvoke({"value": 1}, config=config)
            assert result.get("__interrupt__")
        finally:
            await first_checkpointer.conn.close()

        second_checkpointer = await create_async_checkpointer(db_path)
        try:
            second_graph = _build_checkpoint_graph(second_checkpointer)
            snapshot = await second_graph.aget_state(config)
            assert snapshot.values["value"] == 1
            assert snapshot.next == ("pause",)

            result = await second_graph.ainvoke(
                Command(resume={"choice": "continue"}),
                config=config,
            )
            assert result["value"] == 2
        finally:
            await second_checkpointer.conn.close()

    asyncio.run(scenario())
