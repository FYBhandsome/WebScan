from unittest.mock import Mock

import pytest


@pytest.fixture
def mapping_engine(tmp_path, monkeypatch):
    from TOSKill.RAG import rag_engine, retriever

    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir()
    (knowledge_dir / "mapping.md").write_text(
        "SQL注入漏洞需要参数化查询，并依据风险等级提供修复建议和安全加固。",
        encoding="utf-8",
    )

    rag_engine.TOSKillRAGEngine._instance = None
    rag_engine._rag_engine = None
    monkeypatch.setattr(rag_engine, "_KNOWLEDGE_DIR", knowledge_dir)
    monkeypatch.setattr(rag_engine.settings, "RAG_MODE", "mapping")
    load_embed = Mock(return_value=None)
    monkeypatch.setattr(rag_engine.TOSKillRAGEngine, "_try_load_embed_model", load_embed)

    engine = rag_engine.TOSKillRAGEngine()
    monkeypatch.setattr(retriever, "get_rag_engine", lambda: engine)
    yield engine, retriever, load_embed

    rag_engine.TOSKillRAGEngine._instance = None
    rag_engine._rag_engine = None


def test_default_mapping_does_not_load_embedding(mapping_engine):
    engine, _, load_embed = mapping_engine

    assert engine.get_status()["mode"] == "mapping"
    assert engine.get_status()["model_loaded"] is False
    load_embed.assert_not_called()


def test_mapping_public_retrieval_interfaces(mapping_engine):
    _, retriever, _ = mapping_engine

    strategy = retriever.get_scan_strategy(
        target="https://example.test",
        current_task="sqli_scan",
        completed_tasks=[],
        last_result={},
    )
    report = retriever.retrieve_for_report(
        "https://example.test", [{"type": "sqli", "severity": "high"}]
    )
    risk = retriever.retrieve_for_risk_assessment("sqli", "high")
    score = retriever.get_kb_match_score("SQL注入 风险等级 修复建议")

    assert strategy
    assert report
    assert risk
    assert isinstance(strategy, str)
    assert isinstance(report, str)
    assert isinstance(risk, str)
    assert 0.0 <= score <= 1.0


def test_mapping_miss_does_not_trigger_embedding_model(mapping_engine):
    _, retriever, load_embed = mapping_engine

    result = retriever.get_scan_strategy(
        target="",
        current_task="不存在的检索词xyz987",
        completed_tasks=[],
        last_result={},
    )
    score = retriever.get_kb_match_score("不存在的检索词xyz987")

    assert result == ""
    assert score == 0.0
    load_embed.assert_not_called()


def test_legacy_vector_mode_remains_callable(mapping_engine):
    engine, _, _ = mapping_engine

    status = engine.set_mode("vector")

    assert status["mode"] == "vector"
    assert status["index_ready"] or isinstance(status["last_error"], str)
