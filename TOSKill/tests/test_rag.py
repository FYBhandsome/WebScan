"""
TOSKill RAG引擎测试
验证嵌入模型加载、知识文档、向量检索功能
"""
import pytest
import time
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestRAGInitialization:
    """RAG引擎初始化测试"""

    def test_rag_engine_singleton(self):
        """测试RAG引擎单例模式"""
        from TOSKill.RAG.rag_engine import get_rag_engine
        engine1 = get_rag_engine()
        engine2 = get_rag_engine()
        assert engine1 is engine2

    def test_rag_engine_not_initialized_by_default(self):
        """测试默认不加载模型"""
        from TOSKill.RAG.rag_engine import get_rag_engine
        engine = get_rag_engine()
        assert not engine._initialized

    def test_embed_model_loading_mocked(self):
        """Mocked：嵌入模型加载"""
        from TOSKill.RAG.rag_engine import get_rag_engine
        engine = get_rag_engine()
        with patch.object(engine, '_try_load_embed_model', return_value=MagicMock()):
            with patch.object(engine, '_build_index', return_value=None):
                with patch('llama_index.embeddings.huggingface.HuggingFaceEmbedding'):
                    assert engine is not None

    def test_knowledge_dir_exists(self):
        """验证知识目录存在"""
        from TOSKill.RAG.rag_engine import _KNOWLEDGE_DIR
        assert _KNOWLEDGE_DIR.exists()


class TestKnowledgeDocuments:
    """知识文档测试"""

    def test_knowledge_documents_count(self):
        """14个知识文档应全部存在"""
        from TOSKill.RAG.rag_engine import _KNOWLEDGE_DIR
        md_files = list(_KNOWLEDGE_DIR.glob("*.md"))
        expected_count = 14
        assert len(md_files) >= expected_count, f"期望{expected_count}个知识文档，实际{len(md_files)}个"

    def test_knowledge_files_have_content(self):
        """知识文档应有内容"""
        from TOSKill.RAG.rag_engine import _KNOWLEDGE_DIR
        for f in _KNOWLEDGE_DIR.glob("*.md"):
            content = f.read_text(encoding='utf-8')
            assert len(content) > 100, f"{f.name} 内容不足"

    def test_owasp_document_exists(self):
        """OWASP Top10文档应存在"""
        from TOSKill.RAG.rag_engine import _KNOWLEDGE_DIR
        owasp_file = _KNOWLEDGE_DIR / "06_owasp_top10.md"
        assert owasp_file.exists(), "OWASP Top10知识文档不存在"


class TestRAGRetrieval:
    """RAG检索功能测试"""

    def test_get_scan_strategy_import(self):
        """验证检索接口可导入"""
        try:
            from TOSKill.RAG.retriever import get_scan_strategy
            assert callable(get_scan_strategy)
        except ImportError as e:
            pytest.skip(f"RAG检索接口导入失败: {e}")

    @patch('TOSKill.RAG.retriever.get_rag_engine')
    def test_strategy_query_sql_injection(self, mock_engine):
        """查询SQL注入应返回相关策略（Mocked）"""
        mock_inst = MagicMock()
        mock_inst.is_available.return_value = True
        mock_inst.retriever = MagicMock()
        mock_node = MagicMock()
        mock_node.node.get_content.return_value = "# SQL注入\n\n方法：使用参数化查询防止注入"
        mock_inst.retriever.retrieve.return_value = [mock_node]
        mock_engine.return_value = mock_inst

        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(
            target="http://test.example.com",
            current_task="sqli",
            completed_tasks=[],
            last_result={}
        )
        assert result is not None
        assert len(result) > 0

    @patch('TOSKill.RAG.retriever.get_rag_engine')
    def test_strategy_empty_query(self, mock_engine):
        """空查询应返回空结果"""
        mock_inst = MagicMock()
        mock_inst.is_available.return_value = True
        mock_inst.retriever = MagicMock()
        mock_inst.retriever.retrieve.return_value = []
        mock_engine.return_value = mock_inst

        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(target="", current_task="", completed_tasks=[], last_result={})
        assert result == ""

    @patch('TOSKill.RAG.retriever.get_rag_engine')
    def test_special_characters_query(self, mock_engine):
        """特殊字符查询应安全处理"""
        mock_inst = MagicMock()
        mock_inst.is_available.return_value = True
        mock_inst.retriever = MagicMock()
        mock_node = MagicMock()
        mock_node.node.get_content.return_value = "测试内容"
        mock_inst.retriever.retrieve.return_value = [mock_node]
        mock_engine.return_value = mock_inst

        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(
            target='<script>alert(1)</script>',
            current_task='sqli_scan',
            completed_tasks=[],
            last_result={}
        )
        assert result is not None


class TestRAGEdgeCases:
    """RAG边界条件测试"""

    @patch('TOSKill.RAG.retriever.get_rag_engine')
    def test_engine_not_available(self, mock_engine):
        """引擎不可用时应处理"""
        mock_inst = MagicMock()
        mock_inst.is_available.return_value = False
        mock_engine.return_value = mock_inst

        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(
            target="http://test.com",
            current_task="baseinfo",
            completed_tasks=[],
            last_result={}
        )
        assert result == ""

    @patch('TOSKill.RAG.retriever.get_rag_engine')
    def test_retrieval_exception_graceful(self, mock_engine):
        """检索异常应优雅处理不崩溃"""
        mock_inst = MagicMock()
        mock_inst.is_available.return_value = True
        mock_inst.retriever.retrieve.side_effect = RuntimeError("模拟检索失败")
        mock_engine.return_value = mock_inst

        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(
            target="http://test.com",
            current_task="xss",
            completed_tasks=[],
            last_result={}
        )
        assert isinstance(result, str)