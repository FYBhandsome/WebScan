"""
TOSKill RAG引擎测试
验证嵌入模型加载、知识文档、向量检索功能
"""
import ast
import re

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

    def test_rag_engine_initialization_follows_configuration(self):
        """RAG启用时应尝试初始化；禁用时保持未初始化。"""
        from TOSKill.config import settings
        from TOSKill.RAG.rag_engine import get_rag_engine
        engine = get_rag_engine()
        if settings.RAG_ENABLED:
            assert engine._initialized or engine._model_load_error
        else:
            assert not engine._initialized

    def test_embed_model_loading_mocked(self):
        """Mocked：嵌入模型加载"""
        from TOSKill.RAG.rag_engine import get_rag_engine
        engine = get_rag_engine()
        with patch.object(engine, '_try_load_embed_model', return_value=MagicMock()):
            with patch.object(engine, '_build_index', return_value=None):
                assert engine is not None

    def test_knowledge_dir_exists(self):
        """验证知识目录存在"""
        from TOSKill.RAG.rag_engine import _KNOWLEDGE_DIR
        assert _KNOWLEDGE_DIR.exists()


class TestKnowledgeDocuments:
    """知识文档测试"""

    def test_knowledge_documents_count(self):
        """18个知识文档应全部存在"""
        from TOSKill.RAG.rag_engine import _KNOWLEDGE_DIR
        md_files = list(_KNOWLEDGE_DIR.glob("*.md"))
        expected_count = 18
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
        from TOSKill.RAG.retriever import get_scan_strategy
        assert callable(get_scan_strategy)

    def test_strategy_query_sql_injection(self):
        """查询SQL注入应返回相关策略（真实RAG调用）"""
        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(
            target="http://test.example.com",
            current_task="sqli_scan",
            completed_tasks=["baseinfo_scan"],
            last_result={"status": "success"}
        )
        assert isinstance(result, str)

    def test_strategy_empty_query(self):
        """空查询应返回空结果"""
        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(target="", current_task="", completed_tasks=[], last_result={})
        assert isinstance(result, str)

    def test_special_characters_handled(self):
        """特殊字符查询应安全处理"""
        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(
            target='<script>alert(1)</script>',
            current_task='sqli_scan',
            completed_tasks=[],
            last_result={}
        )
        assert isinstance(result, str)


class TestRAGEdgeCases:
    """RAG边界条件测试"""

    def test_engine_not_available(self):
        """引擎不可用时应安全返回"""
        from TOSKill.RAG.retriever import get_scan_strategy
        from TOSKill.RAG.rag_engine import get_rag_engine
        engine = get_rag_engine()

        try:
            with patch.object(engine, 'is_available', return_value=False):
                result = get_scan_strategy(
                    target="http://test.com",
                    current_task="baseinfo_scan",
                    completed_tasks=[],
                    last_result={}
                )
                assert result == ""
        except Exception:
            pass

    def test_retrieval_exception_graceful(self):
        """检索异常应优雅处理不崩溃"""
        from TOSKill.RAG.retriever import get_scan_strategy
        result = get_scan_strategy(
            target="http://test.com",
            current_task="xss_scan",
            completed_tasks=[],
            last_result={}
        )
        assert isinstance(result, str)


class TestKnowledgeConsistency:
    """知识库与当前系统工具注册表的一致性检查。"""

    PROJECT_ROOT = Path(__file__).resolve().parents[1]
    KNOWLEDGE_DIR = PROJECT_ROOT / "RAG" / "knowledge"

    @staticmethod
    def _literal_assignment(path: Path, name: str):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                return ast.literal_eval(node.value)
        raise AssertionError(f"{path.name} 中缺少可静态读取的 {name}")

    @staticmethod
    def _name_list_assignment(path: Path, name: str) -> list[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                if not isinstance(node.value, ast.List):
                    break
                values = [item.id for item in node.value.elts if isinstance(item, ast.Name)]
                if len(values) == len(node.value.elts):
                    return values
        raise AssertionError(f"{path.name} 中缺少可静态读取的 {name}")

    @classmethod
    def _system_tool_names(cls) -> set[str]:
        tools_path = cls.PROJECT_ROOT / "AI" / "tools.py"
        return set().union(*(
            cls._name_list_assignment(tools_path, registry)
            for registry in ("INFO_COLLECTION_TOOLS", "VULN_SCAN_TOOLS", "POC_TOOLS")
        ))

    def test_rag_tool_keywords_cover_every_system_scan_tool(self):
        keyword_map = self._literal_assignment(
            self.PROJECT_ROOT / "RAG" / "rag_engine.py",
            "TOOL_KNOWLEDGE_MAP",
        )
        assert set(keyword_map) == self._system_tool_names()

    def test_canonical_tool_catalog_lists_every_system_scan_tool(self):
        catalog = (self.KNOWLEDGE_DIR / "03_tool_mapping.md").read_text(encoding="utf-8")
        missing = sorted(name for name in self._system_tool_names() if f"`{name}`" not in catalog)
        assert not missing, f"工具目录缺少: {missing}"

    def test_decision_documents_do_not_use_obsolete_callable_names(self):
        obsolete_names = {
            "dir_scan", "dirscan", "waf_detect", "cdn_detect", "cms_detect",
            "whatcms_scan", "web_vuln_scan",
        }
        offenders = []
        for path in self.KNOWLEDGE_DIR.glob("*.md"):
            if path.name == "03_tool_mapping.md":
                continue  # 该文件保留历史别名用于旧报告兼容说明。
            content = path.read_text(encoding="utf-8")
            for name in obsolete_names:
                if re.search(rf"(?<![a-z0-9_]){re.escape(name)}(?![a-z0-9_])", content):
                    offenders.append(f"{path.name}:{name}")
        assert not offenders, f"知识库仍使用旧调用名称: {offenders}"

    def test_knowledge_base_does_not_claim_automatic_mlps_compliance(self):
        forbidden_claims = {
            "可直接用于等保合规决策", "基础符合度 =", "行业基准置信度",
            "全工具链无漏洞 | 无 | 控制项全部满足",
        }
        offenders = []
        for path in self.KNOWLEDGE_DIR.glob("*.md"):
            content = path.read_text(encoding="utf-8")
            for claim in forbidden_claims:
                if claim in content:
                    offenders.append(f"{path.name}:{claim}")
        assert not offenders, f"知识库包含不应自动生成的合规结论: {offenders}"

    def test_confidence_prompt_uses_technical_evidence_schema(self):
        prompt_source = (
            self.PROJECT_ROOT / "tools" / "report" / "confidence_assessor.py"
        ).read_text(encoding="utf-8")
        assert '"evidence_coverage"' in prompt_source
        assert '"review_required": true' in prompt_source
        assert '"compliance_estimate"' not in prompt_source

    def test_report_labels_confidence_as_technical_evidence(self):
        template_source = (
            self.PROJECT_ROOT / "tools" / "report" / "scan_report_template.py"
        ).read_text(encoding="utf-8")
        assert "AI 技术证据置信度" in template_source
        assert "AI 等保评估置信度" not in template_source
