import pytest
from services.ast_service import ASTAuditor


class TestASTAuditor:
    def test_safe_code_no_vulns(self, safe_code):
        auditor = ASTAuditor(safe_code)
        vulns = auditor.scan()
        assert len(vulns) == 0

    def test_detect_danger_functions(self, danger_functions_code):
        auditor = ASTAuditor(danger_functions_code)
        vulns = auditor.scan()
        assert len(vulns) >= 3
        vuln_types = [v["vuln_type"] for v in vulns]
        assert "命令/代码执行" in vuln_types
        for v in vulns:
            if v["vuln_type"] == "命令/代码执行":
                assert v["level"] == "HIGH"
                assert v["line_no"] > 0

    def test_detect_hardcoded_secrets(self, hardcode_code):
        auditor = ASTAuditor(hardcode_code)
        vulns = auditor.scan()
        assert len(vulns) >= 2
        for v in vulns:
            if v["vuln_type"] == "硬编码密钥":
                assert v["level"] == "HIGH"

    def test_detect_sql_injection(self, sql_code):
        auditor = ASTAuditor(sql_code)
        vulns = auditor.scan()
        assert len(vulns) >= 1
        sql_vulns = [v for v in vulns if v["vuln_type"] == "SQL注入风险"]
        assert len(sql_vulns) >= 1
        for v in sql_vulns:
            assert v["level"] == "MEDIUM"

    def test_detect_hardcoded_password_variable(self):
        code = 'password = "Admin@123"\n'
        auditor = ASTAuditor(code)
        vulns = auditor.scan()
        assert len(vulns) == 1
        assert vulns[0]["vuln_type"] == "硬编码密钥"
        assert vulns[0]["level"] == "HIGH"

    def test_detect_token_variable(self):
        code = 'token = "secret_token_value"\n'
        auditor = ASTAuditor(code)
        vulns = auditor.scan()
        assert len(vulns) == 1
        assert vulns[0]["vuln_type"] == "硬编码密钥"

    def test_detect_key_variable(self):
        code = 'api_access_key = "abcdef123456"\n'
        auditor = ASTAuditor(code)
        vulns = auditor.scan()
        assert len(vulns) == 1
        assert vulns[0]["vuln_type"] == "硬编码密钥"

    def test_syntax_error_handling(self, syntax_error_code):
        auditor = ASTAuditor(syntax_error_code)
        vulns = auditor.scan()
        assert len(vulns) == 1
        assert vulns[0]["vuln_type"] == "语法错误"
        assert vulns[0]["level"] == "HIGH"

    def test_standardize_code(self):
        code = """
def hello(  ):
    print( "hello" )
"""
        result = ASTAuditor.standardize(code)
        assert "hello" in result
        assert "def" in result

    def test_standardize_syntax_error(self):
        code = "def broken(:"
        result = ASTAuditor.standardize(code)
        assert result == code

    def test_line_number_in_vulns(self, danger_code):
        auditor = ASTAuditor(danger_code)
        vulns = auditor.scan()
        for v in vulns:
            if v["vuln_type"] != "语法错误":
                assert v["line_no"] > 0
                assert isinstance(v["line_no"], int)

    def test_code_snippet_in_vulns(self, danger_code):
        auditor = ASTAuditor(danger_code)
        vulns = auditor.scan()
        for v in vulns:
            if v["vuln_type"] != "语法错误":
                assert isinstance(v["code"], str)
                assert isinstance(v["desc"], str)
