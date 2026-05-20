import ast
from typing import List, Dict


class ASTAuditor:
    def __init__(self, code: str):
        self.code = code
        self.vulns: List[Dict] = []
        self.lines = code.splitlines()

    def scan(self) -> List[Dict]:
        try:
            tree = ast.parse(self.code)
            visitor = VulnNodeVisitor(self)
            visitor.visit(tree)
        except SyntaxError:
            self.vulns.append({
                "vuln_type": "语法错误",
                "level": "HIGH",
                "line_no": 0,
                "code": "",
                "desc": "代码语法不合法，无法解析"
            })
        return self.vulns

    @staticmethod
    def standardize(code: str) -> str:
        try:
            tree = ast.parse(code)
            return ast.unparse(tree)
        except SyntaxError:
            return code


class VulnNodeVisitor(ast.NodeVisitor):
    def __init__(self, auditor: ASTAuditor):
        self.auditor = auditor

    def visit_Call(self, node: ast.Call):
        func = self._get_func_name(node.func)
        self._check_danger_func(func, node.lineno)
        self._check_sql_inject(func, node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._check_hard_code(node)
        self.generic_visit(node)

    def _get_func_name(self, func) -> str:
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            return func.attr
        return ""

    def _check_danger_func(self, func: str, line: int):
        dangers = ["eval", "exec", "system", "popen", "subprocess"]
        if func in dangers:
            self.auditor.vulns.append({
                "vuln_type": "命令/代码执行",
                "level": "HIGH",
                "line_no": line,
                "code": self.auditor.lines[line - 1].strip() if line <= len(self.auditor.lines) else "",
                "desc": f"使用危险函数 {func}，存在远程代码执行风险"
            })

    def _check_sql_inject(self, func: str, line: int):
        if func in ["execute", "executemany"]:
            self.auditor.vulns.append({
                "vuln_type": "SQL注入风险",
                "level": "MEDIUM",
                "line_no": line,
                "code": self.auditor.lines[line - 1].strip() if line <= len(self.auditor.lines) else "",
                "desc": "数据库语句未参数化，存在注入漏洞"
            })

    def _check_hard_code(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()
                if any(k in name for k in ["pwd", "password", "token", "key", "secret"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.auditor.vulns.append({
                            "vuln_type": "硬编码密钥",
                            "level": "HIGH",
                            "line_no": node.lineno,
                            "code": self.auditor.lines[node.lineno - 1].strip(),
                            "desc": "检测到硬编码密码/密钥，极易泄露"
                        })
