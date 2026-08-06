"""
TOSKill Cookie 机制升级自测脚本 (Task 11)

验证内容:
    SubTask 11.1: 信息收集工具在 on_demand 模式下不携带 cookie；
                  按需逻辑——仅当 params 中显式存在 cookie 时才传递。
    SubTask 11.2: LLM 在 params 中显式指定 cookie/cookies 键时，cookie 被正确透传。
    SubTask 11.3: cookie_brute_extract 可执行、签名正确、注册在 COOKIE_TOOLS，
                  返回 ToolResult 格式。

运行方式 (PowerShell):
    & "D:\AI_WebSecurity\.conda\python.exe" "d:\AI_WebSecurity\TOSKill\test_cookie_mechanism.py"

说明:
    - 不修改任何源码，仅做黑盒/灰盒自测。
    - 使用 Mock 工具验证 invoke_tool_with_auth 的按需下发行为，避免真实网络请求。
    - 依赖缺失时降级并报告可用情况。
"""

import os
import sys
import inspect
import traceback
from typing import Dict, Any, List, Optional

# ---------------------------------------------------------------------------
# 0. 环境准备: 把项目根目录加入 sys.path，使 TOSKill.AI.tools 可被导入
# ---------------------------------------------------------------------------
PROJECT_ROOT = r"d:\AI_WebSecurity"
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# 测试结果收集
# ---------------------------------------------------------------------------
_results: List[Dict[str, Any]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    _results.append({"name": name, "passed": passed, "detail": detail})
    tag = "PASS" if passed else "FAIL"
    print(f"[{tag}] {name}" + (f" -- {detail}" if detail else ""))


def check(name: str, condition: bool, detail: str = "") -> None:
    record(name, bool(condition), detail)


# ---------------------------------------------------------------------------
# Mock 工具: 用于验证 invoke_tool_with_auth 的参数透传行为
# ---------------------------------------------------------------------------
class MockTool:
    """模拟 LangChain 工具: 记录最后一次 invoke 收到的参数。"""

    def __init__(self, name: str, func=None):
        self.name = name
        self.last_params: Optional[Dict[str, Any]] = None
        # unified_tool_invoke 会通过 inspect.signature(tool.func) 取签名做参数过滤
        self.func = func if func is not None else self._default_func

    @staticmethod
    def _default_func(target: str, cookies: Dict[str, str] = None) -> Dict[str, Any]:
        return {"target": target, "cookies": cookies}

    def invoke(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.last_params = dict(params)
        return {"success": True, "data": dict(params), "error": None}


# ===========================================================================
# 模块导入
# ===========================================================================
tools = None
_import_error = None
try:
    from TOSKill.AI import tools as _tools_mod  # noqa: E402
    tools = _tools_mod
    record("模块导入 TOSKill.AI.tools", True)
except Exception as e:  # pragma: no cover - 降级分支
    _import_error = traceback.format_exc()
    record("模块导入 TOSKill.AI.tools", False, f"{type(e).__name__}: {e}")


# ===========================================================================
# SubTask 11.1: 信息收集工具不携带 cookie + 按需逻辑
# ===========================================================================
def test_info_collection_tools_definition():
    """INFO_COLLECTION_TOOLS 存在且包含预期工具。"""
    if tools is None:
        record("11.1a INFO_COLLECTION_TOOLS 定义", False, "模块未导入")
        return
    expected = {
        "baseinfo_scan", "port_scan", "subdomain_scan", "dir_brute",
        "waf_detect_scan", "cdn_detect_scan", "cms_detect_scan",
        "infoleak_scan", "ip_locate_scan", "webside_query_scan", "web_weight_scan",
    }
    lst = getattr(tools, "INFO_COLLECTION_TOOLS", None)
    check("11.1a INFO_COLLECTION_TOOLS 存在", isinstance(lst, list) and len(lst) >= 10,
          f"len={len(lst) if isinstance(lst, list) else 'N/A'}")
    if isinstance(lst, list):
        names = {getattr(t, "name", "") for t in lst}
        missing = expected - names
        check("11.1a INFO_COLLECTION_TOOLS 含预期工具", not missing,
              f"缺失: {missing}" if missing else f"共 {len(names)} 个工具")


def test_on_demand_mode_constant():
    """COOKIE_INJECTION_MODE == 'on_demand'。"""
    if tools is None:
        record("11.1b COOKIE_INJECTION_MODE 常量", False, "模块未导入")
        return
    mode = getattr(tools, "COOKIE_INJECTION_MODE", None)
    check("11.1b COOKIE_INJECTION_MODE == 'on_demand'", mode == "on_demand",
          f"实际值: {mode!r}")


def test_on_demand_no_auto_injection():
    """on_demand 模式下，state 含 auth_info 但 params 无 cookie 时，不自动注入。"""
    if tools is None:
        record("11.1c on_demand 不自动注入 cookie", False, "模块未导入")
        return
    mock = MockTool("sqli_scan")  # 非信息收集工具
    state = {
        "auth_info": {
            "cookies": {"sessionid": "AUTO_INJECTED"},
            "headers": {"Authorization": "Bearer AUTO"},
            "token": "AUTO_TOKEN",
        }
    }
    try:
        tools.invoke_tool_with_auth(mock, {"target": "http://example.com"}, state)
        got = mock.last_params or {}
        no_cookie = "cookies" not in got
        no_header = "headers" not in got
        no_token = "auth_token" not in got
        check("11.1c on_demand 不自动注入 cookie", no_cookie and no_header and no_token,
              f"params keys={sorted(got.keys())}")
    except Exception as e:
        record("11.1c on_demand 不自动注入 cookie", False, f"{type(e).__name__}: {e}")


def test_info_collection_guard_in_legacy():
    """legacy 模式下，信息收集工具仍不下发 cookie (守卫生效)。"""
    if tools is None:
        record("11.1d legacy 模式信息收集工具守卫", False, "模块未导入")
        return
    original_mode = tools.COOKIE_INJECTION_MODE
    try:
        tools.COOKIE_INJECTION_MODE = "legacy"

        # 信息收集工具 -> 不应注入
        info_mock = MockTool("baseinfo_scan")
        state = {"auth_info": {"cookies": {"x": "1"}, "headers": {"h": "1"}, "token": "t"}}
        tools.invoke_tool_with_auth(info_mock, {"target": "http://example.com"}, state)
        info_got = info_mock.last_params or {}
        info_clean = "cookies" not in info_got and "headers" not in info_got

        # 非信息收集工具 -> legacy 应自动注入
        vuln_mock = MockTool("sqli_scan")
        tools.invoke_tool_with_auth(vuln_mock, {"target": "http://example.com"}, state)
        vuln_got = vuln_mock.last_params or {}
        vuln_has_cookie = vuln_got.get("cookies") == {"x": "1"}

        check("11.1d legacy 模式信息收集工具不下发 cookie", info_clean,
              f"info params keys={sorted(info_got.keys())}")
        check("11.1d legacy 模式非信息收集工具自动注入 cookie", vuln_has_cookie,
              f"vuln params keys={sorted(vuln_got.keys())}")
    except Exception as e:
        record("11.1d legacy 模式信息收集工具守卫", False, f"{type(e).__name__}: {e}")
    finally:
        tools.COOKIE_INJECTION_MODE = original_mode


# ===========================================================================
# SubTask 11.2: LLM 显式指定 cookie 键时正确透传
# ===========================================================================
def test_explicit_cookies_passthrough():
    """params 显式含 'cookies' 键时，on_demand 模式下被原样透传给工具。"""
    if tools is None:
        record("11.2a 显式 cookies 透传", False, "模块未导入")
        return
    mock = MockTool("sqli_scan")
    explicit_cookies = {"sessionid": "LLM_PROVIDED_TOKEN"}
    state = {"auth_info": {"cookies": {"sessionid": "SHOULD_NOT_OVERRIDE_OR_INJECT"}}}
    params = {"target": "http://example.com", "cookies": explicit_cookies}
    try:
        tools.invoke_tool_with_auth(mock, params, state)
        got = mock.last_params or {}
        ok = got.get("cookies") == explicit_cookies
        check("11.2a 显式 cookies 透传 (不被覆盖)", ok,
              f"cookies={got.get('cookies')!r}")
    except Exception as e:
        record("11.2a 显式 cookies 透传", False, f"{type(e).__name__}: {e}")


def test_explicit_cookie_singular_passthrough():
    """params 显式含 'cookie' (单数) 键时也应被保留透传。"""
    if tools is None:
        record("11.2b 显式 cookie(单数) 透传", False, "模块未导入")
        return
    mock = MockTool("sqli_scan")
    state = {"auth_info": {"cookies": {"a": "1"}}}
    params = {"target": "http://example.com", "cookie": "PHPSESSID=abc123"}
    try:
        tools.invoke_tool_with_auth(mock, params, state)
        got = mock.last_params or {}
        check("11.2b 显式 cookie(单数) 透传", got.get("cookie") == "PHPSESSID=abc123",
              f"cookie={got.get('cookie')!r}")
    except Exception as e:
        record("11.2b 显式 cookie(单数) 透传", False, f"{type(e).__name__}: {e}")


def test_explicit_headers_token_passthrough():
    """params 显式含 headers/auth_token 时被透传 (on_demand 不注入也不删除)。"""
    if tools is None:
        record("11.2c 显式 headers/auth_token 透传", False, "模块未导入")
        return
    mock = MockTool("sqli_scan")
    state = {"auth_info": {"cookies": {"a": "1"}}}
    params = {
        "target": "http://example.com",
        "headers": {"X-Custom": "yes"},
        "auth_token": "MY_TOKEN",
    }
    try:
        tools.invoke_tool_with_auth(mock, params, state)
        got = mock.last_params or {}
        ok = got.get("headers") == {"X-Custom": "yes"} and got.get("auth_token") == "MY_TOKEN"
        check("11.2c 显式 headers/auth_token 透传", ok,
              f"headers={got.get('headers')!r} auth_token={got.get('auth_token')!r}")
    except Exception as e:
        record("11.2c 显式 headers/auth_token 透传", False, f"{type(e).__name__}: {e}")


# ===========================================================================
# SubTask 11.3: cookie_brute_extract 可执行性
# ===========================================================================
def test_cookie_brute_extract_registration():
    """cookie_brute_extract 已注册在 COOKIE_TOOLS。"""
    if tools is None:
        record("11.3a cookie_brute_extract 注册", False, "模块未导入")
        return
    brute = getattr(tools, "cookie_brute_extract", None)
    cookie_tools = getattr(tools, "COOKIE_TOOLS", [])
    names = [getattr(t, "name", "") for t in cookie_tools]
    check("11.3a cookie_brute_extract 在 COOKIE_TOOLS 中",
          brute is not None and "cookie_brute_extract" in names,
          f"COOKIE_TOOLS={names}")


def test_cookie_brute_extract_signature():
    """cookie_brute_extract 具有正确签名 (target, login_paths, cred_pairs)。"""
    if tools is None:
        record("11.3b cookie_brute_extract 签名", False, "模块未导入")
        return
    brute = getattr(tools, "cookie_brute_extract", None)
    if brute is None:
        record("11.3b cookie_brute_extract 签名", False, "对象不存在")
        return
    has_invoke = hasattr(brute, "invoke")
    has_func = hasattr(brute, "func")
    try:
        sig = inspect.signature(brute.func) if has_func else None
        params = list(sig.parameters.keys()) if sig else []
        expected = ["target", "login_paths", "cred_pairs"]
        check("11.3b cookie_brute_extract 可调用 (has invoke/func)",
              has_invoke or has_func, f"invoke={has_invoke} func={has_func}")
        check("11.3b cookie_brute_extract 签名正确",
              params == expected, f"params={params}")
    except Exception as e:
        record("11.3b cookie_brute_extract 签名", False, f"{type(e).__name__}: {e}")


def test_cookie_brute_extract_executable():
    """cookie_brute_extract 可执行并以 dict 返回 (空目标早退路径)。"""
    if tools is None:
        record("11.3c cookie_brute_extract 可执行", False, "模块未导入")
        return
    brute = getattr(tools, "cookie_brute_extract", None)
    if brute is None:
        record("11.3c cookie_brute_extract 可执行", False, "对象不存在")
        return
    try:
        result = brute.invoke({"target": ""})
        is_dict = isinstance(result, dict)
        has_success = is_dict and "success" in result and isinstance(result["success"], bool)
        has_data = is_dict and isinstance(result.get("data"), dict)
        has_error = is_dict and "error" in result
        check("11.3c cookie_brute_extract 返回 dict 且含 success/data/error",
              is_dict and has_success and has_data and has_error,
              f"keys={sorted(result.keys()) if is_dict else type(result)}")

        # ToolResult 标准要求 timestamp 字段 (validate_tool_result)
        has_timestamp = is_dict and isinstance(result.get("timestamp"), str)
        vtr = tools.validate_tool_result(result) if is_dict else False
        check("11.3c cookie_brute_extract 返回符合 ToolResult 标准 (含 timestamp)",
              has_timestamp and vtr,
              f"timestamp={result.get('timestamp')!r} validate_tool_result={vtr}")
    except Exception as e:
        record("11.3c cookie_brute_extract 可执行", False, f"{type(e).__name__}: {e}")


# ===========================================================================
# 附加: unified_tool_invoke 参数过滤
# ===========================================================================
def test_unified_tool_invoke_param_filtering():
    """unified_tool_invoke 通过 inspect 过滤工具不接受的多余参数。"""
    if tools is None:
        record("11.4a unified_tool_invoke 参数过滤", False, "模块未导入")
        return

    def _func(target: str, cookies: Dict[str, str] = None) -> Dict[str, Any]:
        return {"target": target, "cookies": cookies}

    mock = MockTool("mock_filter_tool", func=_func)

    # 临时注册到 TOOL_MAP
    tool_map = getattr(tools, "TOOL_MAP", {})
    original = tool_map.get("mock_filter_tool")
    tool_map["mock_filter_tool"] = mock
    try:
        # 传入多余参数 extra_junk，应被过滤掉；cookies 显式传入应保留
        arguments = {
            "target": "http://example.com",
            "cookies": {"k": "v"},
            "extra_junk": "should_be_filtered",
        }
        tools.unified_tool_invoke("mock_filter_tool", arguments, state=None)
        got = mock.last_params or {}
        junk_filtered = "extra_junk" not in got
        cookies_kept = got.get("cookies") == {"k": "v"}
        check("11.4a unified_tool_invoke 过滤多余参数",
              junk_filtered and cookies_kept,
              f"keys={sorted(got.keys())}")
    except Exception as e:
        record("11.4a unified_tool_invoke 参数过滤", False, f"{type(e).__name__}: {e}")
    finally:
        if original is None:
            tool_map.pop("mock_filter_tool", None)
        else:
            tool_map["mock_filter_tool"] = original


def test_unified_tool_invoke_missing_tool():
    """unified_tool_invoke 对不存在工具返回标准错误。"""
    if tools is None:
        record("11.4b unified_tool_invoke 工具不存在", False, "模块未导入")
        return
    try:
        result = tools.unified_tool_invoke("__not_exist_tool__", {"target": "x"}, state=None)
        ok = isinstance(result, dict) and result.get("success") is False
        check("11.4b unified_tool_invoke 工具不存在返回 success=False", ok,
              f"result={result}")
    except Exception as e:
        record("11.4b unified_tool_invoke 工具不存在", False, f"{type(e).__name__}: {e}")


# ===========================================================================
# 主入口
# ===========================================================================
def main() -> int:
    print("=" * 72)
    print("TOSKill Cookie 机制升级自测 (Task 11)")
    print("=" * 72)

    if tools is None:
        print("\n[警告] 模块导入失败，部分测试将跳过。导入错误:\n")
        print(_import_error or "(未知错误)")
    else:
        print(f"\n环境: Python {sys.version.split()[0]} | "
              f"COOKIE_INJECTION_MODE={tools.COOKIE_INJECTION_MODE!r}\n")

    # 11.1
    test_info_collection_tools_definition()
    test_on_demand_mode_constant()
    test_on_demand_no_auto_injection()
    test_info_collection_guard_in_legacy()
    # 11.2
    test_explicit_cookies_passthrough()
    test_explicit_cookie_singular_passthrough()
    test_explicit_headers_token_passthrough()
    # 11.3
    test_cookie_brute_extract_registration()
    test_cookie_brute_extract_signature()
    test_cookie_brute_extract_executable()
    # 11.4 (附加)
    test_unified_tool_invoke_param_filtering()
    test_unified_tool_invoke_missing_tool()

    # 汇总
    total = len(_results)
    passed = sum(1 for r in _results if r["passed"])
    failed = total - passed
    print("\n" + "=" * 72)
    print(f"汇总: {passed}/{total} 通过, {failed} 失败")
    if failed:
        print("失败项:")
        for r in _results:
            if not r["passed"]:
                print(f"  - {r['name']}: {r['detail']}")
    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
