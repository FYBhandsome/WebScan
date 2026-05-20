import sys
import os
import time
import json
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.tests.vuln_test_server import start_vuln_server, stop_vuln_server

PASS_COUNT = 0
FAIL_COUNT = 0
ERRORS = []


def test(name, func):
    global PASS_COUNT, FAIL_COUNT
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    try:
        func()
        PASS_COUNT += 1
        print(f"  ✅ PASS")
    except AssertionError as e:
        FAIL_COUNT += 1
        ERRORS.append((name, str(e)))
        print(f"  ❌ FAIL: {e}")
    except Exception as e:
        FAIL_COUNT += 1
        ERRORS.append((name, f"Exception: {e}\n{traceback.format_exc()}"))
        print(f"  ❌ ERROR: {e}")


def test_scanner_class_exports():
    from backend.vulnerability_scan_plugins.sqli import SCANNER_CLASS as SqliClass
    from backend.vulnerability_scan_plugins.xss import SCANNER_CLASS as XssClass
    from backend.vulnerability_scan_plugins.csrf import SCANNER_CLASS as CsrfClass
    from backend.vulnerability_scan_plugins.cmdi import SCANNER_CLASS as CmdiClass
    from backend.vulnerability_scan_plugins.ssrf import SCANNER_CLASS as SsrfClass
    from backend.vulnerability_scan_plugins.lfi import SCANNER_CLASS as LfiClass
    from backend.vulnerability_scan_plugins.fileupload import SCANNER_CLASS as FuClass
    from backend.vulnerability_scan_plugins.weakpass import SCANNER_CLASS as WpClass

    assert SqliClass is not None, "SQLi SCANNER_CLASS is None"
    assert XssClass is not None, "XSS SCANNER_CLASS is None"
    assert CsrfClass is not None, "CSRF SCANNER_CLASS is None"
    assert CmdiClass is not None, "CMDI SCANNER_CLASS is None"
    assert SsrfClass is not None, "SSRF SCANNER_CLASS is None"
    assert LfiClass is not None, "LFI SCANNER_CLASS is None"
    assert FuClass is not None, "FileUpload SCANNER_CLASS is None"
    assert WpClass is not None, "WeakPass SCANNER_CLASS is None"
    print(f"  All 8 SCANNER_CLASS exports verified")


def test_plugin_manager_loading():
    from backend.vulnerability_scan_plugins.manager import PluginManager
    pm = PluginManager()

    from backend.vulnerability_scan_plugins.sqli import SCANNER_CLASS as SqliClass
    from backend.vulnerability_scan_plugins.xss import SCANNER_CLASS as XssClass
    from backend.vulnerability_scan_plugins.csrf import SCANNER_CLASS as CsrfClass
    from backend.vulnerability_scan_plugins.cmdi import SCANNER_CLASS as CmdiClass
    from backend.vulnerability_scan_plugins.ssrf import SCANNER_CLASS as SsrfClass
    from backend.vulnerability_scan_plugins.lfi import SCANNER_CLASS as LfiClass
    from backend.vulnerability_scan_plugins.fileupload import SCANNER_CLASS as FuClass
    from backend.vulnerability_scan_plugins.weakpass import SCANNER_CLASS as WpClass

    pm.register_plugin_class(SqliClass)
    pm.register_plugin_class(XssClass)
    pm.register_plugin_class(CsrfClass)
    pm.register_plugin_class(CmdiClass)
    pm.register_plugin_class(SsrfClass)
    pm.register_plugin_class(LfiClass)
    pm.register_plugin_class(FuClass)
    pm.register_plugin_class(WpClass)

    plugins = pm.list_plugins()
    assert len(plugins) >= 8, f"Expected >= 8 plugins, got {len(plugins)}"
    print(f"  PluginManager loaded {len(plugins)} plugins")


def test_sqli_scanner():
    from backend.vulnerability_scan_plugins.sqli.scanner import SQLiScanner
    scanner = SQLiScanner(f"http://127.0.0.1:18888/sqli?id=1")
    result = scanner.scan()
    assert result.success, f"SQLi scan failed: {result.error_message}"
    assert result.plugin_name == "sqli_scanner"
    print(f"  SQLi: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_xss_scanner():
    from backend.vulnerability_scan_plugins.xss.scanner import XSSScanner
    scanner = XSSScanner(f"http://127.0.0.1:18888/xss?name=test")
    result = scanner.scan()
    assert result.success, f"XSS scan failed: {result.error_message}"
    assert result.plugin_name == "xss_scanner"
    print(f"  XSS: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_csrf_scanner():
    from backend.vulnerability_scan_plugins.csrf.scanner import CSRFScanner
    scanner = CSRFScanner(f"http://127.0.0.1:18888/csrf")
    result = scanner.scan()
    assert result.success, f"CSRF scan failed: {result.error_message}"
    assert result.plugin_name == "csrf_scanner"
    print(f"  CSRF: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_cmdi_scanner():
    from backend.vulnerability_scan_plugins.cmdi.scanner import CmdiScanner
    scanner = CmdiScanner(f"http://127.0.0.1:18888/cmdi?cmd=test")
    result = scanner.scan()
    assert result.success, f"CMDI scan failed: {result.error_message}"
    assert result.plugin_name == "cmdi"
    print(f"  CMDI: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_ssrf_scanner():
    from backend.vulnerability_scan_plugins.ssrf.scanner import SsrfScanner
    scanner = SsrfScanner(f"http://127.0.0.1:18888/ssrf?url=http://example.com")
    result = scanner.scan()
    assert result.success, f"SSRF scan failed: {result.error_message}"
    assert result.plugin_name == "ssrf"
    print(f"  SSRF: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_lfi_scanner():
    from backend.vulnerability_scan_plugins.lfi.scanner import LfiScanner
    scanner = LfiScanner(f"http://127.0.0.1:18888/lfi?file=test.txt")
    result = scanner.scan()
    assert result.success, f"LFI scan failed: {result.error_message}"
    assert result.plugin_name == "lfi"
    print(f"  LFI: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_fileupload_scanner():
    from backend.vulnerability_scan_plugins.fileupload.scanner import FileUploadScanner
    scanner = FileUploadScanner(f"http://127.0.0.1:18888/upload")
    result = scanner.scan()
    assert result.success, f"FileUpload scan failed: {result.error_message}"
    assert result.plugin_name == "fileupload"
    print(f"  FileUpload: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_weakpass_scanner():
    from backend.vulnerability_scan_plugins.weakpass.scanner import WeakPassScanner
    scanner = WeakPassScanner(
        f"http://127.0.0.1:18888/login",
        config={"max_attempts": 10, "credential_pairs": [("admin", "admin")]}
    )
    result = scanner.scan()
    assert result.success, f"WeakPass scan failed: {result.error_message}"
    assert result.plugin_name == "weakpass"
    print(f"  WeakPass: success={result.success}, vulns={len(result.vulnerabilities)}, duration={result.scan_duration:.2f}s")


def test_toskill_sqli_wrapper():
    from TOSKill.tools.vuln_scan.sqli import sqli_scan
    result = sqli_scan(f"http://127.0.0.1:18888/sqli?id=1")
    assert result["success"], f"TOSKill sqli_scan failed: {result.get('error')}"
    print(f"  TOSKill SQLi: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_xss_wrapper():
    from TOSKill.tools.vuln_scan.xss import xss_scan
    result = xss_scan(f"http://127.0.0.1:18888/xss?name=test")
    assert result["success"], f"TOSKill xss_scan failed: {result.get('error')}"
    print(f"  TOSKill XSS: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_csrf_wrapper():
    from TOSKill.tools.vuln_scan.csrf import csrf_scan
    result = csrf_scan(f"http://127.0.0.1:18888/csrf")
    assert result["success"], f"TOSKill csrf_scan failed: {result.get('error')}"
    print(f"  TOSKill CSRF: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_cmdi_wrapper():
    from TOSKill.tools.vuln_scan.cmdi import cmdi_scan
    result = cmdi_scan(f"http://127.0.0.1:18888/cmdi?cmd=test")
    assert result["success"], f"TOSKill cmdi_scan failed: {result.get('error')}"
    print(f"  TOSKill CMDI: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_ssrf_wrapper():
    from TOSKill.tools.vuln_scan.ssrf import ssrf_scan
    result = ssrf_scan(f"http://127.0.0.1:18888/ssrf?url=http://example.com")
    assert result["success"], f"TOSKill ssrf_scan failed: {result.get('error')}"
    print(f"  TOSKill SSRF: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_lfi_wrapper():
    from TOSKill.tools.vuln_scan.lfi import lfi_scan
    result = lfi_scan(f"http://127.0.0.1:18888/lfi?file=test.txt")
    assert result["success"], f"TOSKill lfi_scan failed: {result.get('error')}"
    print(f"  TOSKill LFI: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_fileupload_wrapper():
    from TOSKill.tools.vuln_scan.fileupload import fileupload_scan
    result = fileupload_scan(f"http://127.0.0.1:18888/upload")
    assert result["success"], f"TOSKill fileupload_scan failed: {result.get('error')}"
    print(f"  TOSKill FileUpload: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_weakpass_wrapper():
    from TOSKill.tools.vuln_scan.weakpass import weakpass_scan
    result = weakpass_scan(
        f"http://127.0.0.1:18888/login",
        usernames=["admin"],
        passwords=["admin"],
        max_attempts=5
    )
    assert result["success"], f"TOSKill weakpass_scan failed: {result.get('error')}"
    print(f"  TOSKill WeakPass: success={result['success']}, vulns={result['data']['vulnerability_count']}")


def test_toskill_auth_params():
    from TOSKill.tools.vuln_scan.cmdi import cmdi_scan
    result = cmdi_scan(
        f"http://127.0.0.1:18888/cmdi?cmd=test",
        cookies={"session": "test123"},
        headers={"X-Custom": "value"},
        auth_token="Bearer test_token"
    )
    assert result["success"], f"TOSKill cmdi_scan with auth failed: {result.get('error')}"
    print(f"  TOSKill CMDI with auth: success={result['success']}")

    from TOSKill.tools.vuln_scan.ssrf import ssrf_scan
    result = ssrf_scan(
        f"http://127.0.0.1:18888/ssrf?url=http://example.com",
        cookies={"session": "test123"},
        auth_token="Bearer test_token"
    )
    assert result["success"], f"TOSKill ssrf_scan with auth failed: {result.get('error')}"
    print(f"  TOSKill SSRF with auth: success={result['success']}")

    from TOSKill.tools.vuln_scan.lfi import lfi_scan
    result = lfi_scan(
        f"http://127.0.0.1:18888/lfi?file=test.txt",
        headers={"X-Auth": "token123"}
    )
    assert result["success"], f"TOSKill lfi_scan with auth failed: {result.get('error')}"
    print(f"  TOSKill LFI with auth: success={result['success']}")


def test_plugin_manager_scan_single():
    from backend.vulnerability_scan_plugins.manager import PluginManager
    from backend.vulnerability_scan_plugins.sqli import SCANNER_CLASS as SqliClass

    pm = PluginManager()
    pm.register_plugin_class(SqliClass)

    result = pm.scan_single("sqli_scanner", f"http://127.0.0.1:18888/sqli?id=1")
    assert result.success, f"PluginManager scan_single failed: {result.error_message}"
    print(f"  PluginManager scan_single: success={result.success}, vulns={len(result.vulnerabilities)}")


def test_adapter_layer():
    import asyncio
    from backend.ai_agents.tools.adapters import PluginAdapter
    adapter = PluginAdapter()

    async def _run_adapter_tests():
        result = await adapter.adapt_sqli_scan(f"http://127.0.0.1:18888/sqli?id=1")
        assert result.is_success, f"PluginAdapter sqli_scan failed: {result.error}"
        vuln_count = 0
        if result.data and isinstance(result.data, dict):
            vuln_count = result.data.get('vulnerability_count', len(result.data.get('vulnerabilities', [])))
        print(f"  PluginAdapter SQLi: success={result.is_success}, vulns={vuln_count}")

        result = await adapter.adapt_xss_scan(f"http://127.0.0.1:18888/xss?name=test")
        assert result.is_success, f"PluginAdapter xss_scan failed: {result.error}"
        vuln_count = 0
        if result.data and isinstance(result.data, dict):
            vuln_count = result.data.get('vulnerability_count', len(result.data.get('vulnerabilities', [])))
        print(f"  PluginAdapter XSS: success={result.is_success}, vulns={vuln_count}")

    asyncio.run(_run_adapter_tests())


if __name__ == '__main__':
    print(f"\n{'#'*60}")
    print(f"  TOSKill 漏洞扫描器集成测试")
    print(f"{'#'*60}")

    print("\n[1/3] 启动模拟漏洞服务器...")
    port = start_vuln_server(18888)
    print(f"  服务器已启动: http://127.0.0.1:{port}")

    print("\n[2/3] 运行测试...")

    test("SCANNER_CLASS 导出一致性", test_scanner_class_exports)
    test("PluginManager 加载所有插件", test_plugin_manager_loading)

    test("Backend SQLi Scanner", test_sqli_scanner)
    test("Backend XSS Scanner", test_xss_scanner)
    test("Backend CSRF Scanner", test_csrf_scanner)
    test("Backend CMDI Scanner", test_cmdi_scanner)
    test("Backend SSRF Scanner", test_ssrf_scanner)
    test("Backend LFI Scanner", test_lfi_scanner)
    test("Backend FileUpload Scanner", test_fileupload_scanner)
    test("Backend WeakPass Scanner", test_weakpass_scanner)

    test("TOSKill SQLi Wrapper", test_toskill_sqli_wrapper)
    test("TOSKill XSS Wrapper", test_toskill_xss_wrapper)
    test("TOSKill CSRF Wrapper", test_toskill_csrf_wrapper)
    test("TOSKill CMDI Wrapper", test_toskill_cmdi_wrapper)
    test("TOSKill SSRF Wrapper", test_toskill_ssrf_wrapper)
    test("TOSKill LFI Wrapper", test_toskill_lfi_wrapper)
    test("TOSKill FileUpload Wrapper", test_toskill_fileupload_wrapper)
    test("TOSKill WeakPass Wrapper", test_toskill_weakpass_wrapper)

    test("TOSKill 认证参数传递", test_toskill_auth_params)
    test("PluginManager scan_single", test_plugin_manager_scan_single)
    test("AI Agent Adapter Layer", test_adapter_layer)

    print("\n[3/3] 停止模拟服务器...")
    stop_vuln_server()

    print(f"\n{'#'*60}")
    print(f"  测试结果汇总")
    print(f"{'#'*60}")
    print(f"  通过: {PASS_COUNT}")
    print(f"  失败: {FAIL_COUNT}")
    print(f"  总计: {PASS_COUNT + FAIL_COUNT}")

    if ERRORS:
        print(f"\n{'='*60}")
        print(f"  失败详情")
        print(f"{'='*60}")
        for name, error in ERRORS:
            print(f"\n  ❌ {name}:")
            print(f"     {error[:200]}")

    print(f"\n{'='*60}")
    if FAIL_COUNT == 0:
        print(f"  🎉 所有测试通过!")
    else:
        print(f"  ⚠️  有 {FAIL_COUNT} 个测试失败")
    print(f"{'='*60}\n")

    sys.exit(0 if FAIL_COUNT == 0 else 1)
