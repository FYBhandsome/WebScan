import os

import pytest

from TOSKill.tools.vuln_scan.sqli import sqli_scan
from TOSKill.tools.vuln_scan.xss import xss_scan
from TOSKill.tools.vuln_scan.lfi import lfi_scan
from TOSKill.tools.vuln_scan.cmdi import cmdi_scan
from TOSKill.tools.vuln_scan.ssrf import ssrf_scan


RUN_PUBLIC = os.getenv("RUN_PUBLIC_VULN_TARGETS") == "1"

PUBLIC_TARGETS = [
    "http://testphp.vulnweb.com",
    "http://testasp.vulnweb.com",
    "https://demo.testfire.net",
]


@pytest.mark.skipif(not RUN_PUBLIC, reason="public demo targets are opt-in")
@pytest.mark.parametrize("target", PUBLIC_TARGETS)
def test_public_demo_target_smoke(target):
    # Minimal smoke coverage only. Use RUN_PUBLIC_VULN_TARGETS=1 to enable.
    assert target.startswith(("http://", "https://"))


@pytest.mark.skipif(not RUN_PUBLIC, reason="public demo targets are opt-in")
@pytest.mark.parametrize(
    "scanner,target,kwargs",
    [
        (sqli_scan, "http://testphp.vulnweb.com/artists.php?artist=1", {"timeout": 5, "max_payloads": 10}),
        (xss_scan, "http://testphp.vulnweb.com/search.php?test=query", {"timeout": 5, "max_payloads": 10}),
        (lfi_scan, "http://testphp.vulnweb.com/showimage.php?file=", {"timeout": 5}),
        (cmdi_scan, "http://testasp.vulnweb.com/cmd.asp?cmd=test", {"timeout": 5}),
        (ssrf_scan, "http://testasp.vulnweb.com/ssrf?url=http://example.com", {"timeout": 5}),
    ],
)
def test_public_demo_target_scanners(scanner, target, kwargs):
    result = scanner(target, **kwargs)
    assert isinstance(result, dict)
    assert "success" in result
