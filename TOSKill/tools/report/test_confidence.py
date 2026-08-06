# -*- coding:utf-8 -*-
"""
置信度计算模块 (confidence_calculator) 自测脚本 —— Task 7

验证项：
  SubTask 7.1: 置信度输出始终在 0-100 范围内
  SubTask 7.2: 四维加权求和 = total（kb_match*0.6 + coverage*0.2 + consistency*0.1 + completeness*0.1）
"""

import sys
import traceback

sys.path.insert(0, r"d:\AI_WebSecurity")

from TOSKill.tools.report.confidence_calculator import calculate_confidence

# =====================================================================
# 辅助
# =====================================================================
PASS = 0
FAIL = 0


def _assert(condition: bool, label: str):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}")


# =====================================================================
# 测试用例数据
# =====================================================================

# --- 1. 正常输入：有完成的任务、有漏洞（字段完整）---
normal_state = {
    "completed_tasks": ["port_scan", "dir_brute", "vuln_scan"],
    "planned_tasks": ["port_scan", "dir_brute", "vuln_scan", "sql_injection"],
    "decision_history": ["d1", "d2", "d3"],
    "execution_history": [
        {"success": True},
        {"success": True},
        {"success": False},
    ],
    "mode": "full_scan",
}
normal_vulns = [
    {
        "type": "SQL注入",
        "severity": "high",
        "url": "http://example.com/login",
        "description": "存在SQL注入漏洞",
    },
    {
        "type": "XSS",
        "severity": "medium",
        "url": "http://example.com/search",
        "description": "反射型XSS",
    },
]
normal_rag = "根据知识库来源分析，该系统存在多种漏洞风险，建议进行扫描检测。策略上应优先修复高危漏洞。" + "A" * 200

# --- 2. 空输入 ---
empty_state = {}
empty_vulns = []

# --- 3. None 输入 ---
none_state = None
none_vulns = None
none_rag = None

# --- 4. 有 rag_result vs 无 rag_result ---
no_rag = None
short_rag = "短文本"
long_rag = "来源：知识库。建议进行漏洞扫描，检测安全问题。策略为优先修复高危漏洞。" + "B" * 300

# --- 5. 极端：大量漏洞 ---
extreme_vulns = [
    {
        "type": f"vuln_type_{i}",
        "severity": "low",
        "url": f"http://example.com/path{i}",
        "description": f"漏洞描述 {i}",
    }
    for i in range(500)
]

# --- 6. 部分字段缺失的漏洞 ---
partial_vulns = [
    {"type": "SQL注入"},  # 缺 severity, url, description
    {"severity": "high"},  # 缺 type, url, description
    {"url": "http://x.com", "description": "test"},  # 缺 type, severity
    {"type": "XSS", "severity": "medium", "url": "http://y.com", "description": "完整"},  # 完整
]

# --- 7. planned_tasks 全部完成 ---
full_cover_state = {
    "completed_tasks": ["a", "b", "c"],
    "planned_tasks": ["a", "b", "c"],
    "decision_history": ["d1"],
    "execution_history": [{"success": True}],
    "mode": "fast",
}

# --- 8. decision_history 非空但 execution_history 全失败 ---
all_fail_state = {
    "decision_history": ["d1", "d2", "d3"],
    "execution_history": [{"success": False}, {"success": False}],
}

# --- 9. vulnerabilities 里有非字典条目 ---
mixed_vulns = [
    "not_a_dict",
    {"type": "SQL注入", "severity": "high", "url": "http://a.com", "description": "desc"},
    None,
]


# =====================================================================
# SubTask 7.1: 置信度输出始终在 0-100 范围内
# =====================================================================
def test_subtask_7_1():
    print("\n===== SubTask 7.1: 置信度输出在 0-100 范围内 =====")

    test_cases = [
        ("正常输入(有rag)", normal_state, normal_vulns, normal_rag),
        ("正常输入(无rag)", normal_state, normal_vulns, None),
        ("空 state + 空 vulns", empty_state, empty_vulns, None),
        ("空 state + 空 vulns + 短 rag", empty_state, empty_vulns, short_rag),
        ("None state", none_state, normal_vulns, None),
        ("None vulns", normal_state, none_vulns, None),
        ("None state + None vulns + None rag", none_state, none_vulns, none_rag),
        ("长 rag 文本", normal_state, normal_vulns, long_rag),
        ("极端大量漏洞", normal_state, extreme_vulns, None),
        ("部分字段缺失漏洞", normal_state, partial_vulns, None),
        ("全覆盖状态", full_cover_state, normal_vulns, None),
        ("全失败执行历史", all_fail_state, normal_vulns, None),
        ("混合漏洞列表(含非字典)", normal_state, mixed_vulns, None),
    ]

    for label, state, vulns, rag in test_cases:
        try:
            result = calculate_confidence(state, vulns, rag)
            total = result["total"]
            bd = result["breakdown"]
            in_range = 0 <= total <= 100
            _assert(in_range, f"{label} -> total={total} 在 [0,100] 内")

            # 检查各子分也在 0-100 内
            for key in ("kb_match", "coverage", "consistency", "completeness"):
                sub = bd[key]
                sub_ok = 0 <= sub <= 100
                _assert(sub_ok, f"{label} -> breakdown.{key}={sub} 在 [0,100] 内")
        except Exception as e:
            _assert(False, f"{label} -> 抛出异常: {e}")
            traceback.print_exc()


# =====================================================================
# SubTask 7.2: 四维加权求和 = total
# =====================================================================
def test_subtask_7_2():
    print("\n===== SubTask 7.2: 四维加权求和验证 =====")

    test_cases = [
        ("正常输入(有rag)", normal_state, normal_vulns, normal_rag),
        ("正常输入(无rag)", normal_state, normal_vulns, None),
        ("空 state + 空 vulns", empty_state, empty_vulns, None),
        ("None state", none_state, normal_vulns, None),
        ("None vulns", normal_state, none_vulns, None),
        ("None state + None vulns + None rag", none_state, none_vulns, none_rag),
        ("长 rag 文本", normal_state, normal_vulns, long_rag),
        ("极端大量漏洞", normal_state, extreme_vulns, None),
        ("部分字段缺失漏洞", normal_state, partial_vulns, None),
        ("全覆盖状态", full_cover_state, normal_vulns, None),
        ("全失败执行历史", all_fail_state, normal_vulns, None),
        ("混合漏洞列表(含非字典)", normal_state, mixed_vulns, None),
    ]

    for label, state, vulns, rag in test_cases:
        try:
            result = calculate_confidence(state, vulns, rag)
            total = result["total"]
            bd = result["breakdown"]

            # 加权计算（使用 int() 截断，与源码一致）
            weighted = int(
                bd["kb_match"] * 0.6
                + bd["coverage"] * 0.2
                + bd["consistency"] * 0.1
                + bd["completeness"] * 0.1
            )
            weighted = max(0, min(100, weighted))

            _assert(
                total == weighted,
                f"{label} -> total={total}, weighted={weighted} (kb={bd['kb_match']} cov={bd['coverage']} con={bd['consistency']} comp={bd['completeness']})",
            )
        except Exception as e:
            _assert(False, f"{label} -> 抛出异常: {e}")
            traceback.print_exc()


# =====================================================================
# 主流程
# =====================================================================
if __name__ == "__main__":
    test_subtask_7_1()
    test_subtask_7_2()

    print(f"\n===== 测试结果汇总 =====")
    print(f"通过: {PASS}")
    print(f"失败: {FAIL}")
    print(f"总计: {PASS + FAIL}")
    if FAIL == 0:
        print("所有测试通过！")
    else:
        print("存在失败测试，请检查上方输出。")
