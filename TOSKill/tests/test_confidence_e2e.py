# -*- coding:utf-8 -*-
"""
AI等保评估置信度模块 - 端到端验证脚本

验证项：
  1. 导入链完整性
  2. _convert_confidence 容错转换（Bug#6）
  3. _parse_confidence_json 三级解析（缺陷#2）
  4. RAG MLPS 检索与降级（Bug#7）
  5. _render_confidence_html 渲染
  6. ScanState.scan_mode 字段（Bug#5）
  7. 置信度失败不中断报告（Bug#3）
"""
import sys
import os
import asyncio
import json

# 确保项目根目录在路径中
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.dirname(project_root))

results = []

def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    results.append((name, passed, detail))
    print(f"  [{status}] {name}" + (f" - {detail}" if detail else ""))


print("=" * 60)
print("AI等保评估置信度模块 - 端到端验证")
print("=" * 60)

# ==================== 1. 导入链验证 ====================
print("\n--- 1. 导入链验证 ---")

try:
    from TOSKill.AI.state import ScanState, create_initial_state
    record("state.py 导入", True)
except Exception as e:
    record("state.py 导入", False, str(e))

try:
    from TOSKill.config import settings
    has_enabled = hasattr(settings, "CONFIDENCE_ASSESSMENT_ENABLED")
    has_timeout = hasattr(settings, "CONFIDENCE_AI_TIMEOUT")
    has_level = hasattr(settings, "MLPS_STANDARD_LEVEL")
    record("config.py 置信度配置项", has_enabled and has_timeout and has_level,
          f"ENABLED={getattr(settings,'CONFIDENCE_ASSESSMENT_ENABLED','?')}, "
          f"TIMEOUT={getattr(settings,'CONFIDENCE_AI_TIMEOUT','?')}, "
          f"LEVEL={getattr(settings,'MLPS_STANDARD_LEVEL','?')}")
except Exception as e:
    record("config.py 置信度配置项", False, str(e))

try:
    from TOSKill.tools.report.confidence_assessor import ConfidenceAssessor, get_confidence_assessor
    record("confidence_assessor.py 导入", True)
except Exception as e:
    record("confidence_assessor.py 导入", False, str(e))

try:
    from TOSKill.RAG.rag_engine import MLPS_VULN_MAPPING, MLPS_SCENARIO_KEYWORDS
    has_sqli = "sqli" in MLPS_VULN_MAPPING
    has_keywords = "confidence_assessment" in MLPS_SCENARIO_KEYWORDS
    record("rag_engine.py MLPS常量", has_sqli and has_keywords,
          f"VULN_MAPPING={len(MLPS_VULN_MAPPING)}类, SCENARIO={len(MLPS_SCENARIO_KEYWORDS)}组")
except Exception as e:
    record("rag_engine.py MLPS常量", False, str(e))

try:
    from TOSKill.RAG.retriever import get_mlps_assessment_context, get_confidence_rules, get_kb_version
    record("retriever.py MLPS函数", True)
except Exception as e:
    record("retriever.py MLPS函数", False, str(e))

try:
    from TOSKill.tools.report.html_report_generator import HTMLReportGenerator
    has_method = hasattr(HTMLReportGenerator, "_convert_confidence")
    record("html_report_generator.py _convert_confidence", has_method)
except Exception as e:
    record("html_report_generator.py _convert_confidence", False, str(e))

try:
    from TOSKill.tools.report.report_manager import ReportManager
    has_method = hasattr(ReportManager, "generate_confidence_async")
    record("report_manager.py generate_confidence_async", has_method)
except Exception as e:
    record("report_manager.py generate_confidence_async", False, str(e))

try:
    from backend.services.report_service import ConfidenceData, ConfidenceDimension
    record("report_service.py ConfidenceData导入", True)
except Exception as e:
    record("report_service.py ConfidenceData导入", False, str(e))


# ==================== 2. _convert_confidence 容错验证（Bug#6） ====================
print("\n--- 2. _convert_confidence 容错验证（Bug#6） ---")

try:
    from TOSKill.tools.report.html_report_generator import HTMLReportGenerator

    # 测试1：完整数据
    full_data = {
        "overall_score": 87,
        "level": "high",
        "standard_text": "基于等保2.0三级标准",
        "kb_version": "v2.17.20260806",
        "dimensions": [
            {"label": "漏洞检测准确性", "value": 92},
            {"label": "等保控制项映射准确度", "value": 88},
            {"label": "风险等级判定一致性", "value": 85},
            {"label": "整改方案合规性", "value": 82},
        ],
        "compliance_estimate": 72,
        "compliance_margin": "±5%",
        "kb_refs": "15_mlps_standard,16_mlps_vuln_mapping",
        "scan_mode": "人机交互",
        "note": "评估说明文字",
    }
    cd = HTMLReportGenerator._convert_confidence(full_data)
    record("完整数据转换", cd.overall_score == 87 and cd.level == "high" and len(cd.dimensions) == 4,
          f"score={cd.overall_score}, level={cd.level}, dims={len(cd.dimensions)}")

    # 测试2：缺失dimensions字段
    no_dims = {"overall_score": 70, "level": "mid"}
    cd2 = HTMLReportGenerator._convert_confidence(no_dims)
    record("缺失dimensions容错", cd2.overall_score == 70 and cd2.level == "mid" and len(cd2.dimensions) == 0,
          f"dims={len(cd2.dimensions)}")

    # 测试3：overall_score为字符串
    str_score = {"overall_score": "85", "level": "high", "dimensions": [{"label": "test", "value": "90"}]}
    cd3 = HTMLReportGenerator._convert_confidence(str_score)
    record("字符串数值容错", cd3.overall_score == 85.0 and cd3.dimensions[0].value == 90.0,
          f"score={cd3.overall_score}, dim0={cd3.dimensions[0].value}")

    # 测试4：level为非法值（自动推导）
    bad_level = {"overall_score": 85, "level": "unknown"}
    cd4 = HTMLReportGenerator._convert_confidence(bad_level)
    record("非法level自动推导", cd4.level == "high", f"level={cd4.level}")

    # 测试5：overall_score为None
    none_score = {"overall_score": None, "level": ""}
    cd5 = HTMLReportGenerator._convert_confidence(none_score)
    record("None值容错", cd5.overall_score == 0.0 and cd5.level == "info",
          f"score={cd5.overall_score}, level={cd5.level}")

    # 测试6：value超出范围（自动clamp）
    over_range = {"overall_score": 150, "level": "high", "dimensions": [{"label": "x", "value": -10}]}
    cd6 = HTMLReportGenerator._convert_confidence(over_range)
    record("数值范围clamp", cd6.overall_score == 100.0 and cd6.dimensions[0].value == 0.0,
          f"score={cd6.overall_score}, dim0={cd6.dimensions[0].value}")

except Exception as e:
    record("_convert_confidence 容错验证", False, str(e))


# ==================== 3. _parse_confidence_json 三级解析验证（缺陷#2） ====================
print("\n--- 3. _parse_confidence_json 三级解析验证（缺陷#2） ---")

try:
    from TOSKill.tools.report.confidence_assessor import ConfidenceAssessor

    # 测试1：纯JSON
    pure_json = '{"overall_score": 87, "level": "high"}'
    r1 = ConfidenceAssessor._parse_confidence_json(pure_json)
    record("纯JSON解析", r1["overall_score"] == 87, f"score={r1['overall_score']}")

    # 测试2：markdown代码块包裹
    md_json = '```json\n{"overall_score": 75, "level": "mid"}\n```'
    r2 = ConfidenceAssessor._parse_confidence_json(md_json)
    record("markdown代码块解析", r2["overall_score"] == 75, f"score={r2['overall_score']}")

    # 测试3：前后有额外文字
    extra_text = '好的，以下是评估结果：\n{"overall_score": 60, "level": "mid"}\n以上是评估。'
    r3 = ConfidenceAssessor._parse_confidence_json(extra_text)
    record("前后额外文字解析", r3["overall_score"] == 60, f"score={r3['overall_score']}")

    # 测试4：嵌套JSON对象
    nested_json = '{"overall_score": 80, "level": "high", "dimensions": [{"label": "test", "value": 85}]}'
    r4 = ConfidenceAssessor._parse_confidence_json(nested_json)
    record("嵌套JSON解析", r4["overall_score"] == 80 and len(r4["dimensions"]) == 1,
          f"score={r4['overall_score']}, dims={len(r4.get('dimensions', []))}")

    # 测试5：完全无效输入（降级默认值）
    invalid = '这不是JSON格式的内容'
    r5 = ConfidenceAssessor._parse_confidence_json(invalid)
    record("无效输入降级默认值", r5["overall_score"] == 0 and r5["level"] == "info",
          f"score={r5['overall_score']}, level={r5['level']}")

except Exception as e:
    record("_parse_confidence_json 三级解析", False, str(e))


# ==================== 4. RAG MLPS 检索与降级验证（Bug#7） ====================
print("\n--- 4. RAG MLPS 检索与降级验证（Bug#7） ---")

try:
    from TOSKill.RAG.rag_engine import TOSKillRAGEngine, MLPS_VULN_MAPPING, MLPS_SCENARIO_KEYWORDS

    # 测试1：_build_mlps_query 构建查询
    engine = TOSKillRAGEngine.__new__(TOSKillRAGEngine)
    engine._query_cache = {}
    engine._total_queries = 0
    engine._cache_hits = 0

    vulns = [
        {"type": "sqli", "severity": "high"},
        {"type": "xss", "severity": "medium"},
    ]
    tools = {"sqli_scan": {"vulnerable": True}, "xss_scan": {"vulnerable": True}}
    query = engine._build_mlps_query(vulns, tools)
    has_sqli_kw = "SQL注入" in query
    has_xss_kw = "XSS" in query
    has_conf_kw = "置信度评估" in query
    record("_build_mlps_query 查询构建", has_sqli_kw and has_xss_kw and has_conf_kw,
          f"query长度={len(query)}, 含SQL注入={has_sqli_kw}, 含XSS={has_xss_kw}")

    # 测试2：_retrieve_mlps_keyword_fallback 降级检索
    fallback_result = engine._retrieve_mlps_keyword_fallback(vulns)
    has_content = len(fallback_result) > 0
    record("_retrieve_mlps_keyword_fallback 降级检索", has_content,
          f"结果长度={len(fallback_result)}")

    # 测试3：retrieve_mlps_context RAG未就绪降级（retriever=None）
    engine.retriever = None
    result = engine.retrieve_mlps_context("http://test.com", vulns, tools)
    # 检查是否返回了关键词降级结果（而非抛异常）
    no_exception = True
    record("retrieve_mlps_context RAG未就绪降级", no_exception and isinstance(result, str),
          f"返回类型={type(result).__name__}, 长度={len(result)}")

    # 测试4：get_kb_version 从manifest读取
    version = engine.get_kb_version()
    has_version = len(version) > 0
    record("get_kb_version 版本读取", has_version, f"version={version}")

except Exception as e:
    record("RAG MLPS 检索与降级", False, str(e))


# ==================== 5. _render_confidence_html 渲染验证 ====================
print("\n--- 5. _render_confidence_html 渲染验证 ---")

try:
    from backend.services.report_service import ReportService, ConfidenceData, ConfidenceDimension

    rs = ReportService.__new__(ReportService)

    # 测试1：完整数据渲染
    cd = ConfidenceData(
        overall_score=87,
        level="high",
        standard_text="基于等保2.0三级标准",
        kb_version="v2.17.20260806",
        dimensions=[
            ConfidenceDimension(label="漏洞检测准确性", value=92),
            ConfidenceDimension(label="等保控制项映射准确度", value=88),
            ConfidenceDimension(label="风险等级判定一致性", value=85),
            ConfidenceDimension(label="整改方案合规性", value=82),
        ],
        compliance_estimate=72,
        compliance_margin="±5%",
        kb_refs="15_mlps_standard,16_mlps_vuln_mapping",
        scan_mode="人机交互",
        note="本置信度由AI综合漏洞扫描结果与等保2.0知识库进行多维匹配得出。",
    )
    # 获取language和labels参数
    from backend.services.report_service import Language
    language = Language.ZH_CN
    labels = {
        "confidence_title": "AI等保评估置信度",
        "confidence_placeholder": "AI等保评估置信度模块尚在规则接入中，暂未生成置信度数据。",
        "confidence_level_high": "高置信度",
        "confidence_level_mid": "中置信度",
        "confidence_level_low": "低置信度",
        "confidence_level_info": "待评估",
        "confidence_kb_version": "知识库版本",
        "confidence_overall": "综合置信度",
        "confidence_note_title": "评估说明",
        "confidence_kb_ref": "等保2.0知识库",
        "compliance_estimate": "符合度预估",
        "kb_refs": "知识库检索条目",
        "scan_mode": "扫描模式",
    }
    html = rs._render_confidence_html(cd, language, labels)
    has_module = "confidence-module" in html
    has_score = "87" in html
    has_level = "高置信度" in html or "high" in html.lower()
    has_dims = "漏洞检测准确性" in html
    record("完整数据HTML渲染", has_module and has_score and has_dims,
          f"HTML长度={len(html)}, 含模块={has_module}, 含分数={has_score}")

    # 测试2：占位渲染（confidence=None）
    placeholder_html = rs._render_confidence_html(None, language, labels)
    has_placeholder = "confidence-placeholder" in placeholder_html or "暂未生成" in placeholder_html
    record("None占位渲染", has_placeholder, f"HTML长度={len(placeholder_html)}")

    # 测试3：空dimensions渲染
    cd_empty = ConfidenceData(
        overall_score=0,
        level="info",
        standard_text="",
        kb_version="",
        dimensions=[],
        compliance_estimate=0,
        compliance_margin="",
        kb_refs="",
        scan_mode="",
        note="评估数据不足",
    )
    html_empty = rs._render_confidence_html(cd_empty, language, labels)
    no_crash = len(html_empty) > 0
    record("空数据不崩溃", no_crash, f"HTML长度={len(html_empty)}")

except Exception as e:
    record("_render_confidence_html 渲染", False, str(e))


# ==================== 6. ScanState.scan_mode 字段验证（Bug#5） ====================
print("\n--- 6. ScanState.scan_mode 字段验证（Bug#5） ---")

try:
    from TOSKill.AI.state import ScanState, create_initial_state

    # 测试1：create_initial_state 包含 scan_mode
    state = create_initial_state("http://test.com")
    has_scan_mode = "scan_mode" in state
    is_default = state.get("scan_mode") == "人机交互"
    record("create_initial_state 含scan_mode", has_scan_mode and is_default,
          f"scan_mode={state.get('scan_mode', 'MISSING')}")

    # 测试2：scan_mode可被覆盖
    state2 = ScanState(target="http://test.com", scan_mode="全自动")
    record("scan_mode可覆盖", state2.get("scan_mode") == "全自动",
          f"scan_mode={state2.get('scan_mode')}")

except Exception as e:
    record("ScanState.scan_mode 字段", False, str(e))


# ==================== 7. 置信度失败不中断报告验证（Bug#3） ====================
print("\n--- 7. 置信度失败不中断报告验证（Bug#3） ---")

try:
    from TOSKill.tools.report.report_manager import ReportManager
    import inspect

    # 验证 generate_confidence_async 有异常处理
    source = inspect.getsource(ReportManager.generate_confidence_async)
    has_try = "try:" in source
    has_except = "except Exception" in source
    has_return_none = "return None" in source
    record("generate_confidence_async 异常处理", has_try and has_except and has_return_none,
          f"try={has_try}, except={has_except}, return_None={has_return_none}")

    # 验证是async方法
    is_async = inspect.iscoroutinefunction(ReportManager.generate_confidence_async)
    record("generate_confidence_async 是async", is_async)

except Exception as e:
    record("置信度失败不中断报告", False, str(e))


# ==================== 8. 完整数据流模拟 ====================
print("\n--- 8. 完整数据流模拟 ---")

try:
    from TOSKill.tools.report.html_report_generator import HTMLReportGenerator

    # 模拟LLM返回的置信度dict
    confidence_dict = {
        "overall_score": 85,
        "level": "high",
        "standard_text": "基于等保2.0（GB/T 22239-2019）三级标准",
        "kb_version": "v2.17.20260806",
        "dimensions": [
            {"label": "漏洞检测准确性", "value": 90},
            {"label": "等保控制项映射准确度", "value": 85},
            {"label": "风险等级判定一致性", "value": 82},
            {"label": "整改方案合规性", "value": 80},
        ],
        "compliance_estimate": 75,
        "compliance_margin": "±5%",
        "kb_refs": "15_mlps_standard,16_mlps_vuln_mapping",
        "scan_mode": "人机交互",
        "note": "本置信度由AI综合漏洞扫描结果与等保2.0知识库进行多维匹配得出。",
    }

    # dict → ConfidenceData
    cd = HTMLReportGenerator._convert_confidence(confidence_dict)
    record("dict→ConfidenceData转换", cd.overall_score == 85 and len(cd.dimensions) == 4,
          f"score={cd.overall_score}, dims={len(cd.dimensions)}")

    # ConfidenceData → HTML渲染
    from backend.services.report_service import ReportService, Language
    rs = ReportService.__new__(ReportService)
    test_labels = {
        "confidence_title": "AI等保评估置信度",
        "confidence_placeholder": "AI等保评估置信度模块尚在规则接入中，暂未生成置信度数据。",
        "confidence_level_high": "高置信度",
        "confidence_level_mid": "中置信度",
        "confidence_level_low": "低置信度",
        "confidence_level_info": "待评估",
        "confidence_kb_version": "知识库版本",
        "confidence_overall": "综合置信度",
        "confidence_note_title": "评估说明",
        "confidence_kb_ref": "等保2.0知识库",
        "compliance_estimate": "符合度预估",
        "kb_refs": "知识库检索条目",
        "scan_mode": "扫描模式",
    }
    html = rs._render_confidence_html(cd, Language.ZH_CN, test_labels)
    record("ConfidenceData→HTML渲染", "confidence-module" in html and "85" in html,
          f"HTML长度={len(html)}")

    # 空dict → 占位渲染
    cd_none = HTMLReportGenerator._convert_confidence({"overall_score": 0, "level": "info"})
    html_placeholder = rs._render_confidence_html(cd_none, Language.ZH_CN, test_labels)
    record("空数据→占位渲染", len(html_placeholder) > 0, f"HTML长度={len(html_placeholder)}")

except Exception as e:
    record("完整数据流模拟", False, str(e))


# ==================== 汇总 ====================
print("\n" + "=" * 60)
total = len(results)
passed = sum(1 for _, p, _ in results if p)
failed = total - passed
print(f"验证汇总: {passed}/{total} 通过, {failed} 失败")
print("=" * 60)

if failed > 0:
    print("\n失败项:")
    for name, p, detail in results:
        if not p:
            print(f"  [FAIL] {name} - {detail}")
sys.exit(0 if failed == 0 else 1)
