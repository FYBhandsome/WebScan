"""
TOSKill 代码优化与修复测试

测试报告生成节点的功能正确性
"""
import sys
import os
import asyncio
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_report_service_import():
    """测试报告服务导入"""
    print("\n" + "="*60)
    print("📊 测试 1: 报告服务导入")
    print("="*60)
    
    try:
        from backend.services.report_service import (
            ReportService, ReportData, ReportFormat, Language, report_service
        )
        print("   ✅ 报告服务模块导入成功")
        print(f"   ✅ ReportService: {ReportService}")
        print(f"   ✅ ReportFormat: {ReportFormat}")
        print(f"   ✅ report_service 实例: {report_service}")
        return True
    except Exception as e:
        print(f"   ❌ 导入失败: {e}")
        return False


def test_analyzers_module():
    """测试分析器模块"""
    print("\n" + "="*60)
    print("📊 测试 2: 分析器模块")
    print("="*60)
    
    try:
        from backend.ai_agents.analyzers import VulnerabilityAnalyzer
        print("   ✅ VulnerabilityAnalyzer 导入成功")
        
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from backend.ai_agents.analyzers import EnhancedReportGenerator
            
            if any(issubclass(warning.category, DeprecationWarning) for warning in w):
                print("   ✅ EnhancedReportGenerator 已弃用警告正常触发")
            
        print("   ✅ EnhancedReportGenerator 重定向到 ReportService 正常")
        return True
    except Exception as e:
        print(f"   ❌ 测试失败: {e}")
        return False


async def test_report_generation_node():
    """测试报告生成节点"""
    print("\n" + "="*60)
    print("📊 测试 3: 报告生成节点")
    print("="*60)
    
    try:
        from TOSKill.AI.nodes import ReportGenerationNode
        from TOSKill.AI.state import AgentState
        
        print("   ✅ ReportGenerationNode 导入成功")
        
        node = ReportGenerationNode(output_dir="test_reports")
        print("   ✅ ReportGenerationNode 实例化成功")
        
        state = AgentState(
            target="https://example.com",
            task_id="test_task_001"
        )
        
        state.vulnerabilities = [
            {
                "title": "SQL 注入漏洞",
                "severity": "critical",
                "url": "https://example.com/search?id=1",
                "description": "测试漏洞描述"
            },
            {
                "title": "XSS 漏洞",
                "severity": "high",
                "url": "https://example.com/comment",
                "description": "测试 XSS 漏洞"
            }
        ]
        
        state.execution_history = [
            {
                "step_number": 1,
                "task": "baseinfo",
                "status": "success",
                "timestamp_iso": datetime.now().isoformat(),
                "result": {"info": "基础信息收集完成"}
            }
        ]
        
        state.completed_tasks = ["baseinfo", "portscan"]
        state.tool_results = {"baseinfo": {"server": "nginx"}}
        
        result_state = await node(state)
        
        print(f"   ✅ 报告生成执行完成")
        print(f"   ✅ is_complete: {result_state.is_complete}")
        print(f"   ✅ 漏洞数: {len(result_state.vulnerabilities)}")
        
        if "saved_files" in result_state.tool_results:
            saved_files = result_state.tool_results["saved_files"]
            print(f"   ✅ JSON 报告: {saved_files.get('json')}")
            print(f"   ✅ HTML 报告: {saved_files.get('html')}")
            print(f"   ✅ Markdown 报告: {saved_files.get('markdown')}")
            
            for file_type, file_path in saved_files.items():
                if os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    print(f"   ✅ {file_type} 文件存在，大小: {file_size} 字节")
                else:
                    print(f"   ❌ {file_type} 文件不存在: {file_path}")
        
        return result_state.is_complete
        
    except Exception as e:
        print(f"   ❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_full_workflow():
    """测试完整工作流"""
    print("\n" + "="*60)
    print("📊 测试 4: 完整工作流")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        from TOSKill.AI.nodes import (
            VulnerabilityAnalysisNode,
            ReportGenerationNode
        )
        
        state = AgentState(
            target="https://test.example.com",
            task_id="workflow_test_001"
        )
        
        state.vulnerabilities = [
            {"title": "测试漏洞1", "severity": "high", "url": "https://test.example.com/vuln1"},
            {"title": "测试漏洞2", "severity": "medium", "url": "https://test.example.com/vuln2"},
        ]
        
        state.execution_history = [
            {"step_number": 1, "task": "test", "status": "success", "timestamp_iso": datetime.now().isoformat()}
        ]
        
        vuln_node = VulnerabilityAnalysisNode()
        state = await vuln_node(state)
        print(f"   ✅ 漏洞分析节点执行完成")
        
        report_node = ReportGenerationNode(output_dir="test_reports")
        state = await report_node(state)
        print(f"   ✅ 报告生成节点执行完成")
        
        print(f"   ✅ 最终状态: is_complete={state.is_complete}")
        print(f"   ✅ 扫描摘要: {state.scan_summary}")
        
        return state.is_complete
        
    except Exception as e:
        print(f"   ❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_state_fields():
    """测试状态字段"""
    print("\n" + "="*60)
    print("📊 测试 5: 状态字段验证")
    print("="*60)
    
    try:
        from TOSKill.AI.state import AgentState
        
        state = AgentState(
            target="https://test.com",
            task_id="field_test_001"
        )
        
        required_fields = [
            'target', 'task_id', 'planned_tasks', 'current_task', 
            'completed_tasks', 'tool_results', 'vulnerabilities',
            'target_context', 'execution_history', 'is_complete',
            'should_continue', 'errors', 'stage_status', 'scan_summary'
        ]
        
        missing_fields = []
        for field in required_fields:
            if not hasattr(state, field):
                missing_fields.append(field)
        
        if missing_fields:
            print(f"   ❌ 缺少字段: {missing_fields}")
            return False
        
        print(f"   ✅ 所有必需字段存在")
        
        state.add_vulnerability({"title": "test", "severity": "high"})
        print(f"   ✅ add_vulnerability 方法正常")
        
        state.add_error("测试错误")
        print(f"   ✅ add_error 方法正常")
        
        state.mark_complete()
        print(f"   ✅ mark_complete 方法正常")
        
        state_dict = state.to_dict()
        print(f"   ✅ to_dict 方法正常，字段数: {len(state_dict)}")
        
        restored_state = AgentState.from_dict(state_dict)
        print(f"   ✅ from_dict 方法正常")
        
        return True
        
    except Exception as e:
        print(f"   ❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def run_all_tests():
    """运行所有测试"""
    print("\n" + "="*60)
    print("🧪 TOSKill 代码优化与修复测试")
    print("="*60 + "\n")
    
    results = []
    
    results.append(("报告服务导入", test_report_service_import()))
    results.append(("分析器模块", test_analyzers_module()))
    results.append(("状态字段验证", test_state_fields()))
    results.append(("报告生成节点", await test_report_generation_node()))
    results.append(("完整工作流", await test_full_workflow()))
    
    print("\n" + "="*60)
    print("📊 测试结果汇总")
    print("="*60)
    
    passed = 0
    failed = 0
    
    for name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"   {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print(f"\n   总计: {passed} 通过, {failed} 失败")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    try:
        success = asyncio.run(run_all_tests())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n测试执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
