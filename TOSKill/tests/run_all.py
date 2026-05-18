"""
TOSKill 统一测试入口
运行所有测试套件，分阶段执行
"""
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent

TEST_MODULES = [
    ("test_rag.py", "RAG引擎测试"),
    ("test_llm_client.py", "LLM客户端测试"),
    ("test_script_safety.py", "脚本安全审查测试"),
    ("test_tools.py", "工具注册测试"),
    ("test_graph_workflow.py", "工作流集成测试"),
    ("test_api.py", "API接口测试"),
    ("test_websocket.py", "WebSocket测试"),
    ("test_stress.py", "压力测试"),
]


def run_test(module: str, name: str) -> bool:
    """运行单个测试模块"""
    print(f"\n{'='*60}")
    print(f"  开始执行: {name} ({module})")
    print(f"{'='*60}")
    
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(BASE_DIR / module), "-v", "--tb=short"],
        capture_output=False,
        cwd=str(BASE_DIR.parent.parent)
    )
    return result.returncode == 0


def main():
    """主入口"""
    print("=" * 60)
    print("  TOSKill 批量测试执行器")
    print(f"  目标目录: {BASE_DIR}")
    print("=" * 60)
    
    results = {}
    
    for module, name in TEST_MODULES:
        file_path = BASE_DIR / module
        if not file_path.exists():
            print(f"  [SKIP] {module} - 文件不存在")
            results[module] = False
            continue
        
        success = run_test(module, name)
        results[module] = success
        status = "PASS" if success else "FAIL"
        print(f"\n  [{status}] {name}")
    
    print("\n" + "=" * 60)
    print("  测试结果汇总")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for module, success in results.items():
        status = "PASS" if success else "FAIL"
        print(f"    [{status}] {module}")
    
    print(f"\n  总计: {passed}/{total} 通过")
    print("=" * 60)
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())