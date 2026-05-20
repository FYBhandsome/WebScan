"""
统一测试入口 - 批量运行所有 API 模块测试

用法:
    python run_all.py                    # 运行全部测试
    python run_all.py --skip-slow        # 跳过耗时测试(ai_agents扫描)
    python run_all.py --module tasks     # 只运行指定模块
"""
import asyncio
import sys
import os
import time
import argparse

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

TEST_MODULES = {
    "tasks":       ("api.test_tasks",        "扫描任务CRUD"),
    "reports":     ("api.test_reports",      "报告生成/导出"),
    "awvs":        ("api.test_awvs",         "AWVS集成"),
    "poc":         ("api.test_poc",          "POC扫描"),
    "ai":          ("api.test_ai",           "AI对话"),
    "kb":          ("api.test_kb",           "知识库"),
    "settings":    ("api.test_settings",     "系统设置"),
    "user":        ("api.test_user",         "用户管理"),
    "notifications": ("api.test_notifications", "通知系统"),
    "ai_agents":   ("api.test_ai_agents",    "AI Agent扫描"),
    "websocket":   ("api.test_websocket",    "WebSocket连接"),
}

SLOW_MODULES = {"ai_agents"}

async def check_server():
    import httpx
    try:
        r = httpx.get("http://127.0.0.1:8888/health", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

def run_module(module_name, label):
    import_path = TEST_MODULES[module_name][0]
    script_path = "tests/" + import_path.replace(".", "/") + ".py"
    print(f"\n{'#'*70}")
    print(f"#  开始测试: {label} ({module_name})")
    print(f"{'#'*70}")
    start = time.time()
    exit_code = os.system(f"python {script_path}")
    elapsed = time.time() - start
    status = "PASS" if exit_code == 0 else "FAIL"
    print(f"\n#  {label}: {status} ({elapsed:.1f}s)")
    return module_name, exit_code

def main():
    parser = argparse.ArgumentParser(description="批量API测试运行器")
    parser.add_argument("--skip-slow", action="store_true", help="跳过耗时测试")
    parser.add_argument("--module", type=str, help="只运行指定模块")
    parser.add_argument("--list", action="store_true", help="列出所有测试模块")
    args = parser.parse_args()

    if args.list:
        for name, (path, label) in TEST_MODULES.items():
            slow = " [SLOW]" if name in SLOW_MODULES else ""
            print(f"  {name:20s} - {label}{slow}")
        return

    if not asyncio.run(check_server()):
        print("ERROR: 后端服务未启动 (http://127.0.0.1:8888)")
        print("请先启动: python -m uvicorn backend.main:app --host 127.0.0.1 --port 8888")
        sys.exit(1)

    modules_to_run = list(TEST_MODULES.keys())

    if args.module:
        if args.module not in TEST_MODULES:
            print(f"ERROR: 未知模块 '{args.module}'. 可用: {list(TEST_MODULES.keys())}")
            sys.exit(1)
        modules_to_run = [args.module]

    if args.skip_slow:
        modules_to_run = [m for m in modules_to_run if m not in SLOW_MODULES]
        print(f"跳过耗时模块: {SLOW_MODULES}")

    print("=" * 70)
    print(f"  批量API测试 | 共 {len(modules_to_run)} 个模块")
    print("=" * 70)

    results = {}
    total_start = time.time()

    for module_name in modules_to_run:
        name, exit_code = run_module(module_name, TEST_MODULES[module_name][1])
        results[name] = exit_code

    total_elapsed = time.time() - total_start

    print(f"\n{'='*70}")
    print(f"  全部测试完成 ({total_elapsed:.0f}s)")
    print(f"{'='*70}")
    passed = sum(1 for v in results.values() if v == 0)
    failed = sum(1 for v in results.values() if v != 0)
    for name, code in results.items():
        icon = "PASS" if code == 0 else "FAIL"
        print(f"  [{icon}] {name}")
    print(f"\n  通过: {passed}/{len(results)}, 失败: {failed}/{len(results)}")
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()