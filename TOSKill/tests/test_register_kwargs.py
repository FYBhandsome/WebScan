"""
Task 10 自测脚本：register_script_as_tool 扩展 kwargs（接收 __extend_params）

测试1: 新脚本 run(target, cookie=None) → 注册后 tool_func(target, cookie="abc") → cookie 正确传入
测试2: 旧脚本 run(target) → 注册后 tool_func(target, cookie="abc") → 旧脚本正常返回，cookie 被 signature 过滤
测试3: 旧脚本 run(target) → 注册后 tool_func(target) 不传 kwargs → 正常工作（向下兼容）
测试4: 通过 unified_tool_invoke + __extend_params 端到端验证 cookie 到达新脚本
"""
import sys
import os
import inspect
import traceback

# 确保项目根目录在 sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# TOSKill 包路径
TOSKILL_ROOT = os.path.dirname(os.path.abspath(__file__))
if TOSKILL_ROOT not in sys.path:
    sys.path.insert(0, TOSKILL_ROOT)


# 临时脚本文件内容
NEW_SCRIPT_CONTENT = '''def run(target, cookie=None):
    """新脚本：接受 cookie 参数"""
    return {"success": True, "target": target, "cookie": cookie}
'''

OLD_SCRIPT_CONTENT = '''def run(target):
    """旧脚本：不接受 cookie 参数"""
    return {"success": True, "target": target}
'''

# 用于统一清理注册的临时脚本文件
_CLEANUP_FILES = []


def _cleanup(manager):
    """清理测试中创建的临时脚本文件"""
    for script_name in list(_CLEANUP_FILES):
        try:
            path = manager._scripts_dir / f"{script_name}.py"
            if path.exists():
                path.unlink()
        except Exception:
            pass


def test1_new_script_receives_cookie():
    """测试1: 新脚本 run(target, cookie=None) 注册后收到 cookie"""
    print("\n" + "=" * 60)
    print("测试1: 新脚本 run(target, cookie=None) 收到 cookie")
    print("=" * 60)

    from TOSKill.AI.tools import ScriptManager

    manager = ScriptManager.get_instance()
    script_name = "tmp_cookie_tool_test1"
    _CLEANUP_FILES.append(script_name)

    result = manager.register_script_as_tool(
        script_content=NEW_SCRIPT_CONTENT,
        script_name=script_name,
        description="测试工具：接受cookie",
        category="custom",
    )

    assert result["success"], f"注册失败: {result.get('error')}"
    print(f"  [OK] 注册成功: tool_name={result['tool_name']}")

    tool = result["tool"]
    tool_func = tool.func

    # 验证 tool_func 签名包含 **kwargs
    sig = inspect.signature(tool_func)
    params = sig.parameters
    assert "target" in params, f"tool_func 缺少 target 参数: {list(params.keys())}"
    has_var_keyword = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    )
    assert has_var_keyword, f"tool_func 缺少 **kwargs: {list(params.keys())}"
    print(f"  [OK] tool_func 签名: {sig}")

    # 直接调用 tool_func，传 cookie
    ret = tool_func(target="http://x", cookie="abc")
    print(f"  [结果] tool_func(target, cookie='abc') = {ret}")
    assert ret["success"] is True, f"脚本执行失败: {ret}"
    assert ret["target"] == "http://x", f"target 不匹配: {ret['target']}"
    assert ret["cookie"] == "abc", f"cookie 未正确传入: {ret['cookie']}"

    print("  [PASS] 新脚本正确收到 cookie='abc'")
    return True


def test2_old_script_ignores_cookie():
    """测试2: 旧脚本 run(target) 注册后调用时传 cookie 不报错（被 signature 过滤）"""
    print("\n" + "=" * 60)
    print("测试2: 旧脚本 run(target) 传 cookie 不报错（signature 过滤）")
    print("=" * 60)

    from TOSKill.AI.tools import ScriptManager

    manager = ScriptManager.get_instance()
    script_name = "tmp_old_tool_test2"
    _CLEANUP_FILES.append(script_name)

    result = manager.register_script_as_tool(
        script_content=OLD_SCRIPT_CONTENT,
        script_name=script_name,
        description="测试工具：旧脚本不接受cookie",
        category="custom",
    )

    assert result["success"], f"注册失败: {result.get('error')}"
    print(f"  [OK] 注册成功: tool_name={result['tool_name']}")

    tool = result["tool"]
    tool_func = tool.func

    # 直接调用 tool_func，传 cookie（旧脚本不接受，应被过滤）
    ret = tool_func(target="http://x", cookie="abc")
    print(f"  [结果] tool_func(target, cookie='abc') = {ret}")
    assert ret["success"] is True, f"旧脚本执行失败: {ret}"
    assert ret["target"] == "http://x", f"target 不匹配: {ret['target']}"
    assert "cookie" not in ret, f"旧脚本不应返回 cookie: {ret}"

    print("  [PASS] 旧脚本正常返回，cookie 被 signature 过滤忽略")
    return True


def test3_old_script_no_kwargs():
    """测试3: 旧脚本不传 kwargs 时正常工作（向下兼容）"""
    print("\n" + "=" * 60)
    print("测试3: 旧脚本不传 kwargs 时正常工作（向下兼容）")
    print("=" * 60)

    from TOSKill.AI.tools import ScriptManager

    manager = ScriptManager.get_instance()
    script_name = "tmp_old_tool_test3"
    _CLEANUP_FILES.append(script_name)

    result = manager.register_script_as_tool(
        script_content=OLD_SCRIPT_CONTENT,
        script_name=script_name,
        description="测试工具：不传kwargs",
        category="custom",
    )

    assert result["success"], f"注册失败: {result.get('error')}"
    print(f"  [OK] 注册成功: tool_name={result['tool_name']}")

    tool = result["tool"]
    tool_func = tool.func

    # 不传 kwargs（模拟旧调用方 tool.invoke(target)）
    ret = tool_func(target="http://x")
    print(f"  [结果] tool_func(target) = {ret}")
    assert ret["success"] is True, f"旧脚本执行失败: {ret}"
    assert ret["target"] == "http://x", f"target 不匹配: {ret['target']}"

    # 也通过 tool.invoke 验证（langchain 调用路径）
    ret_invoke = tool.invoke({"target": "http://y"})
    print(f"  [结果] tool.invoke({{'target':'http://y'}}) = {ret_invoke}")
    assert ret_invoke["success"] is True, f"tool.invoke 失败: {ret_invoke}"
    assert ret_invoke["target"] == "http://y", f"target 不匹配: {ret_invoke['target']}"

    print("  [PASS] 旧脚本不传 kwargs 正常工作（直接调用 + tool.invoke）")
    return True


def test4_unified_tool_invoke_extend_params():
    """测试4: 通过 unified_tool_invoke + __extend_params 端到端验证 cookie 到达新脚本"""
    print("\n" + "=" * 60)
    print("测试4: unified_tool_invoke + __extend_params 端到端")
    print("=" * 60)

    from TOSKill.AI.tools import ScriptManager, unified_tool_invoke, TOOL_MAP

    manager = ScriptManager.get_instance()
    script_name = "tmp_cookie_tool_test4"
    _CLEANUP_FILES.append(script_name)

    result = manager.register_script_as_tool(
        script_content=NEW_SCRIPT_CONTENT,
        script_name=script_name,
        description="测试工具：__extend_params端到端",
        category="custom",
    )

    assert result["success"], f"注册失败: {result.get('error')}"
    tool_name = result["tool_name"]
    print(f"  [OK] 注册成功: tool_name={tool_name}")
    assert tool_name in TOOL_MAP, f"工具未注册到 TOOL_MAP: {tool_name}"

    # 通过 unified_tool_invoke 传 __extend_params 含 cookie
    arguments = {
        "target": "http://dvwa.test",
        "__extend_params": {"cookie": "PHPSESSID=xyz789"},
    }
    ret = unified_tool_invoke(tool_name, arguments, state=None)
    print(f"  [结果] unified_tool_invoke({tool_name}, args) = {ret}")
    assert ret["success"] is True, f"unified_tool_invoke 执行失败: {ret}"
    assert ret["target"] == "http://dvwa.test", f"target 不匹配: {ret['target']}"
    assert ret["cookie"] == "PHPSESSID=xyz789", (
        f"cookie 未通过 __extend_params 到达新脚本: {ret['cookie']}"
    )

    print("  [PASS] __extend_params cookie 经 unified_tool_invoke 到达新脚本")
    return True


def test5_unified_tool_invoke_old_script_ignores_extend_params():
    """测试5: unified_tool_invoke + __extend_params 传给旧脚本时不报错"""
    print("\n" + "=" * 60)
    print("测试5: unified_tool_invoke + __extend_params 传给旧脚本（不报错）")
    print("=" * 60)

    from TOSKill.AI.tools import ScriptManager, unified_tool_invoke, TOOL_MAP

    manager = ScriptManager.get_instance()
    script_name = "tmp_old_tool_test5"
    _CLEANUP_FILES.append(script_name)

    result = manager.register_script_as_tool(
        script_content=OLD_SCRIPT_CONTENT,
        script_name=script_name,
        description="测试工具：旧脚本__extend_params",
        category="custom",
    )

    assert result["success"], f"注册失败: {result.get('error')}"
    tool_name = result["tool_name"]
    print(f"  [OK] 注册成功: tool_name={tool_name}")

    # 旧脚本通过 unified_tool_invoke 传 __extend_params 含 cookie → 应被过滤不报错
    arguments = {
        "target": "http://old.test",
        "__extend_params": {"cookie": "should_be_ignored"},
    }
    ret = unified_tool_invoke(tool_name, arguments, state=None)
    print(f"  [结果] unified_tool_invoke({tool_name}, args) = {ret}")
    assert ret["success"] is True, f"旧脚本执行失败: {ret}"
    assert ret["target"] == "http://old.test", f"target 不匹配: {ret['target']}"
    assert "cookie" not in ret, f"旧脚本不应返回 cookie: {ret}"

    print("  [PASS] 旧脚本经 unified_tool_invoke 忽略 __extend_params cookie")
    return True


def main():
    print("=" * 60)
    print("Task 10 自测：register_script_as_tool 扩展 kwargs")
    print("=" * 60)

    tests = [
        ("测试1: 新脚本收到 cookie", test1_new_script_receives_cookie),
        ("测试2: 旧脚本过滤 cookie", test2_old_script_ignores_cookie),
        ("测试3: 旧脚本不传 kwargs", test3_old_script_no_kwargs),
        ("测试4: unified_tool_invoke 端到端", test4_unified_tool_invoke_extend_params),
        ("测试5: 旧脚本 unified_tool_invoke", test5_unified_tool_invoke_old_script_ignores_extend_params),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {name}: {e}")
            traceback.print_exc()

    # 清理临时脚本文件
    try:
        from TOSKill.AI.tools import ScriptManager
        _cleanup(ScriptManager.get_instance())
        print("\n[清理] 临时脚本文件已清理")
    except Exception as e:
        print(f"\n[清理] 清理失败: {e}")

    print("\n" + "=" * 60)
    print(f"结果: {passed} passed, {failed} failed (共 {len(tests)} 个)")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
