from TOSKill.AI.script_safety import normalize_script_for_registration
from TOSKill.AI.tools import (
    ScriptManager,
    TOOL_MAP,
    ALL_TOOLS,
    get_tool_by_name,
    get_custom_tool_names,
    unified_tool_invoke,
)


SCRIPT_WITH_PARAMS = """
def run(target: str, cookie=None):
    return {
        "success": True,
        "data": {"target": target, "cookie": cookie},
    }
"""


def _unregister_tool(manager, tool_name):
    TOOL_MAP.pop(tool_name, None)
    ALL_TOOLS[:] = [tool for tool in ALL_TOOLS if getattr(tool, "name", None) != tool_name]
    manager._registered_scripts.pop(tool_name, None)
    for suffix in (".py", ".js"):
        path = manager._scripts_dir / f"{tool_name}{suffix}"
        if path.exists():
            path.unlink()


def test_normalize_script_for_registration_extracts_code_and_name():
    wrapped = f"```python\r\n{SCRIPT_WITH_PARAMS}\r\n```"

    ok, message, normalized = normalize_script_for_registration(
        wrapped,
        script_name="Cookie Check.py",
        filename="Cookie Check.py",
    )

    assert ok, message
    assert normalized.tool_name == "custom_Cookie_Check"
    assert normalized.filename == "custom_Cookie_Check.py"
    assert normalized.language == "py"
    assert "\r" not in normalized.content
    assert normalized.content.startswith("def run")


def test_registered_script_is_available_invokable_and_remembered():
    manager = ScriptManager.get_instance()
    requested_name = "Param Check.py"
    expected_tool_name = "custom_Param_Check"
    _unregister_tool(manager, expected_tool_name)

    try:
        result = manager.register_script_as_tool(
            script_content=SCRIPT_WITH_PARAMS,
            script_name=requested_name,
            description="parameter passthrough check",
            category="custom",
        )

        assert result["success"], result
        assert result["tool_name"] == expected_tool_name
        assert expected_tool_name in TOOL_MAP
        assert expected_tool_name in get_custom_tool_names()
        assert get_tool_by_name(expected_tool_name) is result["tool"]

        invoked = unified_tool_invoke(
            expected_tool_name,
            {
                "target": "https://example.test",
                "__extend_params": {"cookie": "sid=abc"},
            },
        )
        assert invoked["success"] is True
        assert invoked["data"]["target"] == "https://example.test"
        assert invoked["data"]["cookie"] == "sid=abc"

        registered = manager.get_registered_scripts()
        assert registered[expected_tool_name]["category"] == "custom"
        assert registered[expected_tool_name]["language"] == "py"
    finally:
        _unregister_tool(manager, expected_tool_name)
