# -*- coding:utf-8 -*-
"""
工具注册验证测试脚本
验证 TOSKill/tools/__init__.py 中所有工具的注册情况
"""

import sys
import os
from typing import List, Dict, Any

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from TOSKill.tools import (
    ALL_TOOLS,
    INFO_COLLECTION_TOOLS,
    POC_TOOLS,
    VULN_SCAN_TOOLS,
    REPORT_TOOLS,
    TOOL_COUNT,
    TOOLS_BY_CATEGORY,
)


def validate_tool(tool: Any, index: int, category: str = "unknown") -> Dict[str, Any]:
    """验证单个工具的属性
    
    Args:
        tool: 工具对象
        index: 工具索引
        category: 工具类别
        
    Returns:
        验证结果字典
    """
    result = {
        "index": index,
        "category": category,
        "valid": True,
        "errors": [],
        "warnings": [],
        "tool_info": {}
    }
    
    if hasattr(tool, 'name'):
        result["tool_info"]["name"] = tool.name
    else:
        result["valid"] = False
        result["errors"].append("缺少 name 属性")
    
    if hasattr(tool, 'description'):
        result["tool_info"]["description"] = tool.description[:50] + "..." if len(tool.description) > 50 else tool.description
    else:
        result["valid"] = False
        result["errors"].append("缺少 description 属性")
    
    is_callable = False
    callable_methods = []
    
    if hasattr(tool, 'invoke') and callable(getattr(tool, 'invoke')):
        is_callable = True
        callable_methods.append('invoke')
    
    if hasattr(tool, 'run') and callable(getattr(tool, 'run')):
        is_callable = True
        callable_methods.append('run')
    
    if hasattr(tool, '_run') and callable(getattr(tool, '_run')):
        is_callable = True
        callable_methods.append('_run')
    
    if hasattr(tool, 'func') and callable(getattr(tool, 'func')):
        is_callable = True
        callable_methods.append('func')
    
    if callable(tool):
        is_callable = True
        callable_methods.append('__call__')
    
    if is_callable:
        result["tool_info"]["callable_methods"] = callable_methods
    else:
        result["valid"] = False
        result["errors"].append("工具不可调用（缺少 invoke/run/func/__call__ 方法）")
    
    tool_type = type(tool).__name__
    result["tool_info"]["type"] = tool_type
    
    return result


def validate_all_tools() -> Dict[str, Any]:
    """验证所有工具
    
    Returns:
        完整的验证结果
    """
    print("=" * 60)
    print("TOSKill 工具注册验证")
    print("=" * 60)
    
    results = {
        "total_tools": len(ALL_TOOLS),
        "expected_tools": 36,
        "categories": {},
        "all_valid": True,
        "invalid_tools": [],
        "warnings": [],
        "details": []
    }
    
    print(f"\n1. 检查工具总数...")
    print(f"   实际工具数量: {results['total_tools']}")
    print(f"   预期工具数量: {results['expected_tools']}")
    
    if results['total_tools'] != results['expected_tools']:
        results['all_valid'] = False
        results['warnings'].append(
            f"工具数量不匹配: 预期 {results['expected_tools']}，实际 {results['total_tools']}"
        )
        print(f"   ❌ 工具数量不匹配!")
    else:
        print(f"   ✅ 工具数量正确!")
    
    print(f"\n2. 检查各类别工具数量...")
    for category, tools in TOOLS_BY_CATEGORY.items():
        count = len(tools)
        expected = TOOL_COUNT.get(category, 0)
        results['categories'][category] = {
            "count": count,
            "expected": expected,
            "match": count == expected
        }
        status = "✅" if count == expected else "❌"
        print(f"   {category}: {count} 个工具 {status}")
    
    print(f"\n3. 验证每个工具的属性...")
    print("-" * 60)
    
    for idx, tool in enumerate(ALL_TOOLS):
        category = "unknown"
        for cat, tools in TOOLS_BY_CATEGORY.items():
            if tool in tools:
                category = cat
                break
        
        result = validate_tool(tool, idx, category)
        results['details'].append(result)
        
        if not result['valid']:
            results['all_valid'] = False
            results['invalid_tools'].append(result)
        
        status = "✅" if result['valid'] else "❌"
        name = result['tool_info'].get('name', 'UNKNOWN')
        tool_type = result['tool_info'].get('type', 'unknown')
        callable_methods = result['tool_info'].get('callable_methods', [])
        
        print(f"   [{idx+1:2d}] {status} {name:30s} ({tool_type})")
        if callable_methods:
            print(f"        可调用方法: {', '.join(callable_methods)}")
        
        if result['errors']:
            for error in result['errors']:
                print(f"        ❌ 错误: {error}")
        
        if result['warnings']:
            for warning in result['warnings']:
                print(f"        ⚠️  警告: {warning}")
    
    print("\n" + "=" * 60)
    print("验证结果摘要")
    print("=" * 60)
    
    print(f"\n总工具数: {results['total_tools']}")
    print(f"有效工具: {results['total_tools'] - len(results['invalid_tools'])}")
    print(f"无效工具: {len(results['invalid_tools'])}")
    
    if results['all_valid']:
        print("\n✅ 所有工具验证通过!")
    else:
        print("\n❌ 发现以下问题:")
        
        if results['warnings']:
            print("\n⚠️  警告:")
            for warning in results['warnings']:
                print(f"   - {warning}")
        
        if results['invalid_tools']:
            print("\n❌ 无效工具:")
            for invalid in results['invalid_tools']:
                name = invalid['tool_info'].get('name', 'UNKNOWN')
                errors = ', '.join(invalid['errors'])
                print(f"   - {name}: {errors}")
    
    print("\n" + "=" * 60)
    
    return results


def print_tool_names_by_category():
    """按类别打印所有工具名称"""
    print("\n" + "=" * 60)
    print("工具名称列表（按类别）")
    print("=" * 60)
    
    for category, tools in TOOLS_BY_CATEGORY.items():
        print(f"\n{category} ({len(tools)} 个工具):")
        for idx, tool in enumerate(tools, 1):
            name = getattr(tool, 'name', 'UNKNOWN')
            print(f"   {idx:2d}. {name}")


if __name__ == "__main__":
    results = validate_all_tools()
    print_tool_names_by_category()
    
    sys.exit(0 if results['all_valid'] else 1)
