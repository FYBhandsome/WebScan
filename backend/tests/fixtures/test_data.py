"""
测试数据工厂 - 模拟前端交互场景的批量测试数据

涵盖所有业务模块：
- Tasks: 扫描任务CRUD + 统计
- Reports: 报告生成/导出/预览
- AWVS: 目标管理/扫描/漏洞同步
- POC: 类型查询/POC检测
- AI Chat: 对话实例/状态
- KB: 漏洞知识库/Seebug
- Settings: 系统配置/API Key
- User: 用户管理/权限
- Notifications: 通知CRUD
- AI Agents: 智能扫描/工具/POC/工作流
"""

TASK_DATA = {
    "basic_scan": {
        "task_name": "基础扫描-测试目标",
        "task_type": "web_scan",
        "target": "http://testphp.vulnweb.com",
        "config": {"scan_depth": 3, "timeout": 300}
    },
    "deep_scan": {
        "task_name": "深度扫描-内部系统",
        "task_type": "vulnerability",
        "target": "https://demo.testfire.net",
        "config": {"scan_depth": 5, "aggressive": True}
    },
    "subdomain_scan": {
        "task_name": "子域名枚举",
        "task_type": "subdomain",
        "target": "example.com",
        "config": {"wordlist": "subdomains-top1m.txt", "threads": 10}
    },
    "port_scan": {
        "task_name": "端口扫描-常见服务",
        "task_type": "port_scan",
        "target": "192.168.1.1",
        "config": {"ports": "1-1000", "rate": 100}
    },
    "batch_create": [
        {"task_name": "批量扫描-A站点", "task_type": "web_scan", "target": "http://testaspnet.vulnweb.com", "config": {"depth": 2}},
        {"task_name": "批量扫描-B站点", "task_type": "web_scan", "target": "http://testhtml5.vulnweb.com", "config": {"depth": 2}},
        {"task_name": "批量扫描-C站点", "task_type": "web_scan", "target": "http://rest.vulnweb.com", "config": {"depth": 2}},
    ],
    "update": {
        "task_name": "已更新-测试扫描任务"
    }
}

REPORT_DATA = {
    "basic_report": {
        "name": "综合漏洞分析报告",
        "format": "json",
        "include_ai_analysis": True,
        "include_summary": True,
        "include_vulnerabilities": True
    },
    "detail_report": {
        "name": "详细技术报告-v2.0",
        "format": "html",
        "include_ai_analysis": True,
        "include_charts": True,
        "include_recommendations": True
    },
    "summary_report": {
        "name": "月度安全汇总报告",
        "format": "markdown",
        "include_ai_analysis": False,
        "include_summary": True
    },
    "export_formats": ["json", "html", "markdown", "pdf"]
}

SETTINGS_DATA = {
    "general": {
        "scan_timeout": "600",
        "max_concurrent_scans": "5",
        "auto_sync_interval": "3600"
    },
    "openai": {
        "api_key": "sk-test-placeholder-key",
        "model": "gpt-4o",
        "temperature": "0.7",
        "max_tokens": "4096"
    },
    "awvs": {
        "api_url": "https://127.0.0.1:3443",
        "api_key": "1986ad8c0a5b3df4d7028d5f3c06e936cef5b5f5d5c5a5e5b5c5d5e5f5a5b5c5de",
        "auto_sync": "true"
    },
    "notification": {
        "email_enabled": "false",
        "webhook_url": "",
        "severity_threshold": "high"
    },
    "api_key_test": {
        "name": "Test API Key",
        "description": "Generated for testing purposes"
    }
}

POC_SCAN_DATA = {
    "weblogic_cve_2020_2551": {
        "target": "http://testphp.vulnweb.com",
        "poc_type": "weblogic_cve_2020_2551"
    },
    "struts2_009": {
        "target": "http://testphp.vulnweb.com",
        "poc_type": "struts2_009"
    },
    "tomcat_cve_2017_12615": {
        "target": "http://testphp.vulnweb.com",
        "poc_type": "tomcat_cve_2017_12615"
    },
    "struts2_032": {
        "target": "http://testphp.vulnweb.com",
        "poc_type": "struts2_032"
    },
    "jboss_cve_2017_12149": {
        "target": "http://testphp.vulnweb.com",
        "poc_type": "jboss_cve_2017_12149"
    }
}

AWVS_SCAN_DATA = {
    "create_target": {
        "address": "http://testphp.vulnweb.com",
        "description": "Test target for API testing",
        "criticality": 10
    },
    "start_scan": {
        "target_id": "test-target-001",
        "profile_id": "full_scan",
        "schedule": {"disable": False, "start_date": None, "time_sensitive": False}
    }
}

AI_CHAT_DATA = {
    "create_chat": {
        "chat_name": "安全分析助手",
        "chat_type": "security_analysis"
    },
    "chat_message": {
        "message": "请分析这个URL是否存在SQL注入漏洞：http://testphp.vulnweb.com/artists.php?artist=1"
    },
    "vuln_analysis": {
        "vulnerability_description": "发现了反射型XSS漏洞，位于搜索参数中",
        "context": "目标站点: http://testphp.vulnweb.com, 扫描类型: web_scan"
    }
}

AI_AGENT_SCAN_DATA = {
    "quick_scan": {
        "target": "http://testphp.vulnweb.com",
        "strategy": "quick",
        "enable_llm_planning": False,
        "concurrency": 3,
        "timeout": 600,
        "max_depth": 3
    },
    "deep_scan": {
        "target": "http://testphp.vulnweb.com",
        "strategy": "deep",
        "enable_llm_planning": True,
        "concurrency": 5,
        "timeout": 1200,
        "max_depth": 5,
        "enable_poc_verification": True
    },
    "targeted_scan": {
        "target": "http://testphp.vulnweb.com",
        "strategy": "targeted",
        "enable_llm_planning": True,
        "focus_areas": ["sql_injection", "xss", "csrf"],
        "concurrency": 3,
        "timeout": 900
    },
    "poc_search": {
        "keyword": "sql injection",
        "cve_id": "CVE-2021-44228"
    },
    "poc_execute": {
        "poc_id": "struts2-045",
        "target": "http://testphp.vulnweb.com"
    }
}

VULNERABILITY_DATA = {
    "sql_injection": {
        "title": "SQL Injection in login form",
        "vuln_type": "SQLInjection",
        "severity": "critical",
        "url": "http://testphp.vulnweb.com/login.php",
        "description": "The login form is vulnerable to SQL injection via the username parameter",
        "payload": "admin' OR '1'='1",
        "evidence": "SQL error message exposed in response",
        "remediation": "Use parameterized queries and input validation"
    },
    "xss_reflected": {
        "title": "Reflected XSS in search parameter",
        "vuln_type": "XSS",
        "severity": "high",
        "url": "http://testphp.vulnweb.com/search.php?q=test",
        "description": "The search parameter reflects user input without sanitization",
        "payload": '<script>alert("XSS")</script>',
        "evidence": "Payload reflected in HTML response without encoding",
        "remediation": "HTML-encode all user-supplied data in output"
    },
    "rce": {
        "title": "Remote Code Execution via file upload",
        "vuln_type": "RCE",
        "severity": "critical",
        "url": "http://testphp.vulnweb.com/upload.php",
        "description": "Unrestricted file upload allows PHP code execution",
        "payload": "<?php system('id'); ?>",
        "remediation": "Restrict file types and use server-side validation"
    }
}

NOTIFICATION_DATA = {
    "scan_completed": {
        "title": "扫描任务完成",
        "message": "基础扫描-测试目标 扫描已完成，发现3个漏洞",
        "type": "info"
    },
    "scan_failed": {
        "title": "扫描任务失败",
        "message": "深度扫描-内部系统 执行失败：连接超时",
        "type": "error"
    },
    "vuln_found": {
        "title": "发现高危漏洞",
        "message": "在目标站点发现SQL注入漏洞，严重程度：critical",
        "type": "warning"
    }
}

# 前端 Dashboard 视图所需的数据集
DASHBOARD_DATA = {
    "statistics_overview": {
        "total_tasks": 45,
        "completed_tasks": 32,
        "running_tasks": 3,
        "failed_tasks": 10,
        "total_vulnerabilities": 128,
        "critical_vulnerabilities": 5,
        "high_vulnerabilities": 23,
        "medium_vulnerabilities": 45,
        "low_vulnerabilities": 55
    }
}

# AgentScan 页面所需的工作流数据集
AGENT_SCAN_WORKFLOW = {
    "steps": [
        {"name": "info_collection", "label": "信息收集", "order": 0},
        {"name": "vuln_scan", "label": "漏洞扫描", "order": 1},
        {"name": "poc_verification", "label": "POC验证", "order": 2},
        {"name": "result_analysis", "label": "结果分析", "order": 3}
    ]
}