"""
Agent 配置文件

定义Agent相关的配置参数。
"""
from typing import Dict, List
from backend.config import settings

class AgentConfig:
    """
    Agent配置类
    
    集中管理Agent的所有配置参数,便于统一调整。
    """
    # 温度配置
    TEMPERATURE: float = settings.AGENT_TEMPERATURE
    """
    温度参数
    
    控制模型输出的随机性。
    默认为0.7。
    """
    
    # = 对话实例配置 =
    MAX_CHAT_INSTANCES_PER_USER: int = 10
    """
    每个用户最大对话实例数
    
    限制单个用户可创建的对话实例数量。
    默认为10个。
    """
    
    CHAT_INSTANCE_TIMEOUT: int = 3600
    """
    对话实例超时时间(秒)
    
    超过此时间未活动的对话实例将被自动清理。
    默认为3600秒(1小时)。
    """
    
    ENABLE_CHAT_INSTANCE_CLEANUP: bool = True
    """
    是否启用对话实例自动清理
    
    默认为True。
    """
    
    # = 工作流配置 =
    MAX_WORKFLOW_INSTANCES: int = 100
    """
    最大工作流实例数
    
    系统同时运行的最大工作流实例数量。
    默认为100个。
    """
    
    WORKFLOW_CHECKPOINT_INTERVAL: int = 30
    """
    工作流检查点保存间隔(秒)
    
    用于断点续传功能。
    默认为30秒。
    """
    
    ENABLE_WORKFLOW_RESUME: bool = True
    """
    是否启用工作流恢复功能
    
    默认为True。
    """
    
    WORKFLOW_RESUME_TIMEOUT: int = 86400
    """
    工作流恢复超时时间(秒)
    
    超过此时间的工作流状态将无法恢复。
    默认为86400秒(24小时)。
    """

    # = 执行配置 =
    MAX_EXECUTION_TIME: int = settings.AGENT_MAX_EXECUTION_TIME
    """
    Agent最大执行时间(秒)
    
    超过此时间后Agent将被强制终止。
    默认为18000秒(5小时)。
    """
    

    MAX_CONCURRENT_TOOLS: int = 5
    """
    最大并发工具执行数
    
    控制同时执行的工具数量上限。
    默认为5个。
    """
    
    TOOL_TIMEOUT: int = 60
    """
    单个工具执行超时时间(秒)
    
    默认为60秒。
    """
    
    # = 流程执行优化配置 =
    ENABLE_RESPONSE_TIME_MONITORING: bool = True
    """
    是否启用响应时间监控
    
    默认为True。
    """
    
    # = API配置 =
    API_RATE_LIMIT: int = 100
    """
    API请求速率限制(每分钟)
    
    默认为100次/分钟。
    """
    
    API_TIMEOUT: int = 30
    """
    API请求超时时间(秒)
    
    默认为30秒。
    """
    
    ENABLE_API_AUTH: bool = True
    """
    是否启用API认证
    
    默认为True。
    """
    
    # = WebSocket配置 =
    WEBSOCKET_HEARTBEAT_INTERVAL: int = 30
    """
    WebSocket心跳间隔(秒)
    
    默认为30秒。
    """
    
    WEBSOCKET_MAX_CONNECTIONS: int = 1000
    """
    WebSocket最大连接数
    
    默认为1000个。
    """
    
    WEBSOCKET_MESSAGE_QUEUE_SIZE: int = 100
    """
    WebSocket消息队列大小
    
    默认为100条。
    """
    
    ENABLE_WEBSOCKET_BROADCAST: bool = True
    """
    是否启用WebSocket广播
    
    默认为True。
    """
    


    # = LLM 配置 =
    MODEL_ID: str = settings.MODEL_ID
    """
    AI 模型 ID
    
    指定使用的大语言模型。
    默认为通义千问 1b7 模型。
    """

    OPENAI_API_KEY: str = settings.OPENAI_API_KEY
    """
    OpenAI API 密钥
    
    用于访问 OpenAI 的 GPT 系列模型。
    用于 AI Agent、代码生成、漏洞分析等功能。
    """

    OPENAI_BASE_URL: str = settings.OPENAI_BASE_URL
    """
    OpenAI API 基础 URL
    
    用于指定 OpenAI API 的自定义端点。
    默认为官方 OpenAI API 地址。
    如果使用第三方兼容服务(如阿里云 MaaS),可以修改此地址。
    """
    
    # = 任务规划配置 =
    ENABLE_LLM_PLANNING: bool = True
    """
    是否启用LLM增强任务规划
    
    设置为True时使用LLM生成更智能的扫描任务。
    设置为False时使用规则化规划器。
    默认为True。
    """
    
    DEFAULT_SCAN_TASKS: List[str] = [
        "baseinfo",
        "portscan",
        "cms_identify",
        "waf_detect",
        "cdn_detect",
        "iplocating",
        "subdomain_scan",
        "webside_scan",
        "webweight_scan",
        "infoleak_scan",
        "dirscan",
        "crawler",
        "sqli_scan",
        "xss_scan",
        "csrf_scan",
        "vuln_infoleak_scan",
        "fileupload_scan",
        "cmdi_scan",
        "weakpass_scan",
        "lfi_scan",
        "ssrf_scan"
    ]
    """
    默认扫描任务列表
    
    规则化规划器使用的默认任务序列。
    包含所有信息收集和漏洞扫描工具，确保完整的安全检测。
    """
    
    # = 漏洞分析配置 =
    SEVERITY_ORDER: Dict[str, int] = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }
    """
    漏洞严重度排序权重
    
    用于漏洞分析时的严重度排序。
    """
    
    ENABLE_KB_INTEGRATION: bool = True
    """
    是否启用漏洞知识库集成
    
    设置为True时,漏洞分析会自动匹配知识库中的修复建议。
    默认为True。
    """
    
    # = 记忆配置 =
    ENABLE_MEMORY: bool = True
    """
    是否启用记忆机制
    
    设置为True时,Agent会记录执行历史和目标上下文。
    默认为True。
    """
    
    MEMORY_MAX_SIZE: int = 1000
    """
    记忆最大条目数
    
    限制记忆存储的条目数量,避免内存占用过大。
    默认为1000条。
    """
    
    # = 日志配置 =
    ENABLE_DETAILED_LOGGING: bool = settings.DEBUG
    """
    是否启用详细日志
    
    设置为True时,记录Agent执行的详细步骤。
    默认与settings.DEBUG一致。
    """
    
    # = 优先级配置 =
    PRIORITY_WEIGHTS: Dict[str, float] = {
        "critical_vulnerability": 1.0,
        "high_vulnerability": 0.8,
        "medium_vulnerability": 0.6,
        "low_vulnerability": 0.4,
        "baseinfo": 0.3,
        "portscan": 0.5
    }
    """
    任务优先级权重
    
    用于动态任务优先级排序。
    """

agent_config = AgentConfig()
"""
全局Agent配置实例

在应用中导入此实例来访问配置:
    from ai_agents.agent_config import agent_config
    max_time = agent_config.MAX_EXECUTION_TIME
"""
