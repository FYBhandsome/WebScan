"""
数据库模型定义 - 使用 Tortoise-ORM
"""
from tortoise import fields
from tortoise.models import Model
from uuid import uuid4
import json


class Task(Model):
    """
    扫描任务表
    
    用于记录和管理各类安全扫描任务，包括端口扫描、漏洞扫描、子域名扫描等。
    任务状态流转：pending -> running -> completed/failed/cancelled
    
    Attributes:
        id: 任务唯一标识
        task_name: 任务名称，便于识别和管理
        task_type: 任务类型，如 scan（扫描）、vulnerability（漏洞检测）、poc（POC验证）等
        target: 扫描目标，可以是域名、IP地址或URL
        status: 任务状态，pending（待执行）、running（执行中）、completed（已完成）、failed（失败）、cancelled（已取消）
        progress: 任务进度，0-100的整数
        config: 任务配置信息，JSON格式存储扫描参数
        result: 任务执行结果，JSON格式存储扫描输出
        error_message: 错误信息，记录任务失败原因
        created_at: 任务创建时间
        updated_at: 任务最后更新时间
    """
    
    id = fields.IntField(primary_key=True, description="任务ID")
    task_name = fields.CharField(max_length=255, description="任务名称")
    task_type = fields.CharField(max_length=50, description="任务类型：scan, vulnerability, poc, etc.")
    target = fields.CharField(max_length=500, description="扫描目标（域名/IP/URL）")
    status = fields.CharField(max_length=50, default="pending", description="状态：pending, running, completed, failed, cancelled")
    progress = fields.IntField(default=0, description="任务进度 0-100")
    config = fields.TextField(null=True, description="任务配置信息（JSON格式）")
    result = fields.TextField(null=True, description="任务执行结果（JSON格式）")
    error_message = fields.TextField(null=True, description="错误信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    # 关系定义
    reports: fields.ReverseRelation["Report"]
    vulnerabilities: fields.ReverseRelation["Vulnerability"]
    scan_results: fields.ReverseRelation["ScanResult"]
    poc_results: fields.ReverseRelation["POCScanResult"]
    
    class Meta:
        table = "tasks"
        table_description = "扫描任务表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.task_name} ({self.status})"
    
    def is_running(self) -> bool:
        """检查任务是否正在运行"""
        return self.status == "running"
    
    def is_completed(self) -> bool:
        """检查任务是否已完成"""
        return self.status == "completed"
    
    def is_failed(self) -> bool:
        """检查任务是否失败"""
        return self.status == "failed"

    async def save(self, *args, **kwargs):
        """
        重写 save 方法以实现状态机检查
        Requirement 3.1: 严格校验状态流转 PENDING->RUNNING->(SUCCESS|FAILED|ABORTED)
        """
        if self.id:
            # 获取当前数据库中的状态
            current = await self.__class__.get_or_none(id=self.id)
            if current:
                old_status = current.status
                new_status = self.status
                
                # 状态未改变，直接跳过检查
                if old_status != new_status:
                    valid_transitions = {
                        "pending": ["running", "cancelled", "failed", "processing"],
                        "running": ["completed", "failed", "cancelled", "processing", "pending"],
                        "processing": ["running", "completed", "failed", "cancelled", "pending"],
                        "completed": ["pending", "running", "processing"],
                        "failed": ["pending", "running", "processing"],
                        "cancelled": ["pending", "running", "processing"]
                    }
                    
                    allowed = valid_transitions.get(old_status, [])
                    if new_status not in allowed:
                        # 为了系统稳定性，这里打印错误日志并抛出异常
                        # 调用者应当捕获此异常
                        error_msg = f"Invalid state transition: Task-{self.id} {old_status} -> {new_status}"
                        # 这里我们只抛出异常，让上层处理
                        raise ValueError(error_msg)
                        
        await super().save(*args, **kwargs)


class Report(Model):
    """
    扫描报告表
    
    用于存储和管理扫描任务生成的报告，支持多种格式（PDF、HTML、JSON等）。
    报告与任务是一对多关系，一个任务可以生成多个报告。
    
    Attributes:
        id: 报告唯一标识
        task: 关联的任务对象，外键关联到Task表
        report_name: 报告名称，便于识别和管理
        report_type: 报告类型，如pdf（PDF文档）、html（HTML网页）、json（JSON数据）等
        content: 报告内容，JSON格式存储结构化数据
        file_path: 报告文件存储路径，如果报告导出为文件
        ai_analysis: AI分析结果，JSON格式存储AI对报告的分析
        analyzed_at: AI分析时间，记录AI分析的执行时间
        analysis_model: 分析模型，记录使用的AI模型名称
        created_at: 报告创建时间
        updated_at: 报告最后更新时间
    """
    
    id = fields.IntField(primary_key=True, description="报告ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="reports", description="关联任务"
    )
    report_name = fields.CharField(max_length=255, description="报告名称")
    report_type = fields.CharField(max_length=50, description="报告类型：pdf, html, json, docx, etc.")
    content = fields.TextField(null=True, description="报告内容（JSON格式）")
    file_path = fields.CharField(max_length=500, null=True, description="报告文件存储路径")
    ai_analysis = fields.TextField(null=True, description="AI分析结果（JSON格式）")
    analyzed_at = fields.DatetimeField(null=True, description="AI分析时间")
    analysis_model = fields.CharField(max_length=100, null=True, description="分析模型")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    class Meta:
        table = "reports"
        table_description = "扫描报告表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.report_name} ({self.report_type})"
    
    def has_file(self) -> bool:
        """检查报告是否有文件"""
        return self.file_path is not None and len(self.file_path) > 0


class Vulnerability(Model):
    """
    漏洞信息表
    
    用于记录和管理安全扫描发现的漏洞信息，包括漏洞详情、严重程度、修复建议等。
    漏洞与任务是一对多关系，一个任务可以发现多个漏洞。
    
    Attributes:
        id: 漏洞唯一标识
        task: 关联的任务对象，外键关联到Task表
        vuln_type: 漏洞类型，如XSS（跨站脚本）、SQLInjection（SQL注入）、CSRF（跨站请求伪造）等
        severity: 严重程度，high（高危）、medium（中危）、low（低危）、info（信息）
        title: 漏洞标题，简洁描述漏洞
        description: 漏洞详细描述，说明漏洞原理和影响
        url: 漏洞所在的URL地址
        payload: 测试使用的Payload，用于复现漏洞
        evidence: 漏洞证据，如截图、响应数据等
        remediation: 修复建议，提供漏洞修复方案
        ai_analysis: AI分析结果，JSON格式存储AI对漏洞的分析
        risk_score: AI评估风险分数，0.0-10.0的数值评分
        fix_priority: 修复优先级，数值越小优先级越高
        status: 漏洞状态，open（未修复）、fixed（已修复）、ignored（已忽略）
        created_at: 漏洞发现时间
        updated_at: 漏洞最后更新时间
    """
    
    id = fields.IntField(primary_key=True, description="漏洞ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="vulnerabilities", description="关联任务"
    )
    vuln_type = fields.CharField(max_length=255, description="漏洞类型：XSS, SQLInjection, CSRF, RCE, SSRF, etc.")
    severity = fields.CharField(max_length=20, description="严重程度：critical, high, medium, low, info")
    title = fields.CharField(max_length=255, description="漏洞标题")
    description = fields.TextField(null=True, description="漏洞详细描述")
    url = fields.CharField(max_length=500, null=True, description="漏洞URL地址")
    payload = fields.TextField(null=True, description="测试Payload")
    evidence = fields.TextField(null=True, description="漏洞证据（截图/响应数据等）")
    remediation = fields.TextField(null=True, description="修复建议")
    ai_analysis = fields.TextField(null=True, description="AI分析结果（JSON格式）")
    risk_score = fields.FloatField(null=True, description="AI评估风险分数")
    fix_priority = fields.IntField(null=True, description="修复优先级")
    cvss_score = fields.FloatField(null=True, description="CVSS评分（0-10）")
    affected_product = fields.CharField(max_length=500, null=True, description="受影响的产品/组件")
    status = fields.CharField(max_length=50, default="open", description="状态：open, fixed, ignored, false_positive")
    source_id = fields.CharField(max_length=100, null=True, description="来源ID (如AWVS vuln_id)")
    source = fields.CharField(max_length=20, default="awvs", description="来源：awvs, poc")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    class Meta:
        table = "vulnerabilities"
        table_description = "漏洞信息表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.title} ({self.severity})"
    
    def is_critical(self) -> bool:
        """检查是否为高危漏洞"""
        return self.severity in ["critical", "high"]
    
    def is_open(self) -> bool:
        """检查漏洞是否未修复"""
        return self.status == "open"
    
    def is_fixed(self) -> bool:
        """检查漏洞是否已修复"""
        return self.status == "fixed"


class ScanResult(Model):
    """
    扫描结果表
    
    用于存储各类扫描任务的执行结果，如端口扫描、子域名扫描、目录扫描等。
    扫描结果与任务是一对多关系，一个任务可以产生多个扫描结果。
    
    Attributes:
        id: 结果唯一标识
        task: 关联的任务对象，外键关联到Task表
        scan_type: 扫描类型，如port_scan（端口扫描）、subdomain（子域名）、directory（目录扫描）等
        target: 扫描目标，域名、IP或URL
        result: 扫描结果，JSON格式存储结构化数据
        ai_analysis: AI分析结果，JSON格式存储AI对扫描结果的分析
        status: 扫描状态，success（成功）、failed（失败）
        error_message: 错误信息，记录扫描失败原因
        created_at: 扫描时间
    """
    
    id = fields.IntField(primary_key=True, description="结果ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="scan_results", description="关联任务"
    )
    scan_type = fields.CharField(max_length=50, description="扫描类型：port_scan, subdomain, directory, etc.")
    target = fields.CharField(max_length=500, description="扫描目标（域名/IP/URL）")
    result = fields.TextField(null=True, description="扫描结果（JSON格式）")
    ai_analysis = fields.TextField(null=True, description="AI分析结果（JSON格式）")
    status = fields.CharField(max_length=50, default="success", description="状态：success, failed")
    error_message = fields.TextField(null=True, description="错误信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "scan_results"
        table_description = "扫描结果表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.scan_type} - {self.target}"
    
    def is_success(self) -> bool:
        """检查扫描是否成功"""
        return self.status == "success"


class SystemSettings(Model):
    """
    系统设置表
    
    用于存储系统全局配置，支持动态更新。
    
    Attributes:
        id: 设置ID
        category: 设置分类（general, scan, notification, security等）
        key: 设置键名
        value: 设置值（字符串形式存储）
        value_type: 值类型（string, number, boolean, object, array）
        description: 设置描述
        is_public: 是否公开（非敏感配置）
        created_at: 创建时间
        updated_at: 更新时间
    """
    id = fields.IntField(primary_key=True, description="设置ID")
    category = fields.CharField(max_length=50, description="设置分类")
    key = fields.CharField(max_length=100, description="设置键名")
    value = fields.TextField(description="设置值")
    value_type = fields.CharField(max_length=20, default="string", description="值类型")
    description = fields.CharField(max_length=255, null=True, description="设置描述")
    is_public = fields.BooleanField(default=True, description="是否公开")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")

    class Meta:
        table = "system_settings"
        table_description = "系统设置表"
        unique_together = (("category", "key"),)

    def __str__(self):
        return f"{self.category}.{self.key} = {self.value}"

    def get_parsed_value(self):
        """获取解析后的值"""
        if self.value_type == "boolean":
            return self.value.lower() == "true"
        elif self.value_type == "number":
            try:
                return int(self.value)
            except ValueError:
                try:
                    return float(self.value)
                except ValueError:
                    return 0
        elif self.value_type in ["object", "array"]:
            try:
                return json.loads(self.value)
            except:
                return self.value
        return self.value


class SystemLog(Model):
    """
    系统日志表
    
    用于记录系统运行日志，包括操作日志、错误日志、访问日志等。
    支持按级别、模块、IP地址等维度查询和分析。
    
    Attributes:
        id: 日志唯一标识
        level: 日志级别，INFO（信息）、WARNING（警告）、ERROR（错误）
        module: 模块名称，标识日志来源模块
        message: 日志消息，具体的日志内容
        ip_address: 客户端IP地址，用于访问日志
        user_agent: 用户代理，记录客户端浏览器信息
        created_at: 日志记录时间
    """
    
    id = fields.IntField(primary_key=True, description="日志ID")
    level = fields.CharField(max_length=20, description="日志级别：DEBUG, INFO, WARNING, ERROR, CRITICAL")
    module = fields.CharField(max_length=100, null=True, description="模块名称")
    message = fields.TextField(description="日志消息内容")
    ip_address = fields.CharField(max_length=50, null=True, description="客户端IP地址")
    user_agent = fields.CharField(max_length=500, null=True, description="用户代理（User-Agent）")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "system_logs"
        table_description = "系统日志表"
        ordering = ["-created_at"]
        indexes = [
            ("level",),
            ("created_at",),
        ]
    
    def __str__(self):
        return f"[{self.level}] {self.message[:50]}..."
    
    def is_error(self) -> bool:
        """检查是否为错误日志"""
        return self.level in ["ERROR", "CRITICAL"]
    
    def is_warning(self) -> bool:
        """检查是否为警告日志"""
        return self.level == "WARNING"


class POCScanResult(Model):
    """
    POC（Proof of Concept）扫描结果表
    
    用于存储POC漏洞验证扫描的结果，验证目标是否存在已知漏洞。
    POC扫描结果与任务是一对多关系，一个任务可以扫描多个POC。
    
    Attributes:
        id: 结果唯一标识
        task: 关联的任务对象，外键关联到Task表
        poc_type: POC类型，如weblogic_cve_2020_2551、struts2_009等
        target: 扫描目标，域名、IP或URL
        vulnerable: 是否存在漏洞，True表示存在漏洞，False表示安全
        message: 扫描结果消息，详细说明扫描情况
        severity: 漏洞严重程度，high（高危）、medium（中危）、low（低危）
        cve_id: CVE编号，如CVE-2020-2551
        created_at: 扫描时间
    """
    
    id = fields.IntField(primary_key=True, description="结果ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="poc_results", description="关联任务"
    )
    poc_type = fields.CharField(max_length=100, description="POC类型：weblogic_cve_2020_2551, struts2_009, etc.")
    target = fields.CharField(max_length=500, description="扫描目标（域名/IP/URL）")
    vulnerable = fields.BooleanField(default=False, description="是否存在漏洞")
    message = fields.TextField(null=True, description="扫描结果消息")
    severity = fields.CharField(max_length=20, null=True, description="严重程度：critical, high, medium, low")
    cve_id = fields.CharField(max_length=50, null=True, description="CVE编号（如CVE-2020-2551）")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "poc_scan_results"
        table_description = "POC扫描结果表"
        ordering = ["-created_at"]
        indexes = [
            ("poc_type",),
            ("vulnerable",),
        ]
    
    def __str__(self):
        return f"{self.poc_type} - {self.target} ({'存在漏洞' if self.vulnerable else '安全'})"
    
    def is_vulnerable(self) -> bool:
        """检查是否存在漏洞"""
        return self.vulnerable
    
    def is_critical(self) -> bool:
        """检查是否为高危漏洞"""
        return self.vulnerable and self.severity in ["critical", "high"]


class AIChatInstance(Model):
    """
    AI对话实例表
    
    用于管理AI对话会话，支持多轮对话、对话历史记录等功能。
    对话实例与消息是一对多关系，一个对话实例包含多条消息。
    
    Attributes:
        id: 对话实例唯一标识（UUID）
        user_id: 用户ID，标识对话所属用户
        chat_name: 对话名称，便于用户识别和管理
        chat_type: 对话类型，如general（通用对话）、security（安全咨询）等
        status: 对话状态，active（活跃）、closed（已关闭）
        created_at: 对话创建时间
        updated_at: 对话最后更新时间
    """
    
    id = fields.UUIDField(primary_key=True, description="对话实例ID（UUID）")
    user_id = fields.CharField(max_length=100, null=True, description="用户ID")
    chat_name = fields.CharField(max_length=255, default="新对话", description="对话名称")
    chat_type = fields.CharField(max_length=50, default="general", description="对话类型：general, security, code_analysis, etc.")
    status = fields.CharField(max_length=50, default="active", description="状态：active, closed, archived")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    # 关系定义
    messages: fields.ReverseRelation["AIChatMessage"]
    
    class Meta:
        table = "ai_chat_instances"
        table_description = "AI对话实例表"
        ordering = ["-updated_at"]
        indexes = [
            ("user_id",),
            ("status",),
        ]
    
    def __str__(self):
        return f"{self.chat_name} ({self.status})"
    
    def is_active(self) -> bool:
        """检查对话是否活跃"""
        return self.status == "active"
    
    def is_closed(self) -> bool:
        """检查对话是否已关闭"""
        return self.status == "closed"
    
    def get_message_count(self) -> int:
        """获取对话消息数量（需要异步调用）"""
        return len(self.messages) if hasattr(self, 'messages') else 0


class AIChatMessage(Model):
    """
    AI对话消息表
    
    用于存储AI对话中的每条消息，包括用户消息和AI回复。
    消息与对话实例是多对一关系，一条消息属于一个对话实例。
    
    Attributes:
        id: 消息唯一标识（自增整数）
        chat_instance: 关联的对话实例对象，外键关联到AIChatInstance表
        role: 消息角色，user（用户消息）、assistant（AI回复）、system（系统消息）
        content: 消息内容，文本或JSON格式
        message_type: 消息类型，text（文本）、image（图片）、code（代码）等
        created_at: 消息创建时间
    """
    
    id = fields.BigIntField(primary_key=True, description="消息ID（自增）")
    chat_instance: fields.ForeignKeyRelation[AIChatInstance] = fields.ForeignKeyField(
        "models.AIChatInstance", related_name="messages", description="关联对话实例"
    )
    role = fields.CharField(max_length=20, description="角色：user, assistant, system")
    content = fields.TextField(description="消息内容")
    message_type = fields.CharField(max_length=50, default="text", description="消息类型：text, image, code, file, etc.")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "ai_chat_messages"
        table_description = "AI对话消息表"
        ordering = ["created_at"]
        indexes = [
            ("chat_instance",),
            ("role",),
        ]
    
    def __str__(self):
        return f"{self.role}: {self.content[:50]}..."
    
    def is_user_message(self) -> bool:
        """检查是否为用户消息"""
        return self.role == "user"
    
    def is_assistant_message(self) -> bool:
        """检查是否为AI回复"""
        return self.role == "assistant"


class AgentTask(Model):
    """
    AI Agent 任务记录表
    
    用于记录AI Agent的自动化任务，如代码生成、漏洞分析、报告生成等。
    Agent任务与结果是一对一关系，一个任务对应一个执行结果。
    
    Attributes:
        task_id: 任务唯一标识（UUID）
        user_id: 用户ID，标识任务所属用户
        input_json: 用户输入的内容，JSON格式存储任务参数
        task_type: 任务类型，如code_generation（代码生成）、vuln_analysis（漏洞分析）等
        status: 任务状态，pending（待执行）、running（执行中）、completed（已完成）、failed（失败）
        created_at: 任务创建时间
        updated_at: 任务最后更新时间
    """
    
    task_id = fields.UUIDField(primary_key=True, description="任务ID（UUID）")
    user_id = fields.CharField(max_length=100, null=True, description="用户ID")
    input_json = fields.TextField(description="用户输入内容（JSON格式）")
    task_type = fields.CharField(max_length=50, null=True, description="任务类型：code_generation, vuln_analysis, report_generation, etc.")
    status = fields.CharField(max_length=50, default="pending", description="状态：pending, running, completed, failed, cancelled")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    # 关系定义
    result: fields.ReverseRelation["AgentResult"]
    
    class Meta:
        table = "agent_tasks"
        table_description = "AI Agent 任务记录表"
        ordering = ["-created_at"]
        indexes = [
            ("user_id",),
            ("status",),
            ("task_type",),
        ]
    
    def __str__(self):
        return f"AgentTask {self.task_id} ({self.status})"
    
    def is_running(self) -> bool:
        """检查任务是否正在运行"""
        return self.status == "running"
    
    def is_completed(self) -> bool:
        """检查任务是否已完成"""
        return self.status == "completed"
    
    def is_failed(self) -> bool:
        """检查任务是否失败"""
        return self.status == "failed"


class AgentResult(Model):
    """
    AI Agent 执行结果表
    
    用于存储AI Agent任务的执行结果，包括输出内容、执行时间、错误信息等。
    结果与任务是多对一关系，一个结果对应一个任务。
    
    Attributes:
        id: 结果唯一标识（UUID）
        task: 关联的任务对象，外键关联到AgentTask表
        final_output: AI输出的结果，JSON格式存储结构化数据
        execution_time: 执行时间，单位为秒
        error_message: 错误信息，记录任务执行失败原因
        created_at: 结果创建时间
    """
    
    id = fields.UUIDField(primary_key=True, description="结果ID（UUID）")
    task: fields.ForeignKeyRelation[AgentTask] = fields.ForeignKeyField(
        "models.AgentTask", related_name="result", description="关联任务"
    )
    final_output = fields.TextField(description="AI输出结果（JSON格式）")
    execution_time = fields.FloatField(null=True, description="执行时间（秒）")
    error_message = fields.TextField(null=True, description="错误信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "agent_results"
        table_description = "AI Agent 执行结果表"
        ordering = ["-created_at"]
        indexes = [
            ("task",),
        ]
    
    def __str__(self):
        return f"AgentResult {self.id} for Task {self.task.task_id}"
    
    def is_success(self) -> bool:
        """检查执行是否成功"""
        return self.error_message is None
    
    def has_error(self) -> bool:
        """检查是否有错误"""
        return self.error_message is not None


class VulnerabilityKB(Model):
    """
    漏洞知识库表
    
    用于存储和管理漏洞知识库信息，包括CVE漏洞详情、POC代码、修复建议等。
    知识库用于支持AI Agent进行漏洞分析和POC生成。
    
    Attributes:
        id: 知识库唯一标识
        cve_id: CVE编号，如CVE-2021-44228，唯一标识漏洞
        name: 漏洞名称，简洁描述漏洞
        description: 漏洞详细描述，说明漏洞原理、影响范围等
        severity: 严重程度，critical（严重）、high（高危）、medium（中危）、low（低危）
        cvss_score: CVSS评分，0.0-10.0的数值评分
        affected_product: 受影响的产品或组件，如Apache Log4j、Spring Framework等
        affected_versions: 受影响的版本范围
        poc_code: POC代码，用于验证漏洞
        remediation: 修复建议，提供漏洞修复方案
        references: 参考链接，JSON格式存储多个URL
        created_at: 记录创建时间
        updated_at: 记录最后更新时间
    """
    
    id = fields.IntField(primary_key=True, description="知识库ID")
    cve_id = fields.CharField(max_length=50, unique=True, description="CVE编号（如CVE-2021-44228）")
    name = fields.CharField(max_length=255, description="漏洞名称")
    description = fields.TextField(null=True, description="漏洞详细描述")
    severity = fields.CharField(max_length=20, description="严重程度：critical, high, medium, low")
    cvss_score = fields.FloatField(null=True, description="CVSS评分（0.0-10.0）")
    affected_product = fields.CharField(max_length=255, null=True, description="受影响产品")
    affected_versions = fields.CharField(max_length=255, null=True, description="受影响版本")
    poc_code = fields.TextField(null=True, description="POC代码")
    remediation = fields.TextField(null=True, description="修复建议")
    references = fields.TextField(null=True, description="参考链接（JSON格式）")
    source = fields.CharField(max_length=50, null=True, description="数据源（seebug, exploit-db等）")
    has_poc = fields.BooleanField(default=False, description="是否有POC")
    ssvid = fields.IntField(null=True, description="Seebug SSVID")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    class Meta:
        table = "vulnerability_kb"
        table_description = "漏洞知识库表"
        ordering = ["-created_at"]
        indexes = [
            ("cve_id",),
            ("severity",),
        ]
    
    def __str__(self):
        return f"{self.cve_id} - {self.name}"
    
    def is_critical(self) -> bool:
        """检查是否为高危漏洞"""
        return self.severity in ["critical", "high"]


class POCVerificationTask(Model):
    """
    POC验证子任务表 (用于DynamicVerificationEngine内部调度)
    
    Attributes:
        id: 任务唯一标识（UUID）
        poc_id: POC ID
        target: 验证目标
        status: 状态
        poc_name: POC名称
        priority: 优先级
        progress: 进度
        config: 配置信息
        created_at: 创建时间
        updated_at: 更新时间
    """
    id = fields.UUIDField(primary_key=True, description="任务ID")
    poc_id = fields.CharField(max_length=100, description="POC ID")
    target = fields.CharField(max_length=500, description="验证目标")
    status = fields.CharField(max_length=50, default="pending", description="状态")
    poc_name = fields.CharField(max_length=255, description="POC名称")
    priority = fields.IntField(default=5, description="优先级(1-10)")
    progress = fields.FloatField(default=0.0, description="进度(0-100)")
    config = fields.JSONField(null=True, default=dict, description="配置信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    results: fields.ReverseRelation["POCVerificationResult"]
    
    class Meta:
        table = "poc_verification_tasks"
        table_description = "POC验证子任务表"

class POCVerificationResult(Model):
    """
    POC验证结果详情 (用于DynamicVerificationEngine)
    
    Attributes:
        id: 结果唯一标识（UUID）
        verification_task: 关联的验证任务
        poc_name: POC名称
        poc_id: POC ID
        target: 验证目标
        vulnerable: 是否存在漏洞
        message: 结果消息
        output: 验证输出
        error: 错误信息
        execution_time: 执行时间
        confidence: 置信度
        severity: 严重程度
        cvss_score: CVSS评分
        analysis: AI分析结果（JSON格式）
        created_at: 创建时间
    """
    id = fields.UUIDField(primary_key=True, description="结果ID")
    verification_task: fields.ForeignKeyRelation[POCVerificationTask] = fields.ForeignKeyField(
        "models.POCVerificationTask", related_name="results", description="关联验证任务"
    )
    poc_name = fields.CharField(max_length=255, description="POC名称")
    poc_id = fields.CharField(max_length=100, description="POC ID")
    target = fields.CharField(max_length=500, description="验证目标")
    vulnerable = fields.BooleanField(default=False, description="是否存在漏洞")
    message = fields.TextField(null=True, description="结果消息")
    output = fields.TextField(null=True, description="验证输出")
    error = fields.TextField(null=True, description="错误信息")
    execution_time = fields.FloatField(default=0.0, description="执行时间(秒)")
    confidence = fields.FloatField(default=0.0, description="置信度(0-1)")
    severity = fields.CharField(max_length=20, null=True, description="严重程度")
    cvss_score = fields.FloatField(default=0.0, description="CVSS评分")
    analysis = fields.JSONField(null=True, default=dict, description="AI分析结果（JSON格式）")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "poc_verification_results"
        table_description = "POC验证结果详情表"

class POCExecutionLog(Model):
    """
    POC执行日志
    
    Attributes:
        id: 日志ID
        task_id: 关联的任务ID
        message: 日志内容
        level: 日志级别
        created_at: 创建时间
    """
    id = fields.IntField(primary_key=True, description="日志ID")
    task_id = fields.CharField(max_length=100, description="任务ID")
    message = fields.TextField(description="日志内容")
    level = fields.CharField(max_length=20, default="INFO", description="日志级别")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "poc_execution_logs"
        table_description = "POC执行日志表"


class User(Model):
    """
    用户表
    
    用于存储和管理系统用户信息，包括用户基本信息、角色权限等。
    
    Attributes:
        id: 用户唯一标识
        username: 用户名，唯一标识用户
        email: 邮箱地址，用于登录和通知
        password_hash: 密码哈希值，存储加密后的密码
        role: 用户角色，如administrator（管理员）、user（普通用户）等
        avatar: 头像URL地址
        last_login: 最后登录时间
        is_active: 是否激活，False表示用户被禁用
        created_at: 用户创建时间
        updated_at: 用户信息最后更新时间
    """
    
    id = fields.IntField(primary_key=True, description="用户ID")
    username = fields.CharField(max_length=100, unique=True, description="用户名")
    email = fields.CharField(max_length=255, unique=True, description="邮箱地址")
    password_hash = fields.CharField(max_length=255, null=True, description="密码哈希值")
    role = fields.CharField(max_length=50, default="user", description="用户角色：administrator, user, etc.")
    avatar = fields.CharField(max_length=500, null=True, description="头像URL")
    last_login = fields.DatetimeField(null=True, description="最后登录时间")
    is_active = fields.BooleanField(default=True, description="是否激活")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    # 关系定义
    notifications: fields.ReverseRelation["Notification"]
    
    class Meta:
        table = "users"
        app = "models"
        table_description = "用户表"
        ordering = ["-created_at"]
        indexes = [
            ("username",),
            ("email",),
            ("role",),
        ]
    
    def __str__(self):
        return f"{self.username} ({self.role})"
    
    def is_administrator(self) -> bool:
        """检查是否为管理员"""
        return self.role == "administrator"
    
    def is_active_user(self) -> bool:
        """检查用户是否激活"""
        return self.is_active
    
    def get_permissions(self) -> list:
        """获取用户权限列表"""
        if self.role == "administrator":
            return [
                "scan:create",
                "scan:read",
                "scan:update",
                "scan:delete",
                "report:generate",
                "report:read",
                "report:delete",
                "settings:manage",
                "user:manage"
            ]
        else:
            return [
                "scan:create",
                "scan:read",
                "report:generate",
                "report:read"
            ]


class Notification(Model):
    """
    通知表
    
    用于存储和管理用户通知信息，包括系统通知、漏洞告警等。
    通知与用户是多对一关系，一个用户可以接收多个通知。
    
    Attributes:
        id: 通知唯一标识
        user: 关联的用户对象，外键关联到User表
        title: 通知标题
        message: 通知详细内容
        type: 通知类型，如high-vulnerability（高危漏洞）、system（系统通知）等
        read: 是否已读，True表示已读，False表示未读
        created_at: 通知创建时间
    """
    
    id = fields.IntField(primary_key=True, description="通知ID")
    user: fields.ForeignKeyRelation[User] = fields.ForeignKeyField(
        "models.User", related_name="notifications", description="关联用户"
    )
    title = fields.CharField(max_length=255, description="通知标题")
    message = fields.TextField(description="通知详细内容")
    type = fields.CharField(max_length=50, default="system", description="通知类型：high-vulnerability, medium-vulnerability, system, etc.")
    read = fields.BooleanField(default=False, description="是否已读")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "notifications"
        app = "models"
        table_description = "通知表"
        ordering = ["-created_at"]
        indexes = [
            ("user_id",),
            ("read",),
            ("type",),
        ]
    
    def __str__(self):
        return f"{self.title} ({'已读' if self.read else '未读'})"
    
    def is_unread(self) -> bool:
        """检查通知是否未读"""
        return not self.read
    
    def is_high_priority(self) -> bool:
        """检查是否为高优先级通知"""
        return self.type in ["high-vulnerability", "critical-vulnerability"]


class WorkflowExecution(Model):
    """
    工作流执行记录表
    
    用于记录AI Agent工作流的执行状态、进度和结果。
    工作流与节点执行是一对多关系。
    
    Attributes:
        id: 工作流唯一标识
        task_id: 关联的任务ID
        workflow_name: 工作流名称
        target: 执行目标
        status: 工作流状态
        progress: 执行进度
        start_time: 开始时间
        end_time: 结束时间
        duration: 执行时长（秒）
        graph_flow: 图流数据（JSON格式）
        vulnerabilities: 发现的漏洞（JSON格式）
        tool_results: 工具执行结果（JSON格式）
        metadata: 元数据（JSON格式）
        created_at: 创建时间
        updated_at: 更新时间
    """
    
    id = fields.UUIDField(primary_key=True, description="工作流ID")
    task_id = fields.CharField(max_length=100, null=True, description="关联任务ID")
    workflow_name = fields.CharField(max_length=255, default="AI Security Scan", description="工作流名称")
    target = fields.CharField(max_length=500, description="执行目标")
    status = fields.CharField(max_length=50, default="pending", description="状态：pending, running, completed, failed, cancelled")
    progress = fields.IntField(default=0, description="执行进度 0-100")
    start_time = fields.FloatField(null=True, description="开始时间戳")
    end_time = fields.FloatField(null=True, description="结束时间戳")
    duration = fields.FloatField(null=True, description="执行时长（秒）")
    current_step = fields.CharField(max_length=255, null=True, description="当前步骤")
    total_steps = fields.IntField(default=0, description="总步骤数")
    completed_steps = fields.IntField(default=0, description="已完成步骤数")
    graph_flow = fields.JSONField(null=True, default=dict, description="图流数据")
    vulnerabilities = fields.JSONField(null=True, default=list, description="发现的漏洞")
    tool_results = fields.JSONField(null=True, default=dict, description="工具执行结果")
    metadata = fields.JSONField(null=True, default=dict, description="元数据")
    error_message = fields.TextField(null=True, description="错误信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    node_executions: fields.ReverseRelation["WorkflowNodeExecution"]
    task_plans: fields.ReverseRelation["WorkflowTaskPlan"]
    
    class Meta:
        table = "workflow_executions"
        table_description = "工作流执行记录表"
        ordering = ["-created_at"]
        indexes = [
            ("task_id",),
            ("status",),
            ("target",),
        ]
    
    def __str__(self):
        return f"Workflow {self.id} - {self.target} ({self.status})"
    
    def is_running(self) -> bool:
        return self.status == "running"
    
    def is_completed(self) -> bool:
        return self.status == "completed"
    
    def is_failed(self) -> bool:
        return self.status == "failed"


class WorkflowNodeExecution(Model):
    """
    工作流节点执行记录表
    
    用于记录工作流中每个节点的执行详情。
    节点执行与工作流是多对一关系。
    
    Attributes:
        id: 节点执行唯一标识
        workflow: 关联的工作流对象
        node_id: 节点ID
        node_name: 节点名称
        node_type: 节点类型
        status: 执行状态
        step_number: 步骤序号
        start_time: 开始时间戳
        end_time: 结束时间戳
        duration_ms: 执行耗时（毫秒）
        execution_time: 执行时间（秒）
        input_params: 输入参数（JSON格式）
        output_data: 输出数据（JSON格式）
        error: 错误信息
        task: 任务名称
        tool_name: 工具名称
        timestamp: 时间戳
        metadata: 元数据（JSON格式）
        created_at: 创建时间
    """
    
    id = fields.BigIntField(primary_key=True, description="节点执行ID")
    workflow: fields.ForeignKeyRelation[WorkflowExecution] = fields.ForeignKeyField(
        "models.WorkflowExecution", related_name="node_executions", description="关联工作流"
    )
    node_id = fields.CharField(max_length=100, description="节点ID")
    node_name = fields.CharField(max_length=255, description="节点名称")
    node_type = fields.CharField(max_length=100, default="unknown", description="节点类型")
    status = fields.CharField(max_length=50, default="pending", description="状态：pending, running, success, failed, skipped")
    step_number = fields.IntField(default=0, description="步骤序号")
    start_time = fields.FloatField(null=True, description="开始时间戳")
    end_time = fields.FloatField(null=True, description="结束时间戳")
    duration_ms = fields.FloatField(null=True, description="执行耗时（毫秒）")
    execution_time = fields.FloatField(null=True, description="执行时间（秒）")
    input_params = fields.JSONField(null=True, default=dict, description="输入参数")
    output_data = fields.JSONField(null=True, default=dict, description="输出数据")
    error = fields.TextField(null=True, description="错误信息")
    error_message = fields.TextField(null=True, description="错误消息")
    task = fields.CharField(max_length=255, null=True, description="任务名称")
    tool_name = fields.CharField(max_length=100, null=True, description="工具名称")
    timestamp = fields.FloatField(null=True, description="时间戳")
    timestamp_iso = fields.CharField(max_length=50, null=True, description="ISO格式时间戳")
    metadata = fields.JSONField(null=True, default=dict, description="元数据")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "workflow_node_executions"
        table_description = "工作流节点执行记录表"
        ordering = ["step_number", "created_at"]
        indexes = [
            ("workflow",),
            ("node_id",),
            ("status",),
        ]
    
    def __str__(self):
        return f"Node {self.node_name} - {self.status}"
    
    def is_success(self) -> bool:
        return self.status == "success"
    
    def is_failed(self) -> bool:
        return self.status == "failed"


class WorkflowTaskPlan(Model):
    """
    工作流任务规划表
    
    用于记录AI Agent生成的任务规划信息。
    任务规划与工作流是多对一关系。
    
    Attributes:
        id: 任务规划唯一标识
        workflow: 关联的工作流对象
        plan_id: 规划ID
        plan_name: 规划名称
        plan_type: 规划类型
        priority: 优先级
        status: 执行状态
        dependencies: 依赖任务（JSON格式）
        estimated_time: 预估时间（秒）
        actual_time: 实际时间（秒）
        parameters: 参数（JSON格式）
        result: 执行结果（JSON格式）
        created_at: 创建时间
        updated_at: 更新时间
    """
    
    id = fields.BigIntField(primary_key=True, description="任务规划ID")
    workflow: fields.ForeignKeyRelation[WorkflowExecution] = fields.ForeignKeyField(
        "models.WorkflowExecution", related_name="task_plans", description="关联工作流"
    )
    plan_id = fields.CharField(max_length=100, description="规划ID")
    plan_name = fields.CharField(max_length=255, description="规划名称")
    plan_type = fields.CharField(max_length=100, default="scan", description="规划类型")
    priority = fields.IntField(default=5, description="优先级 1-10")
    status = fields.CharField(max_length=50, default="pending", description="状态：pending, running, completed, failed, skipped")
    dependencies = fields.JSONField(null=True, default=list, description="依赖任务")
    estimated_time = fields.FloatField(null=True, description="预估时间（秒）")
    actual_time = fields.FloatField(null=True, description="实际时间（秒）")
    parameters = fields.JSONField(null=True, default=dict, description="参数")
    result = fields.JSONField(null=True, default=dict, description="执行结果")
    error_message = fields.TextField(null=True, description="错误信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    class Meta:
        table = "workflow_task_plans"
        table_description = "工作流任务规划表"
        ordering = ["priority", "created_at"]
        indexes = [
            ("workflow",),
            ("plan_id",),
            ("status",),
        ]
    
    def __str__(self):
        return f"Plan {self.plan_name} - {self.status}"
    
    def is_completed(self) -> bool:
        return self.status == "completed"
    
    def is_failed(self) -> bool:
        return self.status == "failed"
