from tortoise import BaseDBAsyncClient


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "ai_chat_instances" (
    "id" CHAR(36) NOT NULL  PRIMARY KEY /* 对话实例ID（UUID） */,
    "user_id" VARCHAR(100)   /* 用户ID */,
    "chat_name" VARCHAR(255) NOT NULL  DEFAULT '新对话' /* 对话名称 */,
    "chat_type" VARCHAR(50) NOT NULL  DEFAULT 'general' /* 对话类型：general, security, code_analysis, etc. */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'active' /* 状态：active, closed, archived */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */
) /* AI对话实例表 */;
CREATE INDEX IF NOT EXISTS "idx_ai_chat_ins_user_id_66ae88" ON "ai_chat_instances" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_ai_chat_ins_status_f1bbc1" ON "ai_chat_instances" ("status");
CREATE TABLE IF NOT EXISTS "ai_chat_messages" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 消息ID（自增） */,
    "role" VARCHAR(20) NOT NULL  /* 角色：user, assistant, system */,
    "content" TEXT NOT NULL  /* 消息内容 */,
    "message_type" VARCHAR(50) NOT NULL  DEFAULT 'text' /* 消息类型：text, image, code, file, etc. */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "chat_instance_id" CHAR(36) NOT NULL REFERENCES "ai_chat_instances" ("id") ON DELETE CASCADE /* 关联对话实例 */
) /* AI对话消息表 */;
CREATE INDEX IF NOT EXISTS "idx_ai_chat_mes_chat_in_875e55" ON "ai_chat_messages" ("chat_instance_id");
CREATE INDEX IF NOT EXISTS "idx_ai_chat_mes_role_16e470" ON "ai_chat_messages" ("role");
CREATE TABLE IF NOT EXISTS "agent_tasks" (
    "task_id" CHAR(36) NOT NULL  PRIMARY KEY /* 任务ID（UUID） */,
    "user_id" VARCHAR(100)   /* 用户ID */,
    "input_json" TEXT NOT NULL  /* 用户输入内容（JSON格式） */,
    "task_type" VARCHAR(50)   /* 任务类型：code_generation, vuln_analysis, report_generation, etc. */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'pending' /* 状态：pending, running, completed, failed, cancelled */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */
) /* AI Agent 任务记录表 */;
CREATE INDEX IF NOT EXISTS "idx_agent_tasks_user_id_cd3d79" ON "agent_tasks" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_agent_tasks_status_48e0c2" ON "agent_tasks" ("status");
CREATE INDEX IF NOT EXISTS "idx_agent_tasks_task_ty_f996b3" ON "agent_tasks" ("task_type");
CREATE TABLE IF NOT EXISTS "agent_results" (
    "id" CHAR(36) NOT NULL  PRIMARY KEY /* 结果ID（UUID） */,
    "final_output" TEXT NOT NULL  /* AI输出结果（JSON格式） */,
    "execution_time" REAL   /* 执行时间（秒） */,
    "error_message" TEXT   /* 错误信息 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "task_id" CHAR(36) NOT NULL REFERENCES "agent_tasks" ("task_id") ON DELETE CASCADE /* 关联任务 */
) /* AI Agent 执行结果表 */;
CREATE INDEX IF NOT EXISTS "idx_agent_resul_task_id_cbb22d" ON "agent_results" ("task_id");
CREATE TABLE IF NOT EXISTS "poc_execution_logs" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 日志ID */,
    "task_id" VARCHAR(100) NOT NULL  /* 任务ID */,
    "message" TEXT NOT NULL  /* 日志内容 */,
    "level" VARCHAR(20) NOT NULL  DEFAULT 'INFO' /* 日志级别 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */
) /* POC执行日志表 */;
CREATE TABLE IF NOT EXISTS "poc_verification_tasks" (
    "id" CHAR(36) NOT NULL  PRIMARY KEY /* 任务ID */,
    "poc_id" VARCHAR(100) NOT NULL  /* POC ID */,
    "target" VARCHAR(500) NOT NULL  /* 验证目标 */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'pending' /* 状态 */,
    "poc_name" VARCHAR(255) NOT NULL  /* POC名称 */,
    "priority" INT NOT NULL  DEFAULT 5 /* 优先级(1-10) */,
    "progress" REAL NOT NULL  DEFAULT 0 /* 进度(0-100) */,
    "config" JSON   /* 配置信息 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */
) /* POC验证子任务表 */;
CREATE TABLE IF NOT EXISTS "poc_verification_results" (
    "id" CHAR(36) NOT NULL  PRIMARY KEY /* 结果ID */,
    "poc_name" VARCHAR(255) NOT NULL  /* POC名称 */,
    "poc_id" VARCHAR(100) NOT NULL  /* POC ID */,
    "target" VARCHAR(500) NOT NULL  /* 验证目标 */,
    "vulnerable" INT NOT NULL  DEFAULT 0 /* 是否存在漏洞 */,
    "message" TEXT   /* 结果消息 */,
    "output" TEXT   /* 验证输出 */,
    "error" TEXT   /* 错误信息 */,
    "execution_time" REAL NOT NULL  DEFAULT 0 /* 执行时间(秒) */,
    "confidence" REAL NOT NULL  DEFAULT 0 /* 置信度(0-1) */,
    "severity" VARCHAR(20)   /* 严重程度 */,
    "cvss_score" REAL NOT NULL  DEFAULT 0 /* CVSS评分 */,
    "analysis" JSON   /* AI分析结果（JSON格式） */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "verification_task_id" CHAR(36) NOT NULL REFERENCES "poc_verification_tasks" ("id") ON DELETE CASCADE /* 关联验证任务 */
) /* POC验证结果详情表 */;
CREATE TABLE IF NOT EXISTS "system_logs" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 日志ID */,
    "level" VARCHAR(20) NOT NULL  /* 日志级别：DEBUG, INFO, WARNING, ERROR, CRITICAL */,
    "module" VARCHAR(100)   /* 模块名称 */,
    "message" TEXT NOT NULL  /* 日志消息内容 */,
    "ip_address" VARCHAR(50)   /* 客户端IP地址 */,
    "user_agent" VARCHAR(500)   /* 用户代理（User-Agent） */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */
) /* 系统日志表 */;
CREATE INDEX IF NOT EXISTS "idx_system_logs_level_607a60" ON "system_logs" ("level");
CREATE INDEX IF NOT EXISTS "idx_system_logs_created_ec52ee" ON "system_logs" ("created_at");
CREATE TABLE IF NOT EXISTS "system_settings" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 设置ID */,
    "category" VARCHAR(50) NOT NULL  /* 设置分类 */,
    "key" VARCHAR(100) NOT NULL  /* 设置键名 */,
    "value" TEXT NOT NULL  /* 设置值 */,
    "value_type" VARCHAR(20) NOT NULL  DEFAULT 'string' /* 值类型 */,
    "description" VARCHAR(255)   /* 设置描述 */,
    "is_public" INT NOT NULL  DEFAULT 1 /* 是否公开 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    CONSTRAINT "uid_system_sett_categor_629d12" UNIQUE ("category", "key")
) /* 系统设置表 */;
CREATE TABLE IF NOT EXISTS "tasks" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 任务ID */,
    "task_name" VARCHAR(255) NOT NULL  /* 任务名称 */,
    "task_type" VARCHAR(50) NOT NULL  /* 任务类型：scan, vulnerability, poc, etc. */,
    "target" VARCHAR(500) NOT NULL  /* 扫描目标（域名\/IP\/URL） */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'pending' /* 状态：pending, running, completed, failed, cancelled */,
    "progress" INT NOT NULL  DEFAULT 0 /* 任务进度 0-100 */,
    "config" TEXT   /* 任务配置信息（JSON格式） */,
    "result" TEXT   /* 任务执行结果（JSON格式） */,
    "error_message" TEXT   /* 错误信息 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */
) /* 扫描任务表 */;
CREATE TABLE IF NOT EXISTS "poc_scan_results" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 结果ID */,
    "poc_type" VARCHAR(100) NOT NULL  /* POC类型：weblogic_cve_2020_2551, struts2_009, etc. */,
    "target" VARCHAR(500) NOT NULL  /* 扫描目标（域名\/IP\/URL） */,
    "vulnerable" INT NOT NULL  DEFAULT 0 /* 是否存在漏洞 */,
    "message" TEXT   /* 扫描结果消息 */,
    "severity" VARCHAR(20)   /* 严重程度：critical, high, medium, low */,
    "cve_id" VARCHAR(50)   /* CVE编号（如CVE-2020-2551） */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "task_id" INT NOT NULL REFERENCES "tasks" ("id") ON DELETE CASCADE /* 关联任务 */
) /* POC扫描结果表 */;
CREATE INDEX IF NOT EXISTS "idx_poc_scan_re_poc_typ_d1fd36" ON "poc_scan_results" ("poc_type");
CREATE INDEX IF NOT EXISTS "idx_poc_scan_re_vulnera_839e01" ON "poc_scan_results" ("vulnerable");
CREATE TABLE IF NOT EXISTS "reports" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 报告ID */,
    "report_name" VARCHAR(255) NOT NULL  /* 报告名称 */,
    "report_type" VARCHAR(50) NOT NULL  /* 报告类型：pdf, html, json, docx, etc. */,
    "content" TEXT   /* 报告内容（JSON格式） */,
    "file_path" VARCHAR(500)   /* 报告文件存储路径 */,
    "ai_analysis" TEXT   /* AI分析结果（JSON格式） */,
    "analyzed_at" TIMESTAMP   /* AI分析时间 */,
    "analysis_model" VARCHAR(100)   /* 分析模型 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "task_id" INT NOT NULL REFERENCES "tasks" ("id") ON DELETE CASCADE /* 关联任务 */
) /* 扫描报告表 */;
CREATE TABLE IF NOT EXISTS "scan_results" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 结果ID */,
    "scan_type" VARCHAR(50) NOT NULL  /* 扫描类型：port_scan, subdomain, directory, etc. */,
    "target" VARCHAR(500) NOT NULL  /* 扫描目标（域名\/IP\/URL） */,
    "result" TEXT   /* 扫描结果（JSON格式） */,
    "ai_analysis" TEXT   /* AI分析结果（JSON格式） */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'success' /* 状态：success, failed */,
    "error_message" TEXT   /* 错误信息 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "task_id" INT NOT NULL REFERENCES "tasks" ("id") ON DELETE CASCADE /* 关联任务 */
) /* 扫描结果表 */;
CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 用户ID */,
    "username" VARCHAR(100) NOT NULL UNIQUE /* 用户名 */,
    "email" VARCHAR(255) NOT NULL UNIQUE /* 邮箱地址 */,
    "password_hash" VARCHAR(255)   /* 密码哈希值 */,
    "role" VARCHAR(50) NOT NULL  DEFAULT 'user' /* 用户角色：administrator, user, etc. */,
    "avatar" VARCHAR(500)   /* 头像URL */,
    "last_login" TIMESTAMP   /* 最后登录时间 */,
    "is_active" INT NOT NULL  DEFAULT 1 /* 是否激活 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */
) /* 用户表 */;
CREATE INDEX IF NOT EXISTS "idx_users_usernam_266d85" ON "users" ("username");
CREATE INDEX IF NOT EXISTS "idx_users_email_133a6f" ON "users" ("email");
CREATE INDEX IF NOT EXISTS "idx_users_role_35db31" ON "users" ("role");
CREATE TABLE IF NOT EXISTS "notifications" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 通知ID */,
    "title" VARCHAR(255) NOT NULL  /* 通知标题 */,
    "message" TEXT NOT NULL  /* 通知详细内容 */,
    "type" VARCHAR(50) NOT NULL  DEFAULT 'system' /* 通知类型：high-vulnerability, medium-vulnerability, system, etc. */,
    "read" INT NOT NULL  DEFAULT 0 /* 是否已读 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "user_id" INT NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE /* 关联用户 */
) /* 通知表 */;
CREATE INDEX IF NOT EXISTS "idx_notificatio_user_id_daa173" ON "notifications" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_notificatio_read_2f2041" ON "notifications" ("read");
CREATE INDEX IF NOT EXISTS "idx_notificatio_type_40b578" ON "notifications" ("type");
CREATE TABLE IF NOT EXISTS "vulnerabilities" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 漏洞ID */,
    "vuln_type" VARCHAR(255) NOT NULL  /* 漏洞类型：XSS, SQLInjection, CSRF, RCE, SSRF, etc. */,
    "severity" VARCHAR(20) NOT NULL  /* 严重程度：critical, high, medium, low, info */,
    "title" VARCHAR(255) NOT NULL  /* 漏洞标题 */,
    "description" TEXT   /* 漏洞详细描述 */,
    "url" VARCHAR(500)   /* 漏洞URL地址 */,
    "payload" TEXT   /* 测试Payload */,
    "evidence" TEXT   /* 漏洞证据（截图\/响应数据等） */,
    "remediation" TEXT   /* 修复建议 */,
    "ai_analysis" TEXT   /* AI分析结果（JSON格式） */,
    "risk_score" REAL   /* AI评估风险分数 */,
    "fix_priority" INT   /* 修复优先级 */,
    "cvss_score" REAL   /* CVSS评分（0-10） */,
    "affected_product" VARCHAR(500)   /* 受影响的产品\/组件 */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'open' /* 状态：open, fixed, ignored, false_positive */,
    "source_id" VARCHAR(100)   /* 来源ID (如AWVS vuln_id) */,
    "source" VARCHAR(20) NOT NULL  DEFAULT 'awvs' /* 来源：awvs, poc */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "task_id" INT NOT NULL REFERENCES "tasks" ("id") ON DELETE CASCADE /* 关联任务 */
) /* 漏洞信息表 */;
CREATE TABLE IF NOT EXISTS "vulnerability_kb" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 知识库ID */,
    "cve_id" VARCHAR(50) NOT NULL UNIQUE /* CVE编号（如CVE-2021-44228） */,
    "name" VARCHAR(255) NOT NULL  /* 漏洞名称 */,
    "description" TEXT   /* 漏洞详细描述 */,
    "severity" VARCHAR(20) NOT NULL  /* 严重程度：critical, high, medium, low */,
    "cvss_score" REAL   /* CVSS评分（0.0-10.0） */,
    "affected_product" VARCHAR(255)   /* 受影响产品 */,
    "affected_versions" VARCHAR(255)   /* 受影响版本 */,
    "poc_code" TEXT   /* POC代码 */,
    "remediation" TEXT   /* 修复建议 */,
    "references" TEXT   /* 参考链接（JSON格式） */,
    "source" VARCHAR(50)   /* 数据源（seebug, exploit-db等） */,
    "has_poc" INT NOT NULL  DEFAULT 0 /* 是否有POC */,
    "ssvid" INT   /* Seebug SSVID */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */
) /* 漏洞知识库表 */;
CREATE INDEX IF NOT EXISTS "idx_vulnerabili_cve_id_fdfdc0" ON "vulnerability_kb" ("cve_id");
CREATE INDEX IF NOT EXISTS "idx_vulnerabili_severit_353240" ON "vulnerability_kb" ("severity");
CREATE TABLE IF NOT EXISTS "workflow_executions" (
    "id" CHAR(36) NOT NULL  PRIMARY KEY /* 工作流ID */,
    "task_id" VARCHAR(100)   /* 关联任务ID */,
    "workflow_name" VARCHAR(255) NOT NULL  DEFAULT 'AI Security Scan' /* 工作流名称 */,
    "target" VARCHAR(500) NOT NULL  /* 执行目标 */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'pending' /* 状态：pending, running, completed, failed, cancelled */,
    "progress" INT NOT NULL  DEFAULT 0 /* 执行进度 0-100 */,
    "start_time" REAL   /* 开始时间戳 */,
    "end_time" REAL   /* 结束时间戳 */,
    "duration" REAL   /* 执行时长（秒） */,
    "current_step" VARCHAR(255)   /* 当前步骤 */,
    "total_steps" INT NOT NULL  DEFAULT 0 /* 总步骤数 */,
    "completed_steps" INT NOT NULL  DEFAULT 0 /* 已完成步骤数 */,
    "graph_flow" JSON   /* 图流数据 */,
    "vulnerabilities" JSON   /* 发现的漏洞 */,
    "tool_results" JSON   /* 工具执行结果 */,
    "metadata" JSON   /* 元数据 */,
    "error_message" TEXT   /* 错误信息 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */
) /* 工作流执行记录表 */;
CREATE INDEX IF NOT EXISTS "idx_workflow_ex_task_id_092f69" ON "workflow_executions" ("task_id");
CREATE INDEX IF NOT EXISTS "idx_workflow_ex_status_9049f7" ON "workflow_executions" ("status");
CREATE INDEX IF NOT EXISTS "idx_workflow_ex_target_1c3dfa" ON "workflow_executions" ("target");
CREATE TABLE IF NOT EXISTS "workflow_node_executions" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 节点执行ID */,
    "node_id" VARCHAR(100) NOT NULL  /* 节点ID */,
    "node_name" VARCHAR(255) NOT NULL  /* 节点名称 */,
    "node_type" VARCHAR(100) NOT NULL  DEFAULT 'unknown' /* 节点类型 */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'pending' /* 状态：pending, running, success, failed, skipped */,
    "step_number" INT NOT NULL  DEFAULT 0 /* 步骤序号 */,
    "start_time" REAL   /* 开始时间戳 */,
    "end_time" REAL   /* 结束时间戳 */,
    "duration_ms" REAL   /* 执行耗时（毫秒） */,
    "execution_time" REAL   /* 执行时间（秒） */,
    "input_params" JSON   /* 输入参数 */,
    "output_data" JSON   /* 输出数据 */,
    "error" TEXT   /* 错误信息 */,
    "error_message" TEXT   /* 错误消息 */,
    "task" VARCHAR(255)   /* 任务名称 */,
    "tool_name" VARCHAR(100)   /* 工具名称 */,
    "timestamp" REAL   /* 时间戳 */,
    "timestamp_iso" VARCHAR(50)   /* ISO格式时间戳 */,
    "metadata" JSON   /* 元数据 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "workflow_id" CHAR(36) NOT NULL REFERENCES "workflow_executions" ("id") ON DELETE CASCADE /* 关联工作流 */
) /* 工作流节点执行记录表 */;
CREATE INDEX IF NOT EXISTS "idx_workflow_no_workflo_c703e6" ON "workflow_node_executions" ("workflow_id");
CREATE INDEX IF NOT EXISTS "idx_workflow_no_node_id_b0dd4d" ON "workflow_node_executions" ("node_id");
CREATE INDEX IF NOT EXISTS "idx_workflow_no_status_506a1b" ON "workflow_node_executions" ("status");
CREATE TABLE IF NOT EXISTS "workflow_task_plans" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL /* 任务规划ID */,
    "plan_id" VARCHAR(100) NOT NULL  /* 规划ID */,
    "plan_name" VARCHAR(255) NOT NULL  /* 规划名称 */,
    "plan_type" VARCHAR(100) NOT NULL  DEFAULT 'scan' /* 规划类型 */,
    "priority" INT NOT NULL  DEFAULT 5 /* 优先级 1-10 */,
    "status" VARCHAR(50) NOT NULL  DEFAULT 'pending' /* 状态：pending, running, completed, failed, skipped */,
    "dependencies" JSON   /* 依赖任务 */,
    "estimated_time" REAL   /* 预估时间（秒） */,
    "actual_time" REAL   /* 实际时间（秒） */,
    "parameters" JSON   /* 参数 */,
    "result" JSON   /* 执行结果 */,
    "error_message" TEXT   /* 错误信息 */,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 创建时间 */,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP /* 更新时间 */,
    "workflow_id" CHAR(36) NOT NULL REFERENCES "workflow_executions" ("id") ON DELETE CASCADE /* 关联工作流 */
) /* 工作流任务规划表 */;
CREATE INDEX IF NOT EXISTS "idx_workflow_ta_workflo_b276de" ON "workflow_task_plans" ("workflow_id");
CREATE INDEX IF NOT EXISTS "idx_workflow_ta_plan_id_088c4b" ON "workflow_task_plans" ("plan_id");
CREATE INDEX IF NOT EXISTS "idx_workflow_ta_status_1335c1" ON "workflow_task_plans" ("status");
CREATE TABLE IF NOT EXISTS "aerich" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "version" VARCHAR(255) NOT NULL,
    "app" VARCHAR(100) NOT NULL,
    "content" JSON NOT NULL
);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        """
