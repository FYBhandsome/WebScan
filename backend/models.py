"""
数据库模型定义 - 使用 Tortoise-ORM
"""
from tortoise import fields
from tortoise.models import Model
from datetime import datetime
from typing import Optional


class Task(Model):
    """任务表"""
    
    id = fields.IntField(pk=True, description="任务ID")
    task_name = fields.CharField(max_length=255, description="任务名称")
    task_type = fields.CharField(max_length=50, description="任务类型：scan, vulnerability, etc.")
    target = fields.CharField(max_length=500, description="扫描目标")
    status = fields.CharField(max_length=50, default="pending", description="状态：pending, running, completed, failed, cancelled")
    progress = fields.IntField(default=0, description="进度 0-100")
    config = fields.TextField(null=True, description="配置信息（JSON格式）")
    result = fields.TextField(null=True, description="结果信息（JSON格式）")
    error_message = fields.TextField(null=True, description="错误信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    # 关系
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


class Report(Model):
    """报告表"""
    
    id = fields.IntField(pk=True, description="报告ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="reports", description="关联任务"
    )
    report_name = fields.CharField(max_length=255, description="报告名称")
    report_type = fields.CharField(max_length=50, description="报告类型：pdf, html, json, etc.")
    content = fields.TextField(null=True, description="报告内容（JSON格式）")
    file_path = fields.CharField(max_length=500, null=True, description="报告文件路径")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    class Meta:
        table = "reports"
        table_description = "扫描报告表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.report_name} ({self.report_type})"


class Vulnerability(Model):
    """漏洞表"""
    
    id = fields.IntField(pk=True, description="漏洞ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="vulnerabilities", description="关联任务"
    )
    vuln_type = fields.CharField(max_length=100, description="漏洞类型：XSS, SQLInjection, CSRF, etc.")
    severity = fields.CharField(max_length=20, description="严重程度：high, medium, low, info")
    title = fields.CharField(max_length=255, description="漏洞标题")
    description = fields.TextField(null=True, description="漏洞描述")
    url = fields.CharField(max_length=500, null=True, description="漏洞URL")
    payload = fields.TextField(null=True, description="测试Payload")
    evidence = fields.TextField(null=True, description="漏洞证据")
    remediation = fields.TextField(null=True, description="修复建议")
    status = fields.CharField(max_length=50, default="open", description="状态：open, fixed, ignored")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    
    class Meta:
        table = "vulnerabilities"
        table_description = "漏洞信息表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.title} ({self.severity})"


class ScanResult(Model):
    """扫描结果表"""
    
    id = fields.IntField(pk=True, description="结果ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="scan_results", description="关联任务"
    )
    scan_type = fields.CharField(max_length=50, description="扫描类型：port_scan, subdomain, etc.")
    target = fields.CharField(max_length=500, description="扫描目标")
    result = fields.TextField(null=True, description="扫描结果（JSON格式）")
    status = fields.CharField(max_length=50, default="success", description="状态：success, failed")
    error_message = fields.TextField(null=True, description="错误信息")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "scan_results"
        table_description = "扫描结果表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.scan_type} - {self.target}"


class SystemLog(Model):
    """系统日志表"""
    
    id = fields.IntField(pk=True, description="日志ID")
    level = fields.CharField(max_length=20, description="日志级别：INFO, WARNING, ERROR")
    module = fields.CharField(max_length=100, null=True, description="模块名称")
    message = fields.TextField(description="日志消息")
    ip_address = fields.CharField(max_length=50, null=True, description="IP地址")
    user_agent = fields.CharField(max_length=500, null=True, description="用户代理")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "system_logs"
        table_description = "系统日志表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"[{self.level}] {self.message[:50]}..."


class POCScanResult(Model):
    """POC 扫描结果表"""
    
    id = fields.IntField(pk=True, description="结果ID")
    task: fields.ForeignKeyRelation[Task] = fields.ForeignKeyField(
        "models.Task", related_name="poc_results", description="关联任务"
    )
    poc_type = fields.CharField(max_length=100, description="POC 类型：weblogic_cve_2020_2551, struts2_009, etc.")
    target = fields.CharField(max_length=500, description="扫描目标")
    vulnerable = fields.BooleanField(default=False, description="是否存在漏洞")
    message = fields.TextField(null=True, description="扫描结果消息")
    severity = fields.CharField(max_length=20, null=True, description="严重程度：high, medium, low")
    cve_id = fields.CharField(max_length=50, null=True, description="CVE 编号")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    
    class Meta:
        table = "poc_scan_results"
        table_description = "POC 扫描结果表"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.poc_type} - {self.target} ({'存在漏洞' if self.vulnerable else '安全'})"