from tortoise import fields
from tortoise.models import Model


class AuditTask(Model):
    id = fields.IntField(pk=True)
    filename = fields.CharField(max_length=255, description="上传文件名")
    original_code = fields.TextField(description="原始代码")
    status = fields.CharField(max_length=20, default="PENDING")
    created_at = fields.DatetimeField(auto_now_add=True)


class CodeStandard(Model):
    id = fields.IntField(pk=True)
    task = fields.OneToOneField("models.AuditTask", on_delete=fields.CASCADE)
    standard_code = fields.TextField(description="AST标准化代码")


class Vulnerability(Model):
    id = fields.IntField(pk=True)
    task = fields.ForeignKeyField("models.AuditTask", related_name="vulns", on_delete=fields.CASCADE)
    vuln_type = fields.CharField(max_length=100)
    level = fields.CharField(max_length=20)
    line_no = fields.IntField()
    code = fields.TextField()
    desc = fields.TextField()
    created_at = fields.DatetimeField(auto_now_add=True)


class DiffRecord(Model):
    id = fields.IntField(pk=True)
    task = fields.OneToOneField("models.AuditTask", on_delete=fields.CASCADE)
    diff_text = fields.TextField()
    diff_html = fields.TextField()
