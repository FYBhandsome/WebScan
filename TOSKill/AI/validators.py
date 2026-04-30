# -*- coding:utf-8 -*-
"""
TOSKill 数据验证模块

提供用户输入数据审核、验证和提取功能。
支持AI智能审核，实现关键参数的精准提取和验证。
"""
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """验证状态"""
    VALID = "valid"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    NEEDS_CLARIFICATION = "needs_clarification"


@dataclass
class ValidationResult:
    """验证结果"""
    status: ValidationStatus
    is_complete: bool
    params: Dict[str, Any] = field(default_factory=dict)
    missing_fields: List[str] = field(default_factory=list)
    invalid_fields: List[str] = field(default_factory=list)
    message: str = ""
    suggestions: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "is_complete": self.is_complete,
            "params": self.params,
            "missing_fields": self.missing_fields,
            "invalid_fields": self.invalid_fields,
            "message": self.message,
            "suggestions": self.suggestions,
            "confidence": self.confidence
        }


class InputValidator:
    """输入验证器"""
    
    URL_PATTERN = re.compile(
        r'^(https?://)?'  # 协议
        r'(([\w-]+\.)+[\w-]+|'  # 域名
        r'(\d{1,3}\.){3}\d{1,3})'  # IP地址
        r'(:\d+)?'  # 端口
        r'(/[\w\-./?%&=#]*)?$',  # 路径
        re.IGNORECASE
    )
    
    IP_PATTERN = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
    )
    
    DOMAIN_PATTERN = re.compile(
        r'^([\w-]+\.)+[\w-]+$',
        re.IGNORECASE
    )
    
    EMAIL_PATTERN = re.compile(
        r'^[\w\.-]+@[\w\.-]+\.\w+$'
    )
    
    @classmethod
    def validate_url(cls, value: str) -> Tuple[bool, str]:
        """验证URL格式"""
        if not value:
            return False, "URL不能为空"
        
        value = value.strip()
        
        if not value.startswith(('http://', 'https://')):
            value = 'http://' + value
        
        if cls.URL_PATTERN.match(value):
            return True, value
        return False, "无效的URL格式"
    
    @classmethod
    def validate_ip(cls, value: str) -> Tuple[bool, str]:
        """验证IP地址格式"""
        if not value:
            return False, "IP地址不能为空"
        
        value = value.strip()
        
        if cls.IP_PATTERN.match(value):
            parts = value.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True, value
        return False, "无效的IP地址格式"
    
    @classmethod
    def validate_domain(cls, value: str) -> Tuple[bool, str]:
        """验证域名格式"""
        if not value:
            return False, "域名不能为空"
        
        value = value.strip().lower()
        
        if cls.DOMAIN_PATTERN.match(value):
            return True, value
        return False, "无效的域名格式"
    
    @classmethod
    def validate_target(cls, value: str) -> Tuple[bool, str, str]:
        """验证目标地址（URL/IP/域名）"""
        if not value:
            return False, "", "目标地址不能为空"
        
        value = value.strip()
        
        is_valid, normalized = cls.validate_url(value)
        if is_valid:
            return True, normalized, "url"
        
        is_valid, normalized = cls.validate_ip(value)
        if is_valid:
            return True, normalized, "ip"
        
        is_valid, normalized = cls.validate_domain(value)
        if is_valid:
            return True, f"http://{normalized}", "domain"
        
        return False, value, "unknown"
    
    @classmethod
    def validate_tool_name(cls, value: str, available_tools: List[str] = None) -> Tuple[bool, str]:
        """验证工具名称"""
        if not value:
            return False, "工具名称不能为空"
        
        value = value.strip().lower()
        value = re.sub(r'[^a-z0-9_]', '_', value)
        
        if available_tools and value not in available_tools:
            return False, f"工具 '{value}' 不在可用工具列表中"
        
        return True, value
    
    @classmethod
    def extract_urls(cls, text: str) -> List[str]:
        """从文本中提取URL"""
        pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|'
            r'(?:[\w-]+\.)+[\w]+(?:/\S*)?'
        )
        matches = pattern.findall(text)
        valid_urls = []
        for url in matches:
            is_valid, normalized, _ = cls.validate_target(url)
            if is_valid:
                valid_urls.append(normalized)
        return valid_urls
    
    @classmethod
    def extract_ips(cls, text: str) -> List[str]:
        """从文本中提取IP地址"""
        pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        matches = pattern.findall(text)
        valid_ips = []
        for ip in matches:
            is_valid, normalized = cls.validate_ip(ip)
            if is_valid:
                valid_ips.append(normalized)
        return valid_ips


class AIInputValidator:
    """AI智能输入验证器"""
    
    def __init__(self, llm=None):
        self.llm = llm
        self._init_llm()
    
    def _init_llm(self):
        """初始化LLM"""
        if self.llm is None:
            try:
                from langchain_openai import ChatOpenAI
                from TOSKill.config import settings
                self.llm = ChatOpenAI(
                    model=settings.MODEL_ID,
                    temperature=0.1,
                    api_key=settings.OPENAI_API_KEY,
                    base_url=settings.OPENAI_BASE_URL
                )
            except Exception as e:
                logger.warning(f"初始化LLM失败: {e}")
    
    async def validate_and_extract(self, user_input: str, intent_type: str) -> ValidationResult:
        """AI智能验证和提取用户输入"""
        
        if not self.llm:
            return self._fallback_validation(user_input, intent_type)
        
        prompt = f"""分析用户输入，提取关键参数并验证完整性。

用户输入: {user_input}
意图类型: {intent_type}

请严格按以下JSON格式回复，不要添加其他内容:
{{
    "is_complete": true/false,
    "target": "提取的目标地址（URL/IP/域名）",
    "tool_name": "提取的工具名称（如果有）",
    "missing_fields": ["缺失的字段列表"],
    "invalid_fields": ["无效的字段列表"],
    "message": "验证结果说明",
    "suggestions": ["建议列表"],
    "confidence": 0.0-1.0
}}

验证规则:
1. scan意图: 必须有target
2. tool意图: 必须有tool_name和target
3. chat意图: 无必需字段
4. upload_script意图: 无必需字段
5. generate_script意图: 无必需字段

目标地址验证:
- 支持URL格式: http(s)://domain/path
- 支持IP格式: x.x.x.x
- 支持域名格式: domain.com
"""
        
        try:
            response = self.llm.invoke(prompt).content
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                
                params = {}
                if result.get("target"):
                    is_valid, normalized, _ = InputValidator.validate_target(result["target"])
                    if is_valid:
                        params["target"] = normalized
                    else:
                        result["invalid_fields"].append("target")
                if result.get("tool_name"):
                    params["tool_name"] = result["tool_name"]
                
                return ValidationResult(
                    status=ValidationStatus.VALID if result.get("is_complete") else ValidationStatus.INCOMPLETE,
                    is_complete=result.get("is_complete", False),
                    params=params,
                    missing_fields=result.get("missing_fields", []),
                    invalid_fields=result.get("invalid_fields", []),
                    message=result.get("message", ""),
                    suggestions=result.get("suggestions", []),
                    confidence=result.get("confidence", 0.5)
                )
        except Exception as e:
            logger.error(f"AI验证失败: {e}")
        
        return self._fallback_validation(user_input, intent_type)
    
    def _fallback_validation(self, user_input: str, intent_type: str) -> ValidationResult:
        """备用验证逻辑（不使用AI）"""
        params = {}
        missing_fields = []
        
        urls = InputValidator.extract_urls(user_input)
        ips = InputValidator.extract_ips(user_input)
        
        if urls:
            params["target"] = urls[0]
        elif ips:
            params["target"] = ips[0]
        
        if intent_type in ["scan", "tool"]:
            if "target" not in params:
                missing_fields.append("target")
        
        is_complete = len(missing_fields) == 0
        
        return ValidationResult(
            status=ValidationStatus.VALID if is_complete else ValidationStatus.INCOMPLETE,
            is_complete=is_complete,
            params=params,
            missing_fields=missing_fields,
            invalid_fields=[],
            message="请提供目标地址" if missing_fields else "验证通过",
            suggestions=["请输入目标网址或IP地址"] if missing_fields else [],
            confidence=0.7
        )
    
    async def clarify_intent(self, user_input: str, possible_intents: List[str]) -> str:
        """澄清模糊意图"""
        if not self.llm:
            return possible_intents[0] if possible_intents else "chat"
        
        prompt = f"""用户输入可能有多种意图，请判断最可能的意图。

用户输入: {user_input}
可能的意图: {', '.join(possible_intents)}

只回复最可能的意图类型，不要其他内容。
"""
        
        try:
            response = self.llm.invoke(prompt).content.strip().lower()
            for intent in possible_intents:
                if intent in response:
                    return intent
        except Exception as e:
            logger.error(f"意图澄清失败: {e}")
        
        return possible_intents[0] if possible_intents else "chat"


class DataInputRequest:
    """数据输入请求构建器"""
    
    FIELD_DEFINITIONS = {
        "target": {
            "label": "目标网址",
            "description": "请输入要扫描的目标网址或IP地址",
            "placeholder": "https://example.com 或 192.168.1.1",
            "required": True,
            "validation": "url_or_ip"
        },
        "tool_name": {
            "label": "工具名称",
            "description": "请输入要执行的工具名称",
            "placeholder": "port_scan, sqli_scan, xss_scan...",
            "required": True,
            "validation": "tool_name"
        },
        "scan_mode": {
            "label": "扫描模式",
            "description": "请选择扫描模式",
            "placeholder": "",
            "required": True,
            "validation": "enum",
            "options": ["info", "vuln", "full"]
        },
        "script_content": {
            "label": "脚本内容",
            "description": "请粘贴Python脚本代码",
            "placeholder": "def run(target):\n    return {'success': True}",
            "required": True,
            "validation": "python_code"
        },
        "script_description": {
            "label": "脚本功能描述",
            "description": "请描述您需要的脚本功能",
            "placeholder": "检测目标网站是否存在敏感文件泄露",
            "required": True,
            "validation": "text"
        }
    }
    
    @classmethod
    def build_request(cls, field: str, custom_message: str = None) -> Dict[str, Any]:
        """构建输入请求"""
        if field not in cls.FIELD_DEFINITIONS:
            return {
                "type": "input_request",
                "payload": {
                    "field": field,
                    "label": field,
                    "description": custom_message or f"请输入{field}",
                    "required": True
                }
            }
        
        definition = cls.FIELD_DEFINITIONS[field]
        return {
            "type": "input_request",
            "payload": {
                "field": field,
                "label": definition["label"],
                "description": custom_message or definition["description"],
                "placeholder": definition.get("placeholder", ""),
                "required": definition.get("required", True),
                "validation": definition.get("validation", "text"),
                "options": definition.get("options", [])
            }
        }
    
    @classmethod
    def build_multi_field_request(cls, fields: List[str], message: str = None) -> Dict[str, Any]:
        """构建多字段输入请求"""
        field_definitions = []
        for field in fields:
            if field in cls.FIELD_DEFINITIONS:
                field_definitions.append({
                    "field": field,
                    **cls.FIELD_DEFINITIONS[field]
                })
        
        return {
            "type": "multi_field_input_request",
            "payload": {
                "message": message or "请提供以下信息",
                "fields": field_definitions
            }
        }


input_validator = InputValidator()
ai_validator = AIInputValidator()


def get_input_validator() -> InputValidator:
    return input_validator


def get_ai_validator() -> AIInputValidator:
    return ai_validator
