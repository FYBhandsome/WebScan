# -*- coding:utf-8 -*-
"""
表单提取器

功能：
1. 提取表单信息
2. 提取输入字段
3. 识别文件上传点
4. 识别登录表单
"""

import re
import urllib.parse
from typing import List, Dict, Optional
from bs4 import BeautifulSoup

from .config import LOGIN_PATHS, UPLOAD_PATHS


class FormExtractor:
    """
    表单提取器
    
    提取内容：
    - action URL
    - method (GET/POST)
    - input字段（name, type, value）
    - 隐藏字段
    - 文件上传字段
    """
    
    def __init__(self):
        self.login_keywords = [
            "login", "signin", "sign-in", "username", "user", "email",
            "password", "pass", "pwd", "auth", "credential",
            "用户名", "密码", "登录", "账号"
        ]
        
        self.password_fields = [
            "password", "pass", "pwd", "passwd", "password1", "password2",
            "new_password", "confirm_password", "old_password",
            "密码", "新密码", "确认密码"
        ]
        
        self.file_fields = ["file", "upload", "attachment", "document", "image", "photo"]
    
    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        提取页面中的所有表单
        
        Args:
            soup: BeautifulSoup对象
            base_url: 基础URL
            
        Returns:
            List[Dict]: 表单信息列表
        """
        forms = []
        
        for form in soup.find_all('form'):
            form_info = self._parse_form(form, base_url)
            if form_info:
                forms.append(form_info)
        
        return forms
    
    def _parse_form(self, form, base_url: str) -> Optional[Dict]:
        """解析单个表单"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        enctype = form.get('enctype', '')
        
        if action:
            action = self._normalize_url(action, base_url)
        else:
            action = base_url
        
        inputs = []
        has_file_upload = False
        has_password = False
        has_hidden = False
        
        for input_tag in form.find_all('input'):
            input_info = self._parse_input(input_tag)
            if input_info:
                inputs.append(input_info)
                
                if input_info["type"] == "file":
                    has_file_upload = True
                if input_info["type"] == "password":
                    has_password = True
                if input_info["type"] == "hidden":
                    has_hidden = True
        
        for textarea in form.find_all('textarea'):
            input_info = {
                "name": textarea.get('name', ''),
                "type": "textarea",
                "value": textarea.string or '',
                "required": textarea.has_attr('required'),
                "placeholder": textarea.get('placeholder', '')
            }
            if input_info["name"]:
                inputs.append(input_info)
        
        for select in form.find_all('select'):
            options = []
            for option in select.find_all('option'):
                options.append({
                    "value": option.get('value', ''),
                    "text": option.string or ''
                })
            
            input_info = {
                "name": select.get('name', ''),
                "type": "select",
                "options": options,
                "required": select.has_attr('required')
            }
            if input_info["name"]:
                inputs.append(input_info)
        
        is_login_form = self._is_login_form(form, inputs)
        is_upload_form = self._is_upload_form(form, inputs, enctype)
        
        return {
            "url": base_url,
            "action": action,
            "method": method,
            "enctype": enctype,
            "inputs": inputs,
            "has_file_upload": has_file_upload,
            "has_password": has_password,
            "has_hidden": has_hidden,
            "is_login_form": is_login_form,
            "is_upload_form": is_upload_form,
            "inputs_count": len(inputs)
        }
    
    def _parse_input(self, input_tag) -> Optional[Dict]:
        """解析input标签"""
        name = input_tag.get('name', '')
        input_type = input_tag.get('type', 'text').lower()
        value = input_tag.get('value', '')
        
        if not name and input_type not in ['submit', 'button', 'reset', 'image']:
            return None
        
        return {
            "name": name,
            "type": input_type,
            "value": value,
            "required": input_tag.has_attr('required'),
            "placeholder": input_tag.get('placeholder', ''),
            "autocomplete": input_tag.get('autocomplete', ''),
            "maxlength": input_tag.get('maxlength', ''),
            "pattern": input_tag.get('pattern', '')
        }
    
    def _is_login_form(self, form, inputs: List[Dict]) -> bool:
        """判断是否为登录表单"""
        action = form.get('action', '').lower()
        form_id = form.get('id', '').lower()
        form_class = form.get('class', [])
        if isinstance(form_class, list):
            form_class = ' '.join(form_class).lower()
        else:
            form_class = str(form_class).lower()
        
        for path in LOGIN_PATHS:
            if path in action:
                return True
        
        login_indicators = ['login', 'signin', 'sign-in', 'auth', 'logon']
        for indicator in login_indicators:
            if indicator in action or indicator in form_id or indicator in form_class:
                return True
        
        has_password = any(i["type"] == "password" for i in inputs)
        has_user_field = any(
            i["name"].lower() in ["username", "user", "email", "login", "account"] or
            "user" in i["name"].lower() or
            "email" in i["name"].lower()
            for i in inputs if i["name"]
        )
        
        if has_password and has_user_field:
            return True
        
        return False
    
    def _is_upload_form(self, form, inputs: List[Dict], enctype: str) -> bool:
        """判断是否为上传表单"""
        if 'multipart/form-data' in enctype.lower():
            return True
        
        action = form.get('action', '').lower()
        for path in UPLOAD_PATHS:
            if path in action:
                return True
        
        for input_info in inputs:
            if input_info["type"] == "file":
                return True
            name_lower = input_info["name"].lower()
            for field in self.file_fields:
                if field in name_lower:
                    return True
        
        return False
    
    def _normalize_url(self, url: str, base_url: str) -> str:
        """标准化URL"""
        if not url:
            return base_url
        
        if url.startswith('//'):
            parsed = urllib.parse.urlparse(base_url)
            return f"{parsed.scheme}:{url}"
        elif url.startswith('/'):
            parsed = urllib.parse.urlparse(base_url)
            return f"{parsed.scheme}://{parsed.netloc}{url}"
        elif not url.startswith(('http://', 'https://')):
            return urllib.parse.urljoin(base_url, url)
        
        return url
    
    def find_upload_points(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        查找所有上传点
        
        Args:
            soup: BeautifulSoup对象
            base_url: 基础URL
            
        Returns:
            List[Dict]: 上传点列表
        """
        upload_points = []
        
        for form in soup.find_all('form'):
            if self._is_upload_form(form, [], form.get('enctype', '')):
                form_info = self._parse_form(form, base_url)
                if form_info:
                    upload_points.append({
                        "url": form_info["action"],
                        "method": form_info["method"],
                        "enctype": form_info["enctype"],
                        "file_inputs": [
                            i for i in form_info["inputs"] 
                            if i["type"] == "file"
                        ]
                    })
        
        for input_tag in soup.find_all('input', {'type': 'file'}):
            parent_form = input_tag.find_parent('form')
            if parent_form:
                continue
            
            upload_points.append({
                "url": base_url,
                "method": "POST",
                "enctype": "multipart/form-data",
                "file_inputs": [{
                    "name": input_tag.get('name', 'file'),
                    "type": "file",
                    "accept": input_tag.get('accept', '')
                }]
            })
        
        return upload_points
    
    def find_login_points(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        查找所有登录点
        
        Args:
            soup: BeautifulSoup对象
            base_url: 基础URL
            
        Returns:
            List[Dict]: 登录点列表
        """
        login_points = []
        
        for form in soup.find_all('form'):
            form_info = self._parse_form(form, base_url)
            if form_info and form_info["is_login_form"]:
                login_points.append({
                    "url": form_info["action"],
                    "method": form_info["method"],
                    "username_field": self._find_username_field(form_info["inputs"]),
                    "password_field": self._find_password_field(form_info["inputs"]),
                    "other_inputs": [
                        i for i in form_info["inputs"]
                        if i["type"] not in ["password", "submit", "button"]
                        and i["name"]
                    ]
                })
        
        return login_points
    
    def _find_username_field(self, inputs: List[Dict]) -> str:
        """查找用户名字段"""
        username_names = ["username", "user", "email", "login", "account", "name"]
        
        for input_info in inputs:
            name_lower = input_info["name"].lower()
            for uname in username_names:
                if uname in name_lower:
                    return input_info["name"]
        
        for input_info in inputs:
            if input_info["type"] in ["text", "email"] and input_info["name"]:
                return input_info["name"]
        
        return ""
    
    def _find_password_field(self, inputs: List[Dict]) -> str:
        """查找密码字段"""
        for input_info in inputs:
            if input_info["type"] == "password":
                return input_info["name"]
        
        for input_info in inputs:
            name_lower = input_info["name"].lower()
            for pfield in self.password_fields:
                if pfield in name_lower:
                    return input_info["name"]
        
        return ""
