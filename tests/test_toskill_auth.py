# -*- coding:utf-8 -*-
"""
TOSKill 认证机制测试用例

测试认证信息提取、认证过期检测、认证失败重试等。
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.mark.auth
class TestAuthExpiry:
    """认证过期检测测试"""
    
    def test_is_auth_expired_no_auth(self, mock_scan_state):
        """测试无认证信息时过期"""
        from TOSKill.AI.tools import is_auth_expired
        
        result = is_auth_expired(mock_scan_state)
        
        assert result == True
    
    def test_is_auth_expired_valid_auth(self, mock_auth_state):
        """测试有效认证未过期"""
        from TOSKill.AI.tools import is_auth_expired
        
        result = is_auth_expired(mock_auth_state)
        
        assert result == False
    
    def test_is_auth_expired_expired_auth(self, expired_auth_state):
        """测试过期认证"""
        from TOSKill.AI.tools import is_auth_expired
        
        result = is_auth_expired(expired_auth_state)
        
        assert result == True
    
    def test_is_auth_expired_with_expires_at(self, mock_scan_state):
        """测试带过期时间的认证"""
        from TOSKill.AI.tools import is_auth_expired
        from TOSKill.AI.state import update_state
        
        future_time = datetime.now() + timedelta(hours=1)
        state = update_state(
            mock_scan_state,
            auth_info={"type": "cookies", "cookies": {"session": "test"}},
            auth_expires_at=future_time.isoformat()
        )
        
        result = is_auth_expired(state)
        
        assert result == False
    
    def test_is_auth_expired_with_past_expires_at(self, mock_scan_state):
        """测试已过期的过期时间"""
        from TOSKill.AI.tools import is_auth_expired
        from TOSKill.AI.state import update_state
        
        past_time = datetime.now() - timedelta(hours=1)
        state = update_state(
            mock_scan_state,
            auth_info={"type": "cookies", "cookies": {"session": "test"}},
            auth_expires_at=past_time.isoformat()
        )
        
        result = is_auth_expired(state)
        
        assert result == True
    
    def test_is_auth_expired_with_timestamp(self, mock_scan_state):
        """测试带时间戳的认证"""
        from TOSKill.AI.tools import is_auth_expired
        from TOSKill.AI.state import update_state
        
        recent_time = datetime.now() - timedelta(minutes=10)
        state = update_state(
            mock_scan_state,
            auth_info={"type": "cookies", "cookies": {"session": "test"}},
            auth_timestamp=recent_time.isoformat()
        )
        
        result = is_auth_expired(state)
        
        assert result == False
    
    def test_is_auth_expired_old_timestamp(self, mock_scan_state):
        """测试旧时间戳的认证"""
        from TOSKill.AI.tools import is_auth_expired
        from TOSKill.AI.state import update_state
        
        old_time = datetime.now() - timedelta(hours=2)
        state = update_state(
            mock_scan_state,
            auth_info={"type": "cookies", "cookies": {"session": "test"}},
            auth_timestamp=old_time.isoformat()
        )
        
        result = is_auth_expired(state)
        
        assert result == True


@pytest.mark.auth
class TestAuthRemainingTime:
    """认证剩余时间测试"""
    
    def test_get_auth_remaining_time_no_auth(self, mock_scan_state):
        """测试无认证信息时剩余时间"""
        from TOSKill.AI.tools import get_auth_remaining_time
        
        result = get_auth_remaining_time(mock_scan_state)
        
        assert result == -1
    
    def test_get_auth_remaining_time_valid_auth(self, mock_auth_state):
        """测试有效认证剩余时间"""
        from TOSKill.AI.tools import get_auth_remaining_time
        
        result = get_auth_remaining_time(mock_auth_state)
        
        assert result > 0
    
    def test_get_auth_remaining_time_expired_auth(self, expired_auth_state):
        """测试过期认证剩余时间"""
        from TOSKill.AI.tools import get_auth_remaining_time
        
        result = get_auth_remaining_time(expired_auth_state)
        
        assert result == 0
    
    def test_get_auth_remaining_time_with_expires_at(self, mock_scan_state):
        """测试带过期时间的剩余时间"""
        from TOSKill.AI.tools import get_auth_remaining_time
        from TOSKill.AI.state import update_state
        
        future_time = datetime.now() + timedelta(minutes=15)
        state = update_state(
            mock_scan_state,
            auth_info={"type": "cookies", "cookies": {"session": "test"}},
            auth_expires_at=future_time.isoformat()
        )
        
        result = get_auth_remaining_time(state)
        
        assert 800 < result < 950


@pytest.mark.auth
class TestAuthExtraction:
    """认证信息提取测试"""
    
    def test_extract_auth_from_result_cookies(self):
        """测试从结果提取Cookie认证"""
        from TOSKill.AI.tools import extract_auth_from_result
        
        result = {
            "cookies_obtained": {"session": "test_session", "token": "test_token"},
            "authentication_used": True
        }
        
        auth_info = extract_auth_from_result(result)
        
        assert "auth_info" in auth_info
        assert auth_info["auth_info"]["cookies"]["session"] == "test_session"
    
    def test_extract_auth_from_result_tokens(self):
        """测试从结果提取Token认证"""
        from TOSKill.AI.tools import extract_auth_from_result
        
        result = {
            "tokens_obtained": "bearer_token_value",
            "authentication_used": True
        }
        
        auth_info = extract_auth_from_result(result)
        
        assert "auth_info" in auth_info
        assert auth_info["auth_info"]["token"] == "bearer_token_value"
    
    def test_extract_auth_from_result_headers(self):
        """测试从结果提取Header认证"""
        from TOSKill.AI.tools import extract_auth_from_result
        
        result = {
            "headers_obtained": {"Authorization": "Bearer token"},
            "authentication_used": True
        }
        
        auth_info = extract_auth_from_result(result)
        
        assert "auth_info" in auth_info
        assert auth_info["auth_info"]["headers"]["Authorization"] == "Bearer token"
    
    def test_extract_auth_from_result_no_auth(self):
        """测试从结果提取无认证信息"""
        from TOSKill.AI.tools import extract_auth_from_result
        
        result = {"success": True, "data": {}}
        
        auth_info = extract_auth_from_result(result)
        
        assert "auth_info" not in auth_info
    
    def test_extract_auth_from_result_multiple(self):
        """测试从结果提取多种认证信息"""
        from TOSKill.AI.tools import extract_auth_from_result
        
        result = {
            "cookies_obtained": {"session": "test_session"},
            "tokens_obtained": "bearer_token",
            "headers_obtained": {"X-Custom": "value"},
            "authentication_used": True
        }
        
        auth_info = extract_auth_from_result(result)
        
        assert "auth_info" in auth_info
        assert auth_info["auth_info"]["cookies"]["session"] == "test_session"
        assert auth_info["auth_info"]["token"] == "bearer_token"
        assert auth_info["auth_info"]["headers"]["X-Custom"] == "value"
    
    def test_extract_auth_from_non_dict_result(self):
        """测试从非字典结果提取"""
        from TOSKill.AI.tools import extract_auth_from_result
        
        result = "not a dict"
        
        auth_info = extract_auth_from_result(result)
        
        assert auth_info == {}


@pytest.mark.auth
class TestAuthInvocation:
    """带认证调用工具测试"""
    
    def test_invoke_tool_with_auth_cookies(self, mock_auth_state):
        """测试带Cookie认证调用工具"""
        from TOSKill.AI.tools import invoke_tool_with_auth
        
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = {"success": True}
        
        result = invoke_tool_with_auth(mock_tool, "example.com", mock_auth_state)
        
        mock_tool.invoke.assert_called_once()
        call_args = mock_tool.invoke.call_args[0][0]
        assert "cookies" in call_args
        assert call_args["cookies"]["session"] == "test_session_value"
    
    def test_invoke_tool_with_auth_token(self, mock_scan_state):
        """测试带Token认证调用工具"""
        from TOSKill.AI.tools import invoke_tool_with_auth
        from TOSKill.AI.state import update_state
        
        state = update_state(
            mock_scan_state,
            auth_info={"type": "token", "token": "bearer_token", "cookies": {}, "headers": {}}
        )
        
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = {"success": True}
        
        result = invoke_tool_with_auth(mock_tool, "example.com", state)
        
        call_args = mock_tool.invoke.call_args[0][0]
        assert "auth_token" in call_args
    
    def test_invoke_tool_with_auth_headers(self, mock_scan_state):
        """测试带Header认证调用工具"""
        from TOSKill.AI.tools import invoke_tool_with_auth
        from TOSKill.AI.state import update_state
        
        state = update_state(
            mock_scan_state,
            auth_info={
                "type": "headers",
                "headers": {"Authorization": "Bearer token"},
                "cookies": {},
                "token": ""
            }
        )
        
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = {"success": True}
        
        result = invoke_tool_with_auth(mock_tool, "example.com", state)
        
        call_args = mock_tool.invoke.call_args[0][0]
        assert "headers" in call_args
    
    def test_invoke_tool_without_auth(self):
        """测试不带认证调用工具"""
        from TOSKill.AI.tools import invoke_tool_with_auth
        
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = {"success": True}
        
        result = invoke_tool_with_auth(mock_tool, "example.com", None)
        
        call_args = mock_tool.invoke.call_args[0][0]
        assert call_args["target"] == "example.com"
        assert "cookies" not in call_args or call_args.get("cookies") is None
    
    def test_invoke_tool_with_legacy_auth_fields(self, mock_scan_state):
        """测试带旧版认证字段调用工具"""
        from TOSKill.AI.tools import invoke_tool_with_auth
        from TOSKill.AI.state import update_state
        
        state = update_state(
            mock_scan_state,
            auth_cookies={"legacy_session": "value"},
            auth_token="legacy_token"
        )
        
        mock_tool = MagicMock()
        mock_tool.invoke.return_value = {"success": True}
        
        result = invoke_tool_with_auth(mock_tool, "example.com", state)
        
        mock_tool.invoke.assert_called_once()


@pytest.mark.auth
class TestAuthRetryManager:
    """认证重试管理器测试"""
    
    @pytest.fixture
    def retry_manager(self):
        from TOSKill.AI.graph import AuthRetryManager
        return AuthRetryManager(max_retries=3)
    
    def test_initial_retry_count(self, retry_manager):
        """测试初始重试计数"""
        result = retry_manager.get_retry_count("test_session")
        
        assert result == 0
    
    def test_increment_retry(self, retry_manager):
        """测试增加重试计数"""
        result = retry_manager.increment_retry("test_session")
        
        assert result == 1
        assert retry_manager.get_retry_count("test_session") == 1
    
    def test_multiple_increments(self, retry_manager):
        """测试多次增加重试计数"""
        retry_manager.increment_retry("test_session")
        retry_manager.increment_retry("test_session")
        result = retry_manager.increment_retry("test_session")
        
        assert result == 3
    
    def test_can_retry(self, retry_manager):
        """测试是否可以重试"""
        assert retry_manager.can_retry("test_session") == True
        
        retry_manager.increment_retry("test_session")
        retry_manager.increment_retry("test_session")
        retry_manager.increment_retry("test_session")
        
        assert retry_manager.can_retry("test_session") == False
    
    def test_reset_retry(self, retry_manager):
        """测试重置重试计数"""
        retry_manager.increment_retry("test_session")
        retry_manager.increment_retry("test_session")
        
        retry_manager.reset_retry("test_session")
        
        assert retry_manager.get_retry_count("test_session") == 0
    
    def test_get_retry_history(self, retry_manager):
        """测试获取重试历史"""
        retry_manager.increment_retry("test_session")
        retry_manager.increment_retry("test_session")
        
        history = retry_manager.get_retry_history("test_session")
        
        assert len(history) == 2
    
    def test_should_trigger_reauth(self, retry_manager):
        """测试是否应触发重新认证"""
        auth_failure_response = {
            "status_code": 401,
            "error": "Unauthorized"
        }
        
        result = retry_manager.should_trigger_reauth("test_session", auth_failure_response)
        
        assert result == True
    
    def test_should_not_trigger_reauth_on_success(self, retry_manager):
        """测试成功响应不触发重新认证"""
        success_response = {
            "status_code": 200,
            "success": True
        }
        
        result = retry_manager.should_trigger_reauth("test_session", success_response)
        
        assert result == False
    
    def test_should_not_trigger_reauth_max_retries(self, retry_manager):
        """测试达到最大重试次数不触发重新认证"""
        retry_manager.increment_retry("test_session")
        retry_manager.increment_retry("test_session")
        retry_manager.increment_retry("test_session")
        
        auth_failure_response = {"status_code": 401}
        
        result = retry_manager.should_trigger_reauth("test_session", auth_failure_response)
        
        assert result == False


@pytest.mark.auth
class TestAuthFailureDetection:
    """认证失败检测测试"""
    
    def test_is_auth_failure_401(self):
        """测试401响应检测"""
        from TOSKill.AI.graph import is_auth_failure_response
        
        response = {"status_code": 401}
        
        result = is_auth_failure_response(response)
        
        assert result == True
    
    def test_is_auth_failure_403(self):
        """测试403响应检测"""
        from TOSKill.AI.graph import is_auth_failure_response
        
        response = {"status_code": 403}
        
        result = is_auth_failure_response(response)
        
        assert result == True
    
    def test_is_auth_failure_error_message(self):
        """测试错误消息检测"""
        from TOSKill.AI.graph import is_auth_failure_response
        
        response = {"error": "Unauthorized access"}
        
        result = is_auth_failure_response(response)
        
        assert result == True
    
    def test_is_auth_failure_token_expired(self):
        """测试Token过期消息检测"""
        from TOSKill.AI.graph import is_auth_failure_response
        
        response = {"error": "Token expired"}
        
        result = is_auth_failure_response(response)
        
        assert result == True
    
    def test_is_auth_failure_success_response(self):
        """测试成功响应不检测为失败"""
        from TOSKill.AI.graph import is_auth_failure_response
        
        response = {"status_code": 200, "success": True}
        
        result = is_auth_failure_response(response)
        
        assert result == False
    
    def test_is_auth_failure_nested_data(self):
        """测试嵌套数据中的认证失败"""
        from TOSKill.AI.graph import is_auth_failure_response
        
        response = {
            "data": {
                "status_code": 401,
                "error": "Authentication required"
            }
        }
        
        result = is_auth_failure_response(response)
        
        assert result == True


@pytest.mark.auth
class TestAuthEncryption:
    """认证加密测试"""
    
    def test_encrypt_auth_info(self):
        """测试加密认证信息"""
        from TOSKill.AI.graph import encrypt_auth_info
        
        auth_data = {
            "cookies": {"session": "test_value"},
            "token": "bearer_token"
        }
        
        encrypted = encrypt_auth_info(auth_data)
        
        assert encrypted is not None
        assert encrypted.startswith("enc:")
    
    def test_decrypt_auth_info(self):
        """测试解密认证信息"""
        from TOSKill.AI.graph import encrypt_auth_info, decrypt_auth_info
        
        auth_data = {
            "cookies": {"session": "test_value"},
            "token": "bearer_token"
        }
        
        encrypted = encrypt_auth_info(auth_data)
        decrypted = decrypt_auth_info(encrypted)
        
        assert decrypted == auth_data
    
    def test_decrypt_invalid_data(self):
        """测试解密无效数据"""
        from TOSKill.AI.graph import decrypt_auth_info
        
        result = decrypt_auth_info("invalid_data")
        
        assert result == {}
    
    def test_decrypt_non_encrypted_data(self):
        """测试解密非加密数据"""
        from TOSKill.AI.graph import decrypt_auth_info
        
        result = decrypt_auth_info("not_encrypted")
        
        assert result == {}


@pytest.mark.auth
class TestMultiStepAuthManager:
    """多步骤认证管理器测试"""
    
    @pytest.fixture
    def auth_manager(self):
        from TOSKill.AI.tools import MultiStepAuthManager
        return MultiStepAuthManager()
    
    def test_register_captcha_handler(self, auth_manager):
        """测试注册验证码处理器"""
        handler = MagicMock()
        
        auth_manager.register_captcha_handler("image", handler)
        
        assert "image" in auth_manager._captcha_handlers
    
    @pytest.mark.asyncio
    async def test_handle_captcha_with_handler(self, auth_manager):
        """测试有处理器时处理验证码"""
        handler = MagicMock(return_value="captcha_answer")
        auth_manager.register_captcha_handler("image", handler)
        
        result = await auth_manager.handle_captcha("image", "base64_data")
        
        assert result["success"] == True
        assert result["answer"] == "captcha_answer"
    
    @pytest.mark.asyncio
    async def test_handle_captcha_without_handler(self, auth_manager):
        """测试无处理器时处理验证码"""
        result = await auth_manager.handle_captcha("unknown_type", "data")
        
        assert result["success"] == False
        assert "未注册" in result["error"]
    
    @pytest.mark.asyncio
    async def test_handle_captcha_async_handler(self, auth_manager):
        """测试异步验证码处理器"""
        async def async_handler(data, session_id):
            return "async_answer"
        
        auth_manager.register_captcha_handler("async", async_handler)
        
        result = await auth_manager.handle_captcha("async", "data")
        
        assert result["success"] == True
        assert result["answer"] == "async_answer"
    
    def test_create_auth_session(self, auth_manager):
        """测试创建认证会话"""
        auth_session_id = auth_manager.create_auth_session("test_session", {"url": "http://example.com"})
        
        assert auth_session_id.startswith("auth_test_session_")
        assert auth_session_id in auth_manager._auth_sessions
    
    def test_get_auth_session(self, auth_manager):
        """测试获取认证会话"""
        auth_session_id = auth_manager.create_auth_session("test_session", {})
        
        session = auth_manager.get_auth_session(auth_session_id)
        
        assert session is not None
        assert session["session_id"] == "test_session"
    
    def test_update_auth_session(self, auth_manager):
        """测试更新认证会话"""
        auth_session_id = auth_manager.create_auth_session("test_session", {})
        
        auth_manager.update_auth_session(auth_session_id, step=1, status="in_progress")
        
        session = auth_manager.get_auth_session(auth_session_id)
        assert session["step"] == 1
        assert session["status"] == "in_progress"
    
    def test_delete_auth_session(self, auth_manager):
        """测试删除认证会话"""
        auth_session_id = auth_manager.create_auth_session("test_session", {})
        
        auth_manager.delete_auth_session(auth_session_id)
        
        assert auth_manager.get_auth_session(auth_session_id) is None


@pytest.mark.auth
class TestCSRFToken:
    """CSRF Token测试"""
    
    @pytest.fixture
    def auth_manager(self):
        from TOSKill.AI.tools import MultiStepAuthManager
        return MultiStepAuthManager()
    
    @pytest.mark.asyncio
    async def test_fetch_csrf_token_success(self, auth_manager):
        """测试获取CSRF Token成功"""
        with patch('requests.Session') as mock_session:
            mock_response = MagicMock()
            mock_response.text = '<input name="_token" value="csrf_token_value">'
            mock_response.status_code = 200
            
            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            result = await auth_manager.fetch_csrf_token("http://example.com/login")
            
            assert result["success"] == True
            assert result["csrf_token"] == "csrf_token_value"
    
    @pytest.mark.asyncio
    async def test_fetch_csrf_token_not_found(self, auth_manager):
        """测试获取CSRF Token未找到"""
        with patch('requests.Session') as mock_session:
            mock_response = MagicMock()
            mock_response.text = '<html>No token here</html>'
            mock_response.status_code = 200
            
            mock_session_instance = MagicMock()
            mock_session_instance.get.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            result = await auth_manager.fetch_csrf_token("http://example.com/login")
            
            assert result["success"] == True
            assert result["csrf_token"] is None


@pytest.mark.auth
class TestLoginFormSubmit:
    """登录表单提交测试"""
    
    @pytest.fixture
    def auth_manager(self):
        from TOSKill.AI.tools import MultiStepAuthManager
        return MultiStepAuthManager()
    
    @pytest.mark.asyncio
    async def test_submit_login_form_success(self, auth_manager):
        """测试提交登录表单成功"""
        with patch('requests.Session') as mock_session:
            mock_response = MagicMock()
            mock_response.text = '<html>Welcome to dashboard</html>'
            mock_response.status_code = 200
            mock_response.url = "http://example.com/dashboard"
            
            mock_session_instance = MagicMock()
            mock_session_instance.post.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            result = await auth_manager.submit_login_form(
                login_url="http://example.com/login",
                username="admin",
                password="password"
            )
            
            assert result["logged_in"] == True
    
    @pytest.mark.asyncio
    async def test_submit_login_form_failure(self, auth_manager):
        """测试提交登录表单失败"""
        with patch('requests.Session') as mock_session:
            mock_response = MagicMock()
            mock_response.text = '<html>Invalid credentials</html>'
            mock_response.status_code = 200
            
            mock_session_instance = MagicMock()
            mock_session_instance.post.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            result = await auth_manager.submit_login_form(
                login_url="http://example.com/login",
                username="wrong",
                password="wrong"
            )
            
            assert result["logged_in"] == False


@pytest.mark.auth
class TestToolResultValidation:
    """工具结果验证测试"""
    
    def test_validate_tool_result_valid(self):
        """测试验证有效工具结果"""
        from TOSKill.AI.tools import validate_tool_result
        
        result = {
            "success": True,
            "data": {"key": "value"},
            "timestamp": datetime.now().isoformat()
        }
        
        is_valid = validate_tool_result(result)
        
        assert is_valid == True
    
    def test_validate_tool_result_missing_success(self):
        """测试验证缺少success字段"""
        from TOSKill.AI.tools import validate_tool_result
        
        result = {
            "data": {"key": "value"},
            "timestamp": datetime.now().isoformat()
        }
        
        is_valid = validate_tool_result(result)
        
        assert is_valid == False
    
    def test_validate_tool_result_missing_data(self):
        """测试验证缺少data字段"""
        from TOSKill.AI.tools import validate_tool_result
        
        result = {
            "success": True,
            "timestamp": datetime.now().isoformat()
        }
        
        is_valid = validate_tool_result(result)
        
        assert is_valid == False
    
    def test_validate_tool_result_missing_timestamp(self):
        """测试验证缺少timestamp字段"""
        from TOSKill.AI.tools import validate_tool_result
        
        result = {
            "success": True,
            "data": {"key": "value"}
        }
        
        is_valid = validate_tool_result(result)
        
        assert is_valid == False
    
    def test_validate_tool_result_with_error(self):
        """测试验证带error字段"""
        from TOSKill.AI.tools import validate_tool_result
        
        result = {
            "success": False,
            "data": {},
            "error": "Something went wrong",
            "timestamp": datetime.now().isoformat()
        }
        
        is_valid = validate_tool_result(result)
        
        assert is_valid == True
    
    def test_validate_tool_result_with_auth_info(self):
        """测试验证带auth_info字段"""
        from TOSKill.AI.tools import validate_tool_result
        
        result = {
            "success": True,
            "data": {},
            "auth_info": {"cookies": {"session": "value"}},
            "timestamp": datetime.now().isoformat()
        }
        
        is_valid = validate_tool_result(result)
        
        assert is_valid == True
    
    def test_validate_tool_result_non_dict(self):
        """测试验证非字典结果"""
        from TOSKill.AI.tools import validate_tool_result
        
        is_valid = validate_tool_result("not a dict")
        
        assert is_valid == False


@pytest.mark.auth
class TestWrapToolResult:
    """工具结果包装测试"""
    
    def test_wrap_tool_result_success(self):
        """测试包装成功结果"""
        from TOSKill.AI.tools import wrap_tool_result
        
        result = wrap_tool_result(True, {"key": "value"})
        
        assert result["success"] == True
        assert result["data"] == {"key": "value"}
        assert result["error"] is None
        assert "timestamp" in result
    
    def test_wrap_tool_result_with_error(self):
        """测试包装带错误结果"""
        from TOSKill.AI.tools import wrap_tool_result
        
        result = wrap_tool_result(False, {}, error="Test error")
        
        assert result["success"] == False
        assert result["error"] == "Test error"
    
    def test_wrap_tool_result_with_auth_info(self):
        """测试包装带认证信息结果"""
        from TOSKill.AI.tools import wrap_tool_result
        
        auth_info = {"cookies": {"session": "value"}}
        result = wrap_tool_result(True, {}, auth_info=auth_info)
        
        assert result["auth_info"] == auth_info


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "auth"])
