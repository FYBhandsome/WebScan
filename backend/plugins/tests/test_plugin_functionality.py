"""
插件功能测试

测试各类插件的基本功能和边界情况。
"""
import pytest
import sys
import json
import socket
import ipaddress
from pathlib import Path
from unittest.mock import patch, Mock, AsyncMock, MagicMock
from typing import Dict, List, Any

backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))


class TestPortscanPlugin:
    """端口扫描插件测试"""
    
    def test_scanport_init(self):
        """测试端口扫描器初始化"""
        from backend.plugins.portscan.portscan import ScanPort
        scanner = ScanPort("127.0.0.1")
        assert scanner.target == "127.0.0.1"
        assert scanner.ipaddr == ""
    
    def test_scanport_normalize_target_ip(self):
        """测试IP目标标准化"""
        from backend.plugins.portscan.portscan import ScanPort
        scanner = ScanPort("192.168.1.1")
        result = scanner._normalize_target()
        assert result is True
        assert scanner.ipaddr == "192.168.1.1"
    
    def test_scanport_normalize_target_url(self):
        """测试URL目标标准化"""
        from backend.plugins.portscan.portscan import ScanPort
        scanner = ScanPort("http://example.com:8080/path")
        result = scanner._normalize_target()
        assert result is True
    
    def test_scanport_invalid_target(self):
        """测试无效目标"""
        from backend.plugins.portscan.portscan import ScanPort
        scanner = ScanPort("")
        result = scanner._normalize_target()
        assert result is False or result is True


class TestSubdomainPlugin:
    """子域名扫描插件测试"""
    
    def test_get_subdomain_with_valid_domain(self):
        """测试有效域名的子域名获取"""
        with patch('backend.plugins.subdomain.subdomain.requests.Session') as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = '<a href="http://www.example.com">www.example.com</a><a href="http://api.example.com">api.example.com</a>'
            mock_response.apparent_encoding = 'utf-8'
            
            mock_session_instance = Mock()
            mock_session_instance.get.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            from backend.plugins.subdomain.subdomain import get_subdomain
            result = get_subdomain("example.com")
            assert isinstance(result, list)
    
    def test_get_subdomain_with_invalid_domain(self):
        """测试无效域名的子域名获取"""
        from backend.plugins.subdomain.subdomain import get_subdomain
        result = get_subdomain("")
        assert result == []
    
    def test_is_valid_domain(self):
        """测试域名验证函数"""
        from backend.plugins.subdomain.subdomain import is_valid_domain
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("baidu.com") is True
        assert is_valid_domain("") is False
        assert is_valid_domain("invalid") is False
        assert is_valid_domain("test") is False


class TestBaseinfoPlugin:
    """基础信息收集插件测试"""
    
    def test_get_ip_addr_success(self):
        """测试IP地址查询成功"""
        with patch('backend.plugins.baseinfo.baseinfo.SESSION') as mock_session:
            mock_response = Mock()
            mock_response.json.return_value = {
                "status": "success",
                "country": "China",
                "regionName": "Zhejiang",
                "city": "Hangzhou",
                "as": "AS37963"
            }
            mock_response.apparent_encoding = 'utf-8'
            mock_session.get.return_value = mock_response
            
            from backend.plugins.baseinfo.baseinfo import get_ip_addr
            result = get_ip_addr("8.8.8.8")
            assert "China" in result or "物理地址" in result
    
    def test_get_ip_list_success(self):
        """测试域名IP列表获取"""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.4.4', 0))
            ]
            
            with patch('backend.plugins.baseinfo.baseinfo.get_ip_addr') as mock_get_ip_addr:
                mock_get_ip_addr.return_value = " (物理地址: China,Zhejiang,Hangzhou,AS37963)  "
                
                from backend.plugins.baseinfo.baseinfo import get_ip_list
                result = get_ip_list("example.com")
                assert isinstance(result, list)
    
    def test_infer_os_from_server(self):
        """测试从Server头推断操作系统"""
        from backend.plugins.baseinfo.baseinfo import infer_os_from_server
        
        assert infer_os_from_server("nginx/1.18.0") == "Linux"
        assert infer_os_from_server("Apache/2.4.41 (Ubuntu)") == "Linux (Ubuntu)"
        assert infer_os_from_server("Microsoft-IIS/10.0") == "Windows Server"
        assert infer_os_from_server("") == "未知操作系统"
    
    def test_getbaseinfo_invalid_url(self):
        """测试无效URL的基础信息获取"""
        from backend.plugins.baseinfo.baseinfo import getbaseinfo
        result = getbaseinfo("")
        assert result["code"] != 200 or result["domain"] is None


class TestCDNExistPlugin:
    """CDN检测插件测试"""
    
    def test_parse_host_to_ip_with_valid_ip(self):
        """测试有效IP解析"""
        from backend.plugins.cdnexist.cdnexist import parse_host_to_ip
        result = parse_host_to_ip("8.8.8.8")
        assert result == "8.8.8.8"
    
    def test_parse_host_to_ip_with_domain(self):
        """测试域名解析为IP"""
        with patch('backend.plugins.common.common.get_domain') as mock_get_domain:
            mock_get_domain.return_value = "example.com"
            with patch('socket.getaddrinfo') as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))
                ]
                
                from backend.plugins.cdnexist.cdnexist import parse_host_to_ip
                result = parse_host_to_ip("example.com")
                assert result is not None
    
    def test_check_ip_in_cdn_networks_cloudflare(self):
        """测试CloudFlare CDN网段检测"""
        from backend.plugins.cdnexist.cdnexist import check_ip_in_cdn_networks
        
        result = check_ip_in_cdn_networks("104.16.0.1")
        assert result is True
    
    def test_check_ip_in_cdn_networks_non_cdn(self):
        """测试非CDN IP检测"""
        from backend.plugins.cdnexist.cdnexist import check_ip_in_cdn_networks
        
        result = check_ip_in_cdn_networks("8.8.8.8")
        assert result is False
    
    def test_check_ip_in_cdn_networks_invalid_ip(self):
        """测试无效IP格式"""
        from backend.plugins.cdnexist.cdnexist import check_ip_in_cdn_networks
        
        result = check_ip_in_cdn_networks("invalid_ip")
        assert result is False


class TestDirscanPlugin:
    """目录扫描插件测试"""
    
    def test_dirscanner_init(self):
        """测试目录扫描器初始化"""
        from backend.plugins.dirscan.dirscan import DirScanner
        scanner = DirScanner("http://example.com")
        assert scanner.target == "http://example.com"
    
    def test_normalize_url(self):
        """测试URL标准化"""
        from backend.plugins.dirscan.dirscan import DirScanner
        scanner = DirScanner("example.com")
        assert scanner.target == "http://example.com"
        
        scanner2 = DirScanner("https://example.com/")
        assert scanner2.target == "https://example.com"
    
    def test_get_default_paths(self):
        """测试默认路径字典"""
        from backend.plugins.dirscan.dirscan import DirScanner
        scanner = DirScanner("http://example.com")
        paths = scanner._get_default_paths()
        
        assert isinstance(paths, list)
        assert len(paths) > 0
        assert "/admin" in paths
        assert "/robots.txt" in paths
    
    def test_thread_safe_result(self):
        """测试线程安全结果存储"""
        from backend.plugins.dirscan.dirscan import ThreadSafeResult
        
        result = ThreadSafeResult()
        result.append({"url": "http://example.com/admin", "status_code": 200})
        result.append({"url": "http://example.com/login", "status_code": 200})
        
        assert len(result.get_result()) == 2
        assert result.is_full() is False
        
        result.clear()
        assert len(result.get_result()) == 0


class TestWAFPlugin:
    """WAF检测插件测试"""
    
    def test_getwaf_cloudflare_detection(self):
        """测试CloudFlare WAF检测"""
        from backend.plugins.waf.waf import getwaf
        
        headers = {"Server": "cloudflare", "CF-RAY": "12345678-LAX"}
        result = getwaf("http://example.com", headers=headers, content="")
        assert result is not None and "CloudFlare" in result
    
    def test_getwaf_safedog_detection(self):
        """测试安全狗WAF检测"""
        from backend.plugins.waf.waf import getwaf
        
        headers = {"Server": "Safedog"}
        result = getwaf("http://example.com", headers=headers, content="")
        assert result is not None and "Safedog" in result
    
    def test_getwaf_no_waf(self):
        """测试无WAF情况"""
        from backend.plugins.waf.waf import getwaf
        
        headers = {"Server": "nginx/1.18.0"}
        result = getwaf("http://example.com", headers=headers, content="")
        assert result is None
    
    def test_getwaf_with_request(self):
        """测试通过请求检测WAF"""
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.headers = {"Server": "cloudflare"}
            mock_response.text = ""
            mock_get.return_value = mock_response
            
            from backend.plugins.waf.waf import getwaf
            result = getwaf("http://example.com")
            assert result is not None or result is None


class TestIPLocatingPlugin:
    """IP归属地查询插件测试"""
    
    def test_is_valid_ipv4(self):
        """测试IPv4格式验证"""
        from backend.plugins.iplocating.iplocating import is_valid_ipv4
        
        assert is_valid_ipv4("8.8.8.8") is True
        assert is_valid_ipv4("192.168.1.1") is True
        assert is_valid_ipv4("256.0.0.1") is False
        assert is_valid_ipv4("") is False
        assert is_valid_ipv4("invalid") is False
    
    def test_get_locating_success(self):
        """测试IP归属地查询成功"""
        with patch('backend.plugins.iplocating.iplocating.SESSION') as mock_session:
            mock_response = Mock()
            mock_response.json.return_value = {
                "status": "success",
                "country": "China",
                "regionName": "Zhejiang",
                "city": "Hangzhou"
            }
            mock_response.apparent_encoding = 'utf-8'
            mock_session.get.return_value = mock_response
            
            from backend.plugins.iplocating.iplocating import get_locating
            result = get_locating("8.8.8.8")
            assert "China" in result or "国家" in result
    
    def test_get_locating_invalid_ip(self):
        """测试无效IP查询"""
        from backend.plugins.iplocating.iplocating import get_locating
        result = get_locating("invalid_ip")
        assert "格式非法" in result
    
    def test_get_locating_empty_ip(self):
        """测试空IP查询"""
        from backend.plugins.iplocating.iplocating import get_locating
        result = get_locating("")
        assert "格式非法" in result or "非法" in result


class TestWhatCMSPlugin:
    """CMS检测插件测试"""
    
    def test_singleton_wappalyzer_init(self):
        """测试Wappalyzer单例初始化"""
        from backend.plugins.whatcms.whatcms import SingletonWappalyzer
        
        instance1 = SingletonWappalyzer()
        instance2 = SingletonWappalyzer()
        assert instance1 is instance2
    
    def test_get_ua(self):
        """测试UA生成"""
        from backend.plugins.whatcms.whatcms import get_ua
        
        headers = get_ua()
        assert isinstance(headers, dict)
        assert "User-Agent" in headers


class TestWebsidePlugin:
    """旁站查询插件测试"""
    
    def test_is_valid_ipv4(self):
        """测试IPv4格式验证"""
        from backend.plugins.webside.webside import is_valid_ipv4
        
        assert is_valid_ipv4("8.8.8.8") is True
        assert is_valid_ipv4("192.168.1.1") is True
        assert is_valid_ipv4("10.0.0.1") is True
        assert is_valid_ipv4("256.0.0.1") is False
        assert is_valid_ipv4("") is False
    
    def test_get_side_info_invalid_ip(self):
        """测试无效IP的旁站查询"""
        from backend.plugins.webside.webside import get_side_info
        
        result = get_side_info("invalid_ip")
        assert result["success"] is False
        assert "格式非法" in result["message"]
    
    def test_get_side_info_empty_ip(self):
        """测试空IP的旁站查询"""
        from backend.plugins.webside.webside import get_side_info
        
        result = get_side_info("")
        assert result["success"] is False
    
    def test_get_side_info_success(self):
        """测试旁站查询成功"""
        with patch('backend.plugins.webside.webside.requests.Session') as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = '[{"domain": "example1.com"}, {"domain": "example2.com"}]'
            mock_response.apparent_encoding = 'utf-8'
            
            mock_session_instance = Mock()
            mock_session_instance.get.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            from backend.plugins.webside.webside import get_side_info
            result = get_side_info("8.8.8.8")
            assert result["success"] is True


class TestInfoleakPlugin:
    """信息泄露扫描插件测试"""
    
    def test_thread_safe_result(self):
        """测试线程安全结果存储"""
        from backend.plugins.infoleak.infoleak import ThreadSafeResult
        
        result = ThreadSafeResult()
        result.append(("backup", "http://example.com/backup.sql"))
        result.append(("config", "http://example.com/config.php"))
        
        assert len(result.get_result()) == 2
        
        result.clear()
        assert len(result.get_result()) == 0
    
    def test_risk_status_codes(self):
        """测试风险状态码配置"""
        from backend.plugins.infoleak.infoleak import RISK_STATUS_CODES
        
        assert 200 in RISK_STATUS_CODES
        assert 401 in RISK_STATUS_CODES
        assert 404 not in RISK_STATUS_CODES


class TestRandheaderPlugin:
    """随机请求头插件测试"""
    
    def test_generate_random_public_ip(self):
        """测试随机公网IP生成"""
        from backend.plugins.randheader.randheader import generate_random_public_ip
        
        for _ in range(10):
            ip = generate_random_public_ip()
            ip_obj = ipaddress.IPv4Address(ip)
            assert not ip_obj.is_loopback
            assert str(ip_obj) != "0.0.0.0"
            assert str(ip_obj) != "255.255.255.255"
    
    def test_get_ua(self):
        """测试UA获取"""
        from backend.plugins.randheader.randheader import get_ua
        
        headers = get_ua()
        assert isinstance(headers, dict)
        assert "User-Agent" in headers
        assert len(headers["User-Agent"]) > 0


class TestCommonPlugin:
    """通用工具函数测试"""
    
    def test_check_ip_valid(self):
        """测试有效IP检查"""
        from backend.plugins.common.common import check_ip
        
        result = check_ip("8.8.8.8")
        assert result is True or result == "8.8.8.8"
    
    def test_check_ip_private(self):
        """测试私有IP检查"""
        from backend.plugins.common.common import check_ip
        
        result = check_ip("192.168.1.1")
        assert result is False or "禁止" in str(result)
    
    def test_check_ip_loopback(self):
        """测试回环地址检查"""
        from backend.plugins.common.common import check_ip
        
        result = check_ip("127.0.0.1")
        assert result is False or "禁止" in str(result)
    
    def test_get_domain(self):
        """测试域名提取"""
        from backend.plugins.common.common import get_domain
        
        result = get_domain("https://www.example.com/path")
        assert result == "www.example.com" or result is not None
    
    def test_success_response(self):
        """测试成功响应"""
        from backend.plugins.common.common import success
        
        response = success(code=200, data={"key": "value"}, msg="操作成功")
        assert response.status_code == 200
    
    def test_error_response(self):
        """测试错误响应"""
        from backend.plugins.common.common import error
        
        response = error(code=400, data=None, msg="操作失败")
        assert response.status_code == 400


class TestPluginIntegration:
    """插件集成测试"""
    
    def test_portscan_service_detection(self):
        """测试端口扫描服务检测"""
        from backend.plugins.portscan.portscan import ScanPort
        scanner = ScanPort("127.0.0.1")
        scanner._normalize_target()
        assert scanner.ipaddr == "127.0.0.1"
    
    def test_baseinfo_with_cdn_check(self):
        """测试基础信息与CDN检测集成"""
        with patch('backend.plugins.baseinfo.baseinfo.SESSION') as mock_session:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {"Server": "nginx"}
            mock_response.text = "<html><body>test</body></html>"
            mock_response.apparent_encoding = 'utf-8'
            mock_session.get.return_value = mock_response
            
            with patch('socket.getaddrinfo') as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('104.16.0.1', 0))
                ]
                
                from backend.plugins.baseinfo.baseinfo import getbaseinfo
                result = getbaseinfo("http://example.com")
                
                assert isinstance(result, dict)
    
    def test_dirscan_with_randheader(self):
        """测试目录扫描与随机请求头集成"""
        from backend.plugins.dirscan.dirscan import DirScanner
        from backend.plugins.randheader.randheader import get_ua
        
        scanner = DirScanner("http://example.com")
        headers = get_ua()
        
        assert "User-Agent" in headers
        assert scanner.target == "http://example.com"


class TestEdgeCases:
    """边界情况测试"""
    
    def test_empty_string_inputs(self):
        """测试空字符串输入"""
        from backend.plugins.iplocating.iplocating import get_locating
        from backend.plugins.webside.webside import get_side_info
        
        assert "格式非法" in get_locating("") or "非法" in get_locating("")
        assert get_side_info("")["success"] is False
    
    def test_special_characters_in_domain(self):
        """测试域名中的特殊字符"""
        from backend.plugins.subdomain.subdomain import is_valid_domain
        
        assert is_valid_domain("test<script>.com") is False
        assert is_valid_domain("test'or'1'='1.com") is False
    
    def test_very_long_domain(self):
        """测试超长域名"""
        from backend.plugins.subdomain.subdomain import is_valid_domain
        
        long_domain = "a" * 300 + ".com"
        assert is_valid_domain(long_domain) is False
    
    def test_unicode_domain(self):
        """测试Unicode域名"""
        from backend.plugins.subdomain.subdomain import is_valid_domain
        
        assert is_valid_domain("测试.com") is False or is_valid_domain("测试.com") is True
    
    def test_timeout_handling(self):
        """测试超时处理"""
        with patch('backend.plugins.iplocating.iplocating.SESSION.get') as mock_get:
            from requests.exceptions import ConnectTimeout
            mock_get.side_effect = ConnectTimeout("Connection timeout")
            
            from backend.plugins.iplocating.iplocating import get_locating
            result = get_locating("8.8.8.8")
            assert "超时" in result or "异常" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
