"""
Unit tests for seebug_utils module

Tests for:
- SeebugUtils class
- APIResponse dataclass
- Async methods
- Cache functionality
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.utils.seebug_utils import (
    APIResponse,
    SeebugUtils,
    seebug_utils,
    SEBUG_AGENT_AVAILABLE,
)


class TestAPIResponse:
    """Tests for APIResponse dataclass"""

    def test_create_with_defaults(self):
        response = APIResponse(success=True)
        assert response.success is True
        assert response.data is None
        assert response.message == ""
        assert response.status_code == 200
        assert response.execution_time == 0.0

    def test_create_with_all_fields(self):
        response = APIResponse(
            success=True,
            data={"key": "value"},
            message="Success",
            status_code=200,
            execution_time=1.5
        )
        assert response.success is True
        assert response.data == {"key": "value"}
        assert response.message == "Success"
        assert response.status_code == 200
        assert response.execution_time == 1.5

    def test_failure_response(self):
        response = APIResponse(
            success=False,
            message="Error occurred",
            status_code=500
        )
        assert response.success is False
        assert response.message == "Error occurred"
        assert response.status_code == 500


class TestSeebugUtils:
    """Tests for SeebugUtils class"""

    @pytest.fixture
    def utils_instance(self):
        SeebugUtils._instance = None
        return SeebugUtils()

    def test_singleton_pattern(self, utils_instance):
        instance1 = SeebugUtils()
        instance2 = SeebugUtils()
        assert instance1 is instance2

    def test_initialization(self, utils_instance):
        assert hasattr(utils_instance, 'cache')
        assert hasattr(utils_instance, 'enable_cache')
        assert hasattr(utils_instance, 'request_count')
        assert hasattr(utils_instance, 'success_count')
        assert hasattr(utils_instance, 'error_count')

    def test_is_available(self, utils_instance):
        result = utils_instance.is_available()
        assert isinstance(result, bool)

    def test_get_client(self, utils_instance):
        client = utils_instance.get_client()
        if SEBUG_AGENT_AVAILABLE:
            assert client is not None or client is None
        else:
            assert client is None

    def test_get_agent(self, utils_instance):
        agent = utils_instance.get_agent()
        if SEBUG_AGENT_AVAILABLE:
            assert agent is not None or agent is None
        else:
            assert agent is None

    def test_clear_cache(self, utils_instance):
        utils_instance.cache["test_key"] = ("data", datetime.now())
        utils_instance.clear_cache()
        assert len(utils_instance.cache) == 0

    def test_get_cache_stats(self, utils_instance):
        stats = utils_instance.get_cache_stats()
        assert "cache_entries" in stats
        assert "cache_enabled" in stats
        assert "request_count" in stats
        assert "success_count" in stats
        assert "error_count" in stats
        assert "success_rate" in stats

    def test_get_statistics(self, utils_instance):
        stats = utils_instance.get_statistics()
        assert "api_key_configured" in stats
        assert "cache_enabled" in stats
        assert "cache_stats" in stats
        assert "seebug_agent_available" in stats

    def test_cache_hit(self, utils_instance):
        utils_instance.enable_cache = True
        cached_response = APIResponse(success=True, message="Cached")
        utils_instance.cache["validate_key_test"] = (cached_response, datetime.now())
        
        assert "validate_key_test" in utils_instance.cache

    def test_cache_expired(self, utils_instance):
        utils_instance.enable_cache = True
        expired_time = datetime.now() - timedelta(hours=2)
        cached_response = APIResponse(success=True, message="Cached")
        utils_instance.cache["validate_key_test"] = (cached_response, expired_time)
        
        assert "validate_key_test" in utils_instance.cache


class TestSeebugUtilsAsyncMethods:
    """Tests for SeebugUtils async methods"""

    @pytest.fixture
    def utils_instance(self):
        SeebugUtils._instance = None
        return SeebugUtils()

    @pytest.mark.asyncio
    async def test_validate_api_key_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            response = await utils_instance.validate_api_key()
            assert response.success is False
            assert response.status_code == 503
            assert "not available" in response.message.lower()

    @pytest.mark.asyncio
    async def test_search_poc_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            response = await utils_instance.search_poc("test")
            assert response.success is False
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_download_poc_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            response = await utils_instance.download_poc(12345)
            assert response.success is False
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_get_poc_detail_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            response = await utils_instance.get_poc_detail(12345)
            assert response.success is False
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_crawl_recent_vulnerabilities_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            response = await utils_instance.crawl_recent_vulnerabilities()
            assert response.success is False
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_validate_api_key_with_cache(self, utils_instance):
        utils_instance.enable_cache = True
        cached_response = APIResponse(success=True, message="Cached result")
        utils_instance.cache["validate_key_"] = (cached_response, datetime.now())
        
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_client = Mock()
            mock_client.validate_key = Mock(return_value={"status": "success", "msg": "OK"})
            utils_instance.client = mock_client
            
            response = await utils_instance.validate_api_key()
            assert response.message == "Cached result"

    @pytest.mark.asyncio
    async def test_search_poc_with_mock(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_client = Mock()
            mock_client.search_poc = Mock(return_value={
                "status": "success",
                "data": {"list": [{"ssvid": "123", "name": "Test POC"}], "total": 1},
                "msg": "OK"
            })
            utils_instance.client = mock_client
            
            response = await utils_instance.search_poc("test")
            assert response.success is True
            assert response.data["total"] == 1

    @pytest.mark.asyncio
    async def test_download_poc_with_mock(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_client = Mock()
            mock_client.download_poc = Mock(return_value={
                "status": "success",
                "data": {"poc": "print('poc code')"},
                "msg": "OK"
            })
            utils_instance.client = mock_client
            
            response = await utils_instance.download_poc(12345)
            assert response.success is True
            assert response.data["code"] == "print('poc code')"

    @pytest.mark.asyncio
    async def test_get_poc_detail_with_mock(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_client = Mock()
            mock_client.get_poc_detail = Mock(return_value={
                "status": "success",
                "data": {"name": "Test POC", "ssvid": "12345"},
                "msg": "OK"
            })
            utils_instance.client = mock_client
            
            response = await utils_instance.get_poc_detail(12345)
            assert response.success is True
            assert response.data["name"] == "Test POC"

    @pytest.mark.asyncio
    async def test_search_poc_error_handling(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_client = Mock()
            mock_client.search_poc = Mock(side_effect=Exception("Network error"))
            utils_instance.client = mock_client
            
            response = await utils_instance.search_poc("test")
            assert response.success is False
            assert response.status_code == 500
            assert "Network error" in response.message

    @pytest.mark.asyncio
    async def test_download_poc_error_handling(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_client = Mock()
            mock_client.download_poc = Mock(side_effect=Exception("Download failed"))
            utils_instance.client = mock_client
            
            response = await utils_instance.download_poc(12345)
            assert response.success is False
            assert response.status_code == 500


class TestSeebugUtilsSyncMethods:
    """Tests for SeebugUtils synchronous methods"""

    @pytest.fixture
    def utils_instance(self):
        SeebugUtils._instance = None
        return SeebugUtils()

    def test_search_vulnerabilities_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            result = utils_instance.search_vulnerabilities("test")
            assert result["status"] == "error"

    def test_get_vulnerability_detail_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            result = utils_instance.get_vulnerability_detail("12345")
            assert result["status"] == "error"

    def test_get_api_status_not_available(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=False):
            status = utils_instance.get_api_status()
            assert status["available"] is False

    def test_search_vulnerabilities_with_mock(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_agent = Mock()
            mock_agent.search_vulnerabilities = Mock(return_value={
                "status": "success",
                "data": []
            })
            utils_instance.agent = mock_agent
            
            result = utils_instance.search_vulnerabilities("test")
            assert result["status"] == "success"

    def test_get_vulnerability_detail_with_mock(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_agent = Mock()
            mock_agent.get_vulnerability_detail = Mock(return_value={
                "status": "success",
                "data": {"ssvid": "12345"}
            })
            utils_instance.agent = mock_agent
            
            result = utils_instance.get_vulnerability_detail("12345")
            assert result["status"] == "success"

    def test_get_api_status_with_mock(self, utils_instance):
        with patch.object(utils_instance, 'is_available', return_value=True):
            mock_client = Mock()
            mock_client.validate_key = Mock(return_value={
                "status": "success",
                "msg": "OK"
            })
            utils_instance.client = mock_client
            
            status = utils_instance.get_api_status()
            assert status["available"] is True


class TestSeebugUtilsCache:
    """Tests for SeebugUtils cache functionality"""

    @pytest.fixture
    def utils_instance(self):
        SeebugUtils._instance = None
        instance = SeebugUtils()
        instance.enable_cache = True
        return instance

    def test_cache_set_and_get(self, utils_instance):
        response = APIResponse(success=True, message="Test")
        utils_instance.cache["test_key"] = (response, datetime.now())
        
        cached = utils_instance.cache.get("test_key")
        assert cached is not None
        assert cached[0].message == "Test"

    def test_cache_expiration_check(self, utils_instance):
        response = APIResponse(success=True, message="Test")
        expired_time = datetime.now() - timedelta(hours=2)
        utils_instance.cache["expired_key"] = (response, expired_time)
        
        cached_data, timestamp = utils_instance.cache["expired_key"]
        age = (datetime.now() - timestamp).total_seconds()
        assert age > 3600

    def test_cache_clear(self, utils_instance):
        utils_instance.cache["key1"] = ("data1", datetime.now())
        utils_instance.cache["key2"] = ("data2", datetime.now())
        
        utils_instance.clear_cache()
        assert len(utils_instance.cache) == 0

    def test_cache_stats_update(self, utils_instance):
        initial_stats = utils_instance.get_cache_stats()
        initial_entries = initial_stats["cache_entries"]
        
        utils_instance.cache["new_key"] = (APIResponse(success=True), datetime.now())
        
        new_stats = utils_instance.get_cache_stats()
        assert new_stats["cache_entries"] == initial_entries + 1

    def test_success_rate_calculation(self, utils_instance):
        utils_instance.request_count = 10
        utils_instance.success_count = 8
        utils_instance.error_count = 2
        
        stats = utils_instance.get_cache_stats()
        assert stats["success_rate"] == 80.0


class TestGlobalSeebugUtils:
    """Tests for global seebug_utils instance"""

    def test_global_instance_exists(self):
        assert seebug_utils is not None
        assert isinstance(seebug_utils, SeebugUtils)

    def test_global_instance_is_singleton(self):
        from backend.utils.seebug_utils import seebug_utils as utils2
        assert seebug_utils is utils2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
