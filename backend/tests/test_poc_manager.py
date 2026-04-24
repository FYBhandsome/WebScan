"""
Unit tests for POCManager module

Tests for:
- POCMetadata class
- POCVersion class
- POCDependency class
- POCManager class
- POC code retrieval
- Cache management
"""
import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from pathlib import Path
import tempfile
import os

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.ai_agents.poc_system.poc_manager import (
    POCMetadata,
    POCVersion,
    POCDependency,
    POCManager,
    POCSource,
    POCManagerError,
    POCNotFoundError,
    POCVersionIncompatibleError,
    POCSyncError,
    POCValidationError,
    poc_manager,
)


class TestPOCVersion:
    """Tests for POCVersion dataclass"""

    def test_create_with_defaults(self):
        version = POCVersion(version="1.0")
        assert version.version == "1.0"
        assert version.release_date is None
        assert version.changelog is None
        assert version.compatible is True

    def test_create_with_all_fields(self):
        now = datetime.now()
        version = POCVersion(
            version="2.0",
            release_date=now,
            changelog="Major update",
            compatible=True
        )
        assert version.version == "2.0"
        assert version.release_date == now
        assert version.changelog == "Major update"

    def test_to_dict(self):
        version = POCVersion(
            version="1.0",
            changelog="Initial release"
        )
        result = version.to_dict()
        assert result["version"] == "1.0"
        assert result["changelog"] == "Initial release"
        assert result["compatible"] is True


class TestPOCDependency:
    """Tests for POCDependency dataclass"""

    def test_create_with_defaults(self):
        dep = POCDependency(name="requests")
        assert dep.name == "requests"
        assert dep.version is None
        assert dep.required is True
        assert dep.description is None

    def test_create_with_all_fields(self):
        dep = POCDependency(
            name="requests",
            version="2.28.0",
            required=True,
            description="HTTP library"
        )
        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.required is True
        assert dep.description == "HTTP library"

    def test_to_dict(self):
        dep = POCDependency(
            name="requests",
            version="2.28.0",
            description="HTTP library"
        )
        result = dep.to_dict()
        assert result["name"] == "requests"
        assert result["version"] == "2.28.0"
        assert result["required"] is True


class TestPOCMetadata:
    """Tests for POCMetadata class"""

    def test_create_with_defaults(self):
        metadata = POCMetadata(
            poc_name="Test POC",
            poc_id="test_poc_001"
        )
        assert metadata.poc_name == "Test POC"
        assert metadata.poc_id == "test_poc_001"
        assert metadata.poc_type == "web"
        assert metadata.severity == "medium"
        assert metadata.cvss_score is None
        assert metadata.source == "seebug"
        assert metadata.version == "1.0"
        assert metadata.tags == []
        assert metadata.dependencies == []

    def test_create_with_all_fields(self):
        now = datetime.now()
        metadata = POCMetadata(
            poc_name="Test POC",
            poc_id="test_poc_001",
            poc_type="rce",
            severity="high",
            cvss_score=9.8,
            description="Test POC description",
            author="Test Author",
            source="local",
            version="2.0",
            tags=["rce", "critical"],
            dependencies=[POCDependency(name="requests")],
            min_pocsuite_version="1.8.0",
            created_at=now,
            updated_at=now
        )
        assert metadata.poc_name == "Test POC"
        assert metadata.poc_type == "rce"
        assert metadata.severity == "high"
        assert metadata.cvss_score == 9.8
        assert metadata.author == "Test Author"
        assert metadata.source == "local"
        assert metadata.version == "2.0"
        assert metadata.tags == ["rce", "critical"]
        assert len(metadata.dependencies) == 1

    def test_to_dict(self):
        metadata = POCMetadata(
            poc_name="Test POC",
            poc_id="test_poc_001",
            severity="high",
            tags=["test"]
        )
        result = metadata.to_dict()
        assert result["poc_name"] == "Test POC"
        assert result["poc_id"] == "test_poc_001"
        assert result["severity"] == "high"
        assert result["tags"] == ["test"]

    def test_update_version(self):
        metadata = POCMetadata(
            poc_name="Test POC",
            poc_id="test_poc_001"
        )
        import time
        time.sleep(0.001)
        metadata.update_version("2.0", "Bug fixes")
        
        assert metadata.version == "2.0"


class TestPOCSource:
    """Tests for POCSource enum"""

    def test_source_values(self):
        assert POCSource.SEEBUG.value == "seebug"
        assert POCSource.LOCAL.value == "local"
        assert POCSource.POCSUITE3.value == "pocsuite3"
        assert POCSource.GENERATED.value == "generated"
        assert POCSource.SEEBUG_AI.value == "seebug_ai"


class TestPOCManager:
    """Tests for POCManager class"""

    @pytest.fixture
    def manager(self):
        manager = POCManager()
        manager.poc_registry.clear()
        manager.generated_poc_codes.clear()
        manager.poc_cache.clear()
        return manager

    def test_initialization(self, manager):
        assert hasattr(manager, 'poc_registry')
        assert hasattr(manager, 'generated_poc_codes')
        assert hasattr(manager, 'poc_cache')
        assert hasattr(manager, 'pocsuite3_agent')
        assert manager.CURRENT_POCSUITE_VERSION == "1.9.0"

    def test_register_dynamic_poc(self, manager):
        result = manager.register_dynamic_poc(
            "dynamic_001",
            "print('poc code')"
        )
        assert result["success"] is True
        assert "dynamic_001" in manager.generated_poc_codes
        assert "dynamic_001" in manager.poc_registry

    def test_register_dynamic_poc_duplicate(self, manager):
        manager.register_dynamic_poc("dynamic_001", "code1")
        result = manager.register_dynamic_poc("dynamic_001", "code2")
        assert result["success"] is True
        assert manager.generated_poc_codes["dynamic_001"] == "code2"

    def test_get_poc_metadata(self, manager):
        metadata = POCMetadata(
            poc_name="Test POC",
            poc_id="test_001"
        )
        manager.poc_registry["test_001"] = metadata
        
        result = manager.get_poc_metadata("test_001")
        assert result.poc_name == "Test POC"

    def test_get_poc_metadata_not_found(self, manager):
        result = manager.get_poc_metadata("nonexistent")
        assert result is None

    def test_get_all_pocs(self, manager):
        manager.poc_registry["poc1"] = POCMetadata("POC 1", "poc1")
        manager.poc_registry["poc2"] = POCMetadata("POC 2", "poc2")
        
        all_pocs = manager.get_all_pocs()
        assert len(all_pocs) == 2

    def test_get_pocs_by_type(self, manager):
        manager.poc_registry["poc1"] = POCMetadata("POC 1", "poc1", poc_type="web")
        manager.poc_registry["poc2"] = POCMetadata("POC 2", "poc2", poc_type="rce")
        manager.poc_registry["poc3"] = POCMetadata("POC 3", "poc3", poc_type="web")
        
        web_pocs = manager.get_pocs_by_type("web")
        assert len(web_pocs) == 2

    def test_get_pocs_by_severity(self, manager):
        manager.poc_registry["poc1"] = POCMetadata("POC 1", "poc1", severity="high")
        manager.poc_registry["poc2"] = POCMetadata("POC 2", "poc2", severity="low")
        manager.poc_registry["poc3"] = POCMetadata("POC 3", "poc3", severity="high")
        
        high_pocs = manager.get_pocs_by_severity("high")
        assert len(high_pocs) == 2

    def test_get_pocs_by_source(self, manager):
        manager.poc_registry["poc1"] = POCMetadata("POC 1", "poc1", source="seebug")
        manager.poc_registry["poc2"] = POCMetadata("POC 2", "poc2", source="local")
        
        seebug_pocs = manager.get_pocs_by_source("seebug")
        assert len(seebug_pocs) == 1

    def test_get_pocs_by_tags(self, manager):
        manager.poc_registry["poc1"] = POCMetadata("POC 1", "poc1", tags=["rce", "critical"])
        manager.poc_registry["poc2"] = POCMetadata("POC 2", "poc2", tags=["xss"])
        manager.poc_registry["poc3"] = POCMetadata("POC 3", "poc3", tags=["rce"])
        
        rce_pocs = manager.get_pocs_by_tags(["rce"])
        assert len(rce_pocs) == 2
        
        critical_rce = manager.get_pocs_by_tags(["rce", "critical"], match_all=True)
        assert len(critical_rce) == 1

    def test_search_pocs(self, manager):
        manager.poc_registry["poc1"] = POCMetadata(
            "SQL Injection POC", "poc1",
            description="SQL injection vulnerability"
        )
        manager.poc_registry["poc2"] = POCMetadata(
            "XSS POC", "poc2",
            description="Cross-site scripting"
        )
        
        results = manager.search_pocs("sql")
        assert len(results) == 1
        assert results[0].poc_name == "SQL Injection POC"

    def test_get_poc_statistics(self, manager):
        manager.poc_registry["poc1"] = POCMetadata("POC 1", "poc1", poc_type="web", severity="high")
        manager.poc_registry["poc2"] = POCMetadata("POC 2", "poc2", poc_type="rce", severity="critical")
        
        stats = manager.get_poc_statistics()
        assert stats["total_count"] == 2
        assert "by_type" in stats
        assert "by_severity" in stats
        assert "cache_stats" in stats

    def test_clear_cache(self, manager):
        manager.poc_cache.set("key1", "value1")
        manager.poc_cache.set("key2", "value2")
        
        result = manager.clear_cache()
        assert result["success"] is True
        assert result["cleared_entries"] == 2

    def test_get_cache_stats(self, manager):
        stats = manager.get_cache_stats()
        assert "cache_entries" in stats
        assert "hits" in stats
        assert "misses" in stats

    def test_invalidate_cache(self, manager):
        manager.poc_cache.set("poc_code_001", "code1")
        manager.poc_cache.set("poc_code_002", "code2")
        manager.poc_cache.set("other_key", "value")
        
        result = manager.invalidate_cache("poc_code_")
        assert result["success"] is True
        assert result["invalidated_entries"] == 2

    def test_check_poc_version_compatibility_not_found(self, manager):
        result = manager.check_poc_version_compatibility("nonexistent")
        assert result["compatible"] is False
        assert "不存在" in result["reason"]

    def test_check_poc_version_compatibility_success(self, manager):
        metadata = POCMetadata("Test POC", "poc1", version="1.0")
        manager.poc_registry["poc1"] = metadata
        
        result = manager.check_poc_version_compatibility("poc1")
        assert result["compatible"] is True
        assert result["poc_id"] == "poc1"

    def test_update_poc_version(self, manager):
        metadata = POCMetadata("Test POC", "poc1", version="1.0")
        manager.poc_registry["poc1"] = metadata
        
        result = manager.update_poc_version("poc1", "2.0", "Major update")
        assert result["success"] is True
        assert manager.poc_registry["poc1"].version == "2.0"

    def test_update_poc_version_not_found(self, manager):
        result = manager.update_poc_version("nonexistent", "2.0")
        assert result["success"] is False

    def test_get_poc_version_info(self, manager):
        metadata = POCMetadata("Test POC", "poc1", version="1.0")
        manager.poc_registry["poc1"] = metadata
        
        result = manager.get_poc_version_info("poc1")
        assert result["success"] is True
        assert result["version"] == "1.0"

    def test_get_poc_version_info_not_found(self, manager):
        result = manager.get_poc_version_info("nonexistent")
        assert result["success"] is False

    def test_get_poc_dependencies(self, manager):
        dep = POCDependency(name="requests")
        metadata = POCMetadata("Test POC", "poc1", dependencies=[dep])
        manager.poc_registry["poc1"] = metadata
        
        deps = manager.get_poc_dependencies("poc1")
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_get_poc_dependencies_not_found(self, manager):
        deps = manager.get_poc_dependencies("nonexistent")
        assert deps == []

    def test_validate_poc_script(self, manager):
        valid_code = '''
from pocsuite3.api import POCBase, register_poc, VUL_TYPE
from pocsuite3.lib.core.interpreter_option import OptString

# class POC(POCBase) - POC class definition
class TestPOC(POCBase):
    vulID = 'test-001'
    version = '1.0'
    author = 'test'
    vulDate = '2024-01-01'
    createDate = '2024-01-01'
    updateDate = '2024-01-01'
    references = ['https://example.com']
    name = 'Test POC'
    appPowerLink = 'https://example.com'
    appName = 'Test App'
    appVersion = '1.0'
    vulType = VUL_TYPE.OTHER
    desc = 'Test description'
    severity = 'high'
    samples = []
    install_requires = []
    app = 'Test App'
    
    def _verify(self):
        result = {}
        return self.parse_output(result)
    
    def _attack(self):
        return self._verify()

register_poc(TestPOC)
'''
        result = manager.validate_poc_script(valid_code)
        assert result["is_valid"] is True

    def test_validate_poc_script_invalid(self, manager):
        invalid_code = "invalid python code {{{"
        result = manager.validate_poc_script(invalid_code)
        assert result["is_valid"] is False

    def test_compare_versions(self, manager):
        assert manager._compare_versions("1.9.0", "1.8.0") is True
        assert manager._compare_versions("1.8.0", "1.9.0") is False
        assert manager._compare_versions("2.0.0", "1.9.0") is True
        assert manager._compare_versions("1.0.0", "1.0.0") is True

    def test_extract_dependencies(self, manager):
        code = '''
import requests
from bs4 import BeautifulSoup
import os
'''
        deps = manager._extract_dependencies(code)
        dep_names = [d.name for d in deps]
        assert "requests" in dep_names
        assert "bs4" in dep_names

    def test_extract_min_version(self, manager):
        code = '''
min_version = "1.8.0"
'''
        version = manager._extract_min_version(code)
        assert version == "1.8.0"

    def test_extract_min_version_not_found(self, manager):
        code = "no version here"
        version = manager._extract_min_version(code)
        assert version is None

    def test_get_error_history(self, manager):
        manager._sync_errors = [
            {"operation": "op1", "error": "error1"},
            {"operation": "op2", "error": "error2"}
        ]
        
        history = manager.get_error_history()
        assert len(history) == 2

    def test_clear_error_history(self, manager):
        manager._sync_errors = [{"operation": "op1"}]
        
        result = manager.clear_error_history()
        assert result["success"] is True
        assert result["cleared_count"] == 1
        assert len(manager._sync_errors) == 0


class TestPOCManagerAsyncMethods:
    """Tests for POCManager async methods"""

    @pytest.fixture
    def manager(self):
        manager = POCManager()
        manager.poc_registry.clear()
        manager.generated_poc_codes.clear()
        manager.poc_cache.clear()
        return manager

    @pytest.mark.asyncio
    async def test_get_poc_code_from_generated(self, manager):
        manager.generated_poc_codes["gen_001"] = "print('generated code')"
        
        code = await manager.get_poc_code("gen_001")
        assert code == "print('generated code')"

    @pytest.mark.asyncio
    async def test_get_poc_code_from_cache(self, manager):
        manager.poc_cache.set("poc_code_cached_001", "cached code")
        
        code = await manager.get_poc_code("cached_001")
        assert code == "cached code"

    @pytest.mark.asyncio
    async def test_get_poc_code_not_found(self, manager):
        code = await manager.get_poc_code("nonexistent_poc")
        assert code is None

    @pytest.mark.asyncio
    async def test_register_generated_poc(self, manager):
        metadata = POCMetadata(
            poc_name="Generated POC",
            poc_id="gen_001",
            source=POCSource.GENERATED.value
        )
        
        result = manager.register_generated_poc("gen_001", "poc code", metadata)
        assert result["success"] is True
        assert "gen_001" in manager.generated_poc_codes
        assert "gen_001" in manager.poc_registry

    @pytest.mark.asyncio
    async def test_sync_from_seebug_with_mock(self, manager):
        with patch('backend.ai_agents.poc_system.poc_manager.seebug_utils') as mock_utils:
            mock_response = Mock()
            mock_response.success = True
            mock_response.data = {
                "list": [
                    {"ssvid": "123", "name": "Test POC", "severity": "high"}
                ]
            }
            mock_utils.search_poc = AsyncMock(return_value=mock_response)
            
            result = await manager.sync_from_seebug("test", limit=10)
            assert len(result) == 1
            assert result[0].poc_name == "Test POC"

    @pytest.mark.asyncio
    async def test_sync_from_seebug_failure(self, manager):
        with patch('backend.ai_agents.poc_system.poc_manager.seebug_utils') as mock_utils:
            mock_response = Mock()
            mock_response.success = False
            mock_response.message = "API Error"
            mock_utils.search_poc = AsyncMock(return_value=mock_response)
            
            result = await manager.sync_from_seebug("test")
            assert result == []

    @pytest.mark.asyncio
    async def test_download_poc_from_seebug_with_mock(self, manager):
        with patch('backend.ai_agents.poc_system.poc_manager.seebug_utils') as mock_utils:
            mock_response = Mock()
            mock_response.success = True
            mock_response.data = {"code": "print('poc code')"}
            mock_utils.download_poc = AsyncMock(return_value=mock_response)
            
            code = await manager.download_poc_from_seebug(12345)
            assert code == "print('poc code')"

    @pytest.mark.asyncio
    async def test_download_poc_from_seebug_cached(self, manager):
        manager.poc_cache.set("poc_code_12345", "cached poc code")
        
        code = await manager.download_poc_from_seebug(12345)
        assert code == "cached poc code"

    @pytest.mark.asyncio
    async def test_download_poc_from_seebug_failure(self, manager):
        with patch('backend.ai_agents.poc_system.poc_manager.seebug_utils') as mock_utils:
            mock_response = Mock()
            mock_response.success = False
            mock_response.message = "Download failed"
            mock_utils.download_poc = AsyncMock(return_value=mock_response)
            
            code = await manager.download_poc_from_seebug(99999)
            assert code is None

    @pytest.mark.asyncio
    async def test_save_poc_to_local(self, manager):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(manager, '_log_operation'):
                result = await manager.save_poc_to_local(
                    ssvid=12345,
                    poc_code="print('test')",
                    category="test",
                    cve_id="CVE-2024-1234"
                )
                assert result["success"] is True
                assert "file_path" in result

    @pytest.mark.asyncio
    async def test_load_local_poc(self, manager):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('test poc')")
            temp_path = f.name
        
        try:
            result = await manager.load_local_poc(temp_path)
            assert result is not None
            assert result.poc_name == Path(temp_path).stem
            assert result.source == POCSource.LOCAL.value
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_load_local_poc_not_found(self, manager):
        result = await manager.load_local_poc("/nonexistent/path/poc.py")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_poc_to_latest_version_not_found(self, manager):
        result = await manager.update_poc_to_latest_version("nonexistent")
        assert result["success"] is False


class TestPOCManagerExceptions:
    """Tests for POCManager exceptions"""

    def test_poc_manager_error(self):
        with pytest.raises(POCManagerError):
            raise POCManagerError("Test error")

    def test_poc_not_found_error(self):
        with pytest.raises(POCNotFoundError):
            raise POCNotFoundError("POC not found")

    def test_poc_version_incompatible_error(self):
        with pytest.raises(POCVersionIncompatibleError):
            raise POCVersionIncompatibleError("Version incompatible")

    def test_poc_sync_error(self):
        with pytest.raises(POCSyncError):
            raise POCSyncError("Sync failed")

    def test_poc_validation_error(self):
        with pytest.raises(POCValidationError):
            raise POCValidationError("Validation failed")


class TestGlobalPOCManager:
    """Tests for global poc_manager instance"""

    def test_global_instance_exists(self):
        assert poc_manager is not None
        assert isinstance(poc_manager, POCManager)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
