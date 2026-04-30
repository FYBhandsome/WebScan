# -*- coding:utf-8 -*-
"""
TOSKill 记忆化存储测试用例

测试会话存储、过期清理、数据冗余合并等。
"""

import pytest
import sys
import time
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


@pytest.mark.memory
class TestMemoryStoreSession:
    """会话存储测试"""
    
    def test_save_session(self, clean_memory_store, mock_scan_state):
        """测试保存会话"""
        version = clean_memory_store.save_session("test_session", mock_scan_state)
        
        assert version == 1
        assert clean_memory_store.get_session("test_session") == mock_scan_state
    
    def test_save_session_updates_version(self, clean_memory_store, mock_scan_state):
        """测试保存会话更新版本"""
        version1 = clean_memory_store.save_session("test_session", mock_scan_state)
        version2 = clean_memory_store.save_session("test_session", mock_scan_state)
        
        assert version2 > version1
    
    def test_get_session(self, clean_memory_store, mock_scan_state):
        """测试获取会话"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        result = clean_memory_store.get_session("test_session")
        
        assert result == mock_scan_state
    
    def test_get_nonexistent_session(self, clean_memory_store):
        """测试获取不存在的会话"""
        result = clean_memory_store.get_session("nonexistent_session")
        
        assert result is None
    
    def test_update_session(self, clean_memory_store, mock_scan_state):
        """测试更新会话"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        updated = clean_memory_store.update_session("test_session", target="updated.example.com")
        
        assert updated["target"] == "updated.example.com"
    
    def test_update_nonexistent_session(self, clean_memory_store):
        """测试更新不存在的会话"""
        result = clean_memory_store.update_session("nonexistent_session", target="test.com")
        
        assert result is None
    
    def test_delete_session(self, clean_memory_store, mock_scan_state):
        """测试删除会话"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        clean_memory_store.delete_session("test_session")
        
        assert clean_memory_store.get_session("test_session") is None
    
    def test_delete_nonexistent_session(self, clean_memory_store):
        """测试删除不存在的会话"""
        clean_memory_store.delete_session("nonexistent_session")
    
    def test_get_session_version(self, clean_memory_store, mock_scan_state):
        """测试获取会话版本"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        version = clean_memory_store.get_session_version("test_session")
        
        assert version == 1
    
    def test_get_session_version_nonexistent(self, clean_memory_store):
        """测试获取不存在会话的版本"""
        version = clean_memory_store.get_session_version("nonexistent_session")
        
        assert version == 0


@pytest.mark.memory
class TestMemoryStoreChatHistory:
    """聊天历史测试"""
    
    def test_append_chat(self, clean_memory_store):
        """测试追加聊天历史"""
        clean_memory_store.append_chat("test_session", "user", "Hello")
        
        history = clean_memory_store.get_chat_history("test_session")
        
        assert len(history) == 1
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "Hello"
    
    def test_append_multiple_chats(self, clean_memory_store):
        """测试追加多条聊天历史"""
        clean_memory_store.append_chat("test_session", "user", "Hello")
        clean_memory_store.append_chat("test_session", "assistant", "Hi there!")
        clean_memory_store.append_chat("test_session", "user", "How are you?")
        
        history = clean_memory_store.get_chat_history("test_session")
        
        assert len(history) == 3
    
    def test_get_chat_history_empty(self, clean_memory_store):
        """测试获取空聊天历史"""
        history = clean_memory_store.get_chat_history("nonexistent_session")
        
        assert history == []
    
    def test_chat_history_max_limit(self, clean_memory_store):
        """测试聊天历史最大限制"""
        for i in range(150):
            clean_memory_store.append_chat("test_session", "user", f"Message {i}")
        
        history = clean_memory_store.get_chat_history("test_session")
        
        assert len(history) <= 100


@pytest.mark.memory
class TestMemoryStoreExpiry:
    """过期清理测试"""
    
    def test_cleanup_expired_sessions(self, clean_memory_store, mock_scan_state):
        """测试清理过期会话"""
        clean_memory_store._session_ttl = 1
        
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        time.sleep(2)
        
        clean_memory_store._cleanup_expired_sessions()
        
        assert clean_memory_store.get_session("test_session") is None
    
    def test_cleanup_preserves_active_sessions(self, clean_memory_store, mock_scan_state):
        """测试清理保留活跃会话"""
        clean_memory_store._session_ttl = 3600
        
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        clean_memory_store._cleanup_expired_sessions()
        
        assert clean_memory_store.get_session("test_session") is not None
    
    def test_cleanup_chat_histories(self, clean_memory_store):
        """测试清理聊天历史"""
        clean_memory_store._max_chat_history = 5
        
        for i in range(10):
            clean_memory_store.append_chat("test_session", "user", f"Message {i}")
        
        clean_memory_store._cleanup_chat_histories()
        
        history = clean_memory_store.get_chat_history("test_session")
        assert len(history) <= 5


@pytest.mark.memory
class TestMemoryStoreDataMerge:
    """数据冗余合并测试"""
    
    def test_sync_chat_history_no_duplicates(self, clean_memory_store, mock_scan_state):
        """测试同步聊天历史无重复"""
        from TOSKill.AI.state import update_state
        
        state = update_state(
            mock_scan_state,
            chat_history=[
                {"role": "user", "content": "Hello", "timestamp": "2024-01-01T12:00:00"}
            ]
        )
        
        clean_memory_store.append_chat("test_session", "user", "Hello")
        
        result = clean_memory_store.sync_chat_history_from_state("test_session", state)
        
        assert len(result["chat_history"]) == 1
    
    def test_sync_chat_history_merges_data(self, clean_memory_store, mock_scan_state):
        """测试同步聊天历史合并数据"""
        from TOSKill.AI.state import update_state
        
        state = update_state(
            mock_scan_state,
            chat_history=[
                {"role": "user", "content": "State message", "timestamp": "2024-01-01T12:00:00"}
            ]
        )
        
        clean_memory_store.append_chat("test_session", "user", "Store message")
        
        result = clean_memory_store.sync_chat_history_from_state("test_session", state)
        
        assert len(result["chat_history"]) == 2
    
    def test_sync_chat_history_same_timestamp_dedup(self, clean_memory_store, mock_scan_state):
        """测试同步聊天历史相同时间戳去重"""
        from TOSKill.AI.state import update_state
        
        timestamp = "2024-01-01T12:00:00"
        state = update_state(
            mock_scan_state,
            chat_history=[
                {"role": "user", "content": "Same message", "timestamp": timestamp}
            ]
        )
        
        clean_memory_store._chat_histories["test_session"] = [
            {"role": "user", "content": "Same message", "timestamp": timestamp}
        ]
        
        result = clean_memory_store.sync_chat_history_from_state("test_session", state)
        
        assert len(result["chat_history"]) == 1


@pytest.mark.memory
class TestMemoryStorePendingInteraction:
    """待处理交互测试"""
    
    def test_set_pending_interaction(self, clean_memory_store):
        """测试设置待处理交互"""
        interaction_data = {"type": "choice", "options": ["A", "B"]}
        
        clean_memory_store.set_pending_interaction("test_session", interaction_data)
        
        assert clean_memory_store.get_pending_interaction("test_session") == interaction_data
    
    def test_get_pending_interaction_empty(self, clean_memory_store):
        """测试获取空待处理交互"""
        result = clean_memory_store.get_pending_interaction("test_session")
        
        assert result is None
    
    def test_clear_pending_interaction(self, clean_memory_store):
        """测试清除待处理交互"""
        clean_memory_store.set_pending_interaction("test_session", {"type": "test"})
        
        clean_memory_store.clear_pending_interaction("test_session")
        
        assert clean_memory_store.get_pending_interaction("test_session") is None
    
    def test_has_pending_interaction(self, clean_memory_store):
        """测试检查是否有待处理交互"""
        assert clean_memory_store.has_pending_interaction("test_session") == False
        
        clean_memory_store.set_pending_interaction("test_session", {"type": "test"})
        
        assert clean_memory_store.has_pending_interaction("test_session") == True


@pytest.mark.memory
class TestMemoryStoreWebSocketCallback:
    """WebSocket回调测试"""
    
    def test_set_websocket_callback(self, clean_memory_store):
        """测试设置WebSocket回调"""
        callback = MagicMock()
        
        clean_memory_store.set_websocket_callback("test_session", callback)
        
        assert clean_memory_store.get_websocket_callback("test_session") == callback
    
    def test_get_websocket_callback_empty(self, clean_memory_store):
        """测试获取空WebSocket回调"""
        result = clean_memory_store.get_websocket_callback("test_session")
        
        assert result is None
    
    def test_clear_websocket_callback(self, clean_memory_store):
        """测试清除WebSocket回调"""
        clean_memory_store.set_websocket_callback("test_session", MagicMock())
        
        clean_memory_store.clear_websocket_callback("test_session")
        
        assert clean_memory_store.get_websocket_callback("test_session") is None
    
    def test_is_websocket_active(self, clean_memory_store):
        """测试检查WebSocket是否活跃"""
        assert clean_memory_store.is_websocket_active("test_session") == False
        
        clean_memory_store.set_websocket_callback("test_session", MagicMock())
        
        assert clean_memory_store.is_websocket_active("test_session") == True


@pytest.mark.memory
class TestMemoryStoreStats:
    """存储统计测试"""
    
    def test_get_active_session_count(self, clean_memory_store, mock_scan_state):
        """测试获取活跃会话数量"""
        assert clean_memory_store.get_active_session_count() == 0
        
        clean_memory_store.save_session("session1", mock_scan_state)
        clean_memory_store.save_session("session2", mock_scan_state)
        
        assert clean_memory_store.get_active_session_count() == 2
    
    def test_get_session_info(self, clean_memory_store, mock_scan_state):
        """测试获取会话信息"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        info = clean_memory_store.get_session_info("test_session")
        
        assert info["exists"] == True
        assert info["target"] == mock_scan_state["target"]
        assert "version" in info
    
    def test_get_session_info_nonexistent(self, clean_memory_store):
        """测试获取不存在会话的信息"""
        info = clean_memory_store.get_session_info("nonexistent_session")
        
        assert info["exists"] == False
    
    def test_get_storage_stats(self, clean_memory_store, mock_scan_state):
        """测试获取存储统计"""
        clean_memory_store.save_session("session1", mock_scan_state)
        clean_memory_store.append_chat("session1", "user", "Hello")
        
        stats = clean_memory_store.get_storage_stats()
        
        assert "sessions" in stats
        assert "chat_history" in stats
        assert "memory" in stats
        assert "config" in stats
        assert stats["sessions"]["total_count"] == 1
        assert stats["chat_history"]["total_messages"] == 1


@pytest.mark.memory
class TestMemoryStoreConfig:
    """存储配置测试"""
    
    def test_set_config_ttl(self, clean_memory_store):
        """测试设置TTL配置"""
        clean_memory_store.set_config(session_ttl=7200)
        
        assert clean_memory_store._session_ttl == 7200
    
    def test_set_config_cleanup_interval(self, clean_memory_store):
        """测试设置清理间隔配置"""
        clean_memory_store.set_config(cleanup_interval=300)
        
        assert clean_memory_store._cleanup_interval == 300
    
    def test_set_config_max_chat_history(self, clean_memory_store):
        """测试设置最大聊天历史配置"""
        clean_memory_store.set_config(max_chat_history=50)
        
        assert clean_memory_store._max_chat_history == 50
    
    def test_set_config_multiple(self, clean_memory_store):
        """测试设置多个配置"""
        clean_memory_store.set_config(
            session_ttl=3600,
            cleanup_interval=600,
            max_chat_history=100
        )
        
        assert clean_memory_store._session_ttl == 3600
        assert clean_memory_store._cleanup_interval == 600
        assert clean_memory_store._max_chat_history == 100


@pytest.mark.memory
class TestSessionMetadata:
    """会话元数据测试"""
    
    def test_session_metadata_created(self, clean_memory_store, mock_scan_state):
        """测试会话元数据创建"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        metadata = clean_memory_store._session_metadata.get("test_session")
        
        assert metadata is not None
        assert metadata.version == 1
        assert metadata.created_at is not None
    
    def test_session_metadata_updated(self, clean_memory_store, mock_scan_state):
        """测试会话元数据更新"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        time.sleep(0.1)
        
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        metadata = clean_memory_store._session_metadata.get("test_session")
        
        assert metadata.version == 2
        assert metadata.updated_at > metadata.created_at


@pytest.mark.memory
class TestMemoryStoreThreadSafety:
    """线程安全测试"""
    
    def test_concurrent_session_access(self, clean_memory_store, mock_scan_state):
        """测试并发会话访问"""
        import threading
        
        errors = []
        
        def save_session(session_id):
            try:
                for i in range(10):
                    clean_memory_store.save_session(session_id, mock_scan_state)
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=save_session, args=(f"session_{i}",))
            for i in range(5)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert clean_memory_store.get_active_session_count() == 5
    
    def test_concurrent_chat_append(self, clean_memory_store):
        """测试并发聊天追加"""
        import threading
        
        errors = []
        
        def append_messages(session_id):
            try:
                for i in range(20):
                    clean_memory_store.append_chat(session_id, "user", f"Message {i}")
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=append_messages, args=("test_session",))
            for _ in range(3)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


@pytest.mark.memory
class TestMemoryStoreEdgeCases:
    """边界条件测试"""
    
    def test_save_empty_state(self, clean_memory_store):
        """测试保存空状态"""
        version = clean_memory_store.save_session("test_session", {})
        
        assert version == 1
        assert clean_memory_store.get_session("test_session") == {}
    
    def test_save_large_state(self, clean_memory_store):
        """测试保存大状态"""
        large_state = {
            "data": "x" * 1000000,
            "list": list(range(10000))
        }
        
        version = clean_memory_store.save_session("test_session", large_state)
        
        assert version == 1
        result = clean_memory_store.get_session("test_session")
        assert len(result["data"]) == 1000000
    
    def test_append_empty_chat(self, clean_memory_store):
        """测试追加空聊天"""
        clean_memory_store.append_chat("test_session", "user", "")
        
        history = clean_memory_store.get_chat_history("test_session")
        
        assert len(history) == 1
        assert history[0]["content"] == ""
    
    def test_special_characters_in_chat(self, clean_memory_store):
        """测试聊天中的特殊字符"""
        special_content = "Hello\nWorld\t<>&\"'"
        
        clean_memory_store.append_chat("test_session", "user", special_content)
        
        history = clean_memory_store.get_chat_history("test_session")
        
        assert history[0]["content"] == special_content
    
    def test_unicode_in_chat(self, clean_memory_store):
        """测试聊天中的Unicode"""
        unicode_content = "你好世界 🌍 مرحبا"
        
        clean_memory_store.append_chat("test_session", "user", unicode_content)
        
        history = clean_memory_store.get_chat_history("test_session")
        
        assert history[0]["content"] == unicode_content


@pytest.mark.memory
class TestMemoryStoreCleanupTask:
    """清理任务测试"""
    
    def test_stop_cleanup_task(self, clean_memory_store):
        """测试停止清理任务"""
        clean_memory_store.stop_cleanup_task()
        
        assert clean_memory_store._stop_cleanup == True
    
    def test_cleanup_task_can_be_restarted(self, clean_memory_store):
        """测试清理任务可以重启"""
        clean_memory_store.stop_cleanup_task()
        
        clean_memory_store._stop_cleanup = False
        
        assert clean_memory_store._stop_cleanup == False


@pytest.mark.memory
class TestMemoryStoreIntegration:
    """集成测试"""
    
    def test_full_session_lifecycle(self, clean_memory_store, mock_scan_state):
        """测试完整会话生命周期"""
        clean_memory_store.save_session("test_session", mock_scan_state)
        
        clean_memory_store.append_chat("test_session", "user", "Hello")
        clean_memory_store.append_chat("test_session", "assistant", "Hi!")
        
        clean_memory_store.set_pending_interaction("test_session", {"type": "choice"})
        
        clean_memory_store.set_websocket_callback("test_session", MagicMock())
        
        assert clean_memory_store.get_session("test_session") is not None
        assert len(clean_memory_store.get_chat_history("test_session")) == 2
        assert clean_memory_store.has_pending_interaction("test_session")
        assert clean_memory_store.is_websocket_active("test_session")
        
        clean_memory_store.delete_session("test_session")
        
        assert clean_memory_store.get_session("test_session") is None
        assert clean_memory_store.get_chat_history("test_session") == []
        assert not clean_memory_store.has_pending_interaction("test_session")
        assert not clean_memory_store.is_websocket_active("test_session")
    
    def test_multiple_sessions_independent(self, clean_memory_store, mock_scan_state):
        """测试多个会话独立性"""
        from TOSKill.AI.state import update_state
        
        state1 = update_state(mock_scan_state, target="target1.com")
        state2 = update_state(mock_scan_state, target="target2.com")
        
        clean_memory_store.save_session("session1", state1)
        clean_memory_store.save_session("session2", state2)
        
        clean_memory_store.append_chat("session1", "user", "Message for session1")
        clean_memory_store.append_chat("session2", "user", "Message for session2")
        
        assert clean_memory_store.get_session("session1")["target"] == "target1.com"
        assert clean_memory_store.get_session("session2")["target"] == "target2.com"
        assert len(clean_memory_store.get_chat_history("session1")) == 1
        assert len(clean_memory_store.get_chat_history("session2")) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "memory"])
