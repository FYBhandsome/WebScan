import json
import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class HistoryManager:
    def __init__(self, history_file: str = "global_history.json"):
        self.history_file = history_file
        self._ensure_history_directory()
        logger.info(f"HistoryManager initialized with file: {self.history_file}")

    def _ensure_history_directory(self):
        history_dir = os.path.dirname(self.history_file)
        if history_dir and not os.path.exists(history_dir):
            os.makedirs(history_dir, exist_ok=True)
            logger.debug(f"Created history directory: {history_dir}")

    def _create_empty_history(self) -> Dict[str, Any]:
        return {
            "chat_history": [],
            "task_history": [],
            "chat_summary": "",
            "user_chat_rules": "",
            "task_result": {}
        }

    def save_history_to_file(self, history_data: dict) -> bool:
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, ensure_ascii=False, indent=2)
            logger.debug(f"History saved to {self.history_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save history to file: {e}")
            return False

    def load_history_from_file(self) -> dict:
        try:
            if not os.path.exists(self.history_file):
                logger.info(f"History file not found: {self.history_file}, returning empty history")
                return self._create_empty_history()
            
            with open(self.history_file, 'r', encoding='utf-8') as f:
                history_data = json.load(f)
            
            for key in ["chat_history", "task_history"]:
                if key not in history_data:
                    history_data[key] = []
            
            for key in ["chat_summary", "user_chat_rules"]:
                if key not in history_data:
                    history_data[key] = ""
            
            if "task_result" not in history_data:
                history_data["task_result"] = {}
            
            logger.debug(f"History loaded from {self.history_file}")
            return history_data
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse history file: {e}")
            return self._create_empty_history()
        except Exception as e:
            logger.error(f"Failed to load history from file: {e}")
            return self._create_empty_history()

    def add_chat_message(self, role: str, content: str, history_data: dict) -> dict:
        if "chat_history" not in history_data:
            history_data["chat_history"] = []
        
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        }
        
        history_data["chat_history"].append(message)
        logger.debug(f"Added chat message: role={role}")
        
        self.save_history_to_file(history_data)
        
        return history_data

    def add_task_record(self, task_name: str, result: dict, history_data: dict) -> dict:
        if "task_history" not in history_data:
            history_data["task_history"] = []
        
        task_record = {
            "task_name": task_name,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
        
        history_data["task_history"].append(task_record)
        logger.debug(f"Added task record: {task_name}")
        
        if "task_result" not in history_data:
            history_data["task_result"] = {}
        history_data["task_result"][task_name] = result
        
        self.save_history_to_file(history_data)
        
        return history_data

    def get_full_history(self, history_data: dict) -> dict:
        full_history = {
            "chat_history": history_data.get("chat_history", []),
            "task_history": history_data.get("task_history", []),
            "chat_summary": history_data.get("chat_summary", ""),
            "user_chat_rules": history_data.get("user_chat_rules", ""),
            "task_result": history_data.get("task_result", {})
        }
        
        logger.debug("Retrieved full history")
        return full_history

    def update_chat_summary(self, summary: str, history_data: dict) -> dict:
        history_data["chat_summary"] = summary
        logger.debug("Updated chat summary")
        self.save_history_to_file(history_data)
        return history_data

    def update_user_rules(self, rules: str, history_data: dict) -> dict:
        history_data["user_chat_rules"] = rules
        logger.debug("Updated user chat rules")
        self.save_history_to_file(history_data)
        return history_data

    def clear_history(self, history_data: dict) -> dict:
        cleared_history = self._create_empty_history()
        self.save_history_to_file(cleared_history)
        logger.info("History cleared")
        return cleared_history

    def get_chat_history_only(self, history_data: dict) -> List[Dict[str, str]]:
        return history_data.get("chat_history", [])

    def get_task_history_only(self, history_data: dict) -> List[Dict[str, Any]]:
        return history_data.get("task_history", [])
