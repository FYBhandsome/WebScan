"""
POC 脚本管理器

负责 POC 脚本的管理，包括从 Seebug 同步、本地加载、版本控制等。
使用 Seebug_Agent 的 SeebugClient 和 SeebugAgent 实现。

模块功能:
1. POC 生命周期管理
   - 从 Seebug 同步 POC
   - 本地自定义 POC 脚本加载
   - POC 版本控制
   - POC 缓存管理

2. POC 元数据管理
   - POCMetadata: POC 元数据类
   - POCVersion: 版本信息
   - POCDependency: 依赖信息

3. 多来源支持
   - Seebug 在线 POC
   - 本地 POC 文件
   - Pocsuite3 内置 POC
   - 动态生成的 POC

简化说明（重构变更）:
- 移除了重复的 seebug_client 和 seebug_agent 实例
- 统一使用 seebug_utils 访问 Seebug_Agent 功能
- 合并了 sync_from_seebug 和 search_seebug_pocs 的重复逻辑
- 优化了缓存管理机制，减少重复代码
- 使用 _search_seebug_pocs_internal 统一处理搜索逻辑

使用示例:
    from backend.ai_agents.poc_system.poc_manager import poc_manager
    
    # 从 Seebug 同步 POC
    pocs = await poc_manager.sync_from_seebug("nginx", limit=10)
    
    # 获取 POC 代码
    poc_code = await poc_manager.get_poc_code("seebug_12345")
    
    # 搜索本地 POC
    results = poc_manager.search_pocs("wordpress")
    
    # 获取 POC 统计信息
    stats = poc_manager.get_poc_statistics()
    
    # 创建验证任务
    task = await poc_manager.create_verification_task(
        poc_id="seebug_12345",
        target="http://example.com"
    )

配置要求:
    需要在 backend/config.py 或 .env 中配置:
    - SEEBUG_API_KEY: Seebug API 密钥
    - POC_CACHE_TTL: POC 缓存过期时间（秒）
"""

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.Pocsuite3Agent.agent import get_pocsuite3_agent
from backend.ai_agents.utils.cache import CacheManager
from backend.config import settings
from backend.models import POCVerificationTask
from backend.ai_agents.poc_system.utils import validate_poc_script_code
from backend.utils.seebug_utils import seebug_utils

logger = logging.getLogger(__name__)


class POCSource(Enum):
    """
    POC 来源枚举
    
    定义 POC 脚本的来源类型:
    - SEEBUG: 从 Seebug 平台获取
    - LOCAL: 本地文件系统
    - POCSUITE3: Pocsuite3 内置
    - GENERATED: 动态生成
    - SEEBUG_AI: Seebug AI 生成
    """
    SEEBUG = "seebug"
    LOCAL = "local"
    POCSUITE3 = "pocsuite3"
    GENERATED = "generated"
    SEEBUG_AI = "seebug_ai"


@dataclass
class POCVersion:
    """
    POC 版本信息
    
    记录 POC 的版本详情，用于版本控制和兼容性检查。
    
    属性:
        version: 版本号（如 "1.0", "2.1"）
        release_date: 发布日期
        changelog: 变更日志
        compatible: 是否与当前系统兼容
    
    使用示例:
        version = POCVersion(
            version="2.0",
            release_date=datetime.now(),
            changelog="修复了超时问题",
            compatible=True
        )
    """
    version: str
    release_date: Optional[datetime] = None
    changelog: Optional[str] = None
    compatible: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式.

        Returns:
            Dict[str, Any]: 版本信息字典.
        """
        return {
            "version": self.version,
            "release_date": self.release_date.isoformat() if self.release_date else None,
            "changelog": self.changelog,
            "compatible": self.compatible,
        }


@dataclass
class POCDependency:
    """
    POC 依赖信息
    
    记录 POC 脚本的外部依赖，用于环境检查和依赖管理。
    
    属性:
        name: 依赖名称（如 "requests", "beautifulsoup4"）
        version: 依赖版本要求
        required: 是否为必需依赖
        description: 依赖描述
    
    使用示例:
        dep = POCDependency(
            name="requests",
            version=">=2.28.0",
            required=True,
            description="HTTP 请求库"
        )
    """
    name: str
    version: Optional[str] = None
    required: bool = True
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式.

        Returns:
            Dict[str, Any]: 依赖信息字典.
        """
        return {
            "name": self.name,
            "version": self.version,
            "required": self.required,
            "description": self.description,
        }


class POCMetadata:
    """POC 元数据类.

    用于存储 POC 的元信息,包括名称、类型、严重度等。

    Attributes:
        poc_name: POC 名称.
        poc_id: POC 唯一标识.
        poc_type: POC 类型.
        severity: 严重程度.
        cvss_score: CVSS 评分.
        description: POC 描述.
        author: 作者.
        source: 来源.
        version: 版本号.
        tags: 标签列表.
        dependencies: 依赖列表.
        min_pocsuite_version: 最低 Pocsuite 版本.
        created_at: 创建时间.
        updated_at: 更新时间.
    """

    def __init__(
        self,
        poc_name: str,
        poc_id: str,
        poc_type: str = "web",
        severity: str = "medium",
        cvss_score: Optional[float] = None,
        description: Optional[str] = None,
        author: Optional[str] = None,
        source: str = "seebug",
        version: str = "1.0",
        tags: Optional[List[str]] = None,
        dependencies: Optional[List[POCDependency]] = None,
        min_pocsuite_version: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ) -> None:
        self.poc_name = poc_name
        self.poc_id = poc_id
        self.poc_type = poc_type
        self.severity = severity
        self.cvss_score = cvss_score
        self.description = description
        self.author = author
        self.source = source
        self.version = version
        self.tags = tags or []
        self.dependencies = dependencies or []
        self.min_pocsuite_version = min_pocsuite_version
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式.

        Returns:
            Dict[str, Any]: 元数据字典.
        """
        return {
            "poc_name": self.poc_name,
            "poc_id": self.poc_id,
            "poc_type": self.poc_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "author": self.author,
            "source": self.source,
            "version": self.version,
            "tags": self.tags,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "min_pocsuite_version": self.min_pocsuite_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def update_version(self, new_version: str, changelog: Optional[str] = None) -> None:
        """更新 POC 版本.

        Args:
            new_version: 新版本号.
            changelog: 变更日志.
        """
        self.version = new_version
        self.updated_at = datetime.now()
        if changelog:
            logger.debug(f"POC {self.poc_id} 更新到版本 {new_version}: {changelog}")


class POCManagerError(Exception):
    """
    POC 管理器基础异常
    
    所有 POC 管理相关异常的基类。
    """
    pass


class POCNotFoundError(POCManagerError):
    """
    POC 未找到异常
    
    当请求的 POC 不存在时抛出。
    """
    pass


class POCVersionIncompatibleError(POCManagerError):
    """
    POC 版本不兼容异常
    
    当 POC 版本与当前系统不兼容时抛出。
    """
    pass


class POCSyncError(POCManagerError):
    """
    POC 同步异常
    
    当从远程源同步 POC 失败时抛出。
    """
    pass


class POCValidationError(POCManagerError):
    """
    POC 验证异常
    
    当 POC 脚本验证失败时抛出。
    """
    pass


class POCManager:
    """POC 管理器类.

    负责管理 POC 脚本的生命周期,包括:
    - 从 Seebug 同步 POC
    - 本地自定义 POC 脚本加载
    - POC 版本控制
    - POC 缓存管理
    - POC 元数据管理

    简化说明:
    - 移除了重复的 seebug_client 和 seebug_agent 实例
    - 统一使用 seebug_utils 访问 Seebug_Agent 功能
    - 合并了 sync_from_seebug 和 search_seebug_pocs 的重复逻辑
    - 优化了缓存管理机制

    Attributes:
        CURRENT_POCSUITE_VERSION: 当前 Pocsuite 版本.
        SUPPORTED_POC_VERSIONS: 支持的 POC 版本列表.
        poc_registry: POC 注册表.
        generated_poc_codes: 生成的 POC 代码缓存.
        poc_cache: POC 缓存管理器.
    """

    CURRENT_POCSUITE_VERSION = "1.9.0"
    SUPPORTED_POC_VERSIONS = ["1.0", "1.1", "1.2", "2.0"]

    def __init__(self) -> None:
        self.poc_registry: Dict[str, POCMetadata] = {}
        self.generated_poc_codes: Dict[str, str] = {}
        self.poc_cache = CacheManager(ttl=settings.POC_CACHE_TTL)
        self._lock = threading.RLock()

        self.pocsuite3_agent = get_pocsuite3_agent()

        self._init_error_recovery()

        logger.info("✅ POC 管理器初始化完成")

    def _init_error_recovery(self) -> None:
        """初始化错误恢复机制."""
        self._retry_count = 3
        self._retry_delay = 1.0
        self._last_sync_time: Optional[datetime] = None
        self._sync_errors: List[Dict[str, Any]] = []

    def _log_operation(self, operation: str, details: Optional[Dict[str, Any]] = None) -> None:
        """记录操作日志.

        Args:
            operation: 操作名称.
            details: 操作详情.
        """
        log_msg = f"[POCManager] {operation}"
        if details:
            log_msg += f" - {details}"
        logger.debug(log_msg)

    def _handle_error(
        self,
        operation: str,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        raise_error: bool = False,
    ) -> Dict[str, Any]:
        """处理错误.

        Args:
            operation: 操作名称.
            error: 异常对象.
            context: 上下文信息.
            raise_error: 是否抛出异常.

        Returns:
            Dict[str, Any]: 错误信息字典.
        """
        error_info = {
            "operation": operation,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context,
            "timestamp": datetime.now().isoformat(),
        }

        self._sync_errors.append(error_info)
        if len(self._sync_errors) > 100:
            self._sync_errors = self._sync_errors[-50:]

        logger.error(f"❌ [{operation}] 错误: {str(error)}", exc_info=True)

        if raise_error:
            raise POCManagerError(f"{operation} 失败: {str(error)}") from error

        return {"success": False, "error": error_info}

    def register_dynamic_poc(self, poc_id: str, code: str) -> Dict[str, Any]:
        """注册动态 POC.

        Args:
            poc_id: POC 唯一标识.
            code: POC 代码.

        Returns:
            Dict[str, Any]: 注册结果.
        """
        try:
            self._log_operation("register_dynamic_poc", {"poc_id": poc_id})

            with self._lock:
                self.generated_poc_codes[poc_id] = code
                self.poc_registry[poc_id] = POCMetadata(
                    poc_name="Dynamic POC",
                    poc_id=poc_id,
                    source=POCSource.GENERATED.value,
                    description="Dynamically generated POC",
                )

            logger.info(f"✅ 动态 POC 注册成功: {poc_id}")
            return {"success": True, "poc_id": poc_id}

        except Exception as e:
            return self._handle_error("register_dynamic_poc", e, {"poc_id": poc_id})

    async def get_poc_code(self, poc_id: str) -> Optional[str]:
        """获取 POC 代码.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Optional[str]: POC 代码,不存在返回 None.
        """
        try:
            self._log_operation("get_poc_code", {"poc_id": poc_id})

            if poc_id in self.generated_poc_codes:
                logger.debug(f"从生成缓存获取 POC: {poc_id}")
                return self.generated_poc_codes[poc_id]

            cache_key = f"poc_code_{poc_id}"
            cached_code = self.poc_cache.get(cache_key)
            if cached_code:
                logger.debug(f"从缓存获取 POC: {poc_id}")
                return cached_code

            if poc_id.startswith("local_"):
                return await self._get_local_poc_code(poc_id)
            elif poc_id.startswith("pocsuite3_"):
                return await self._get_pocsuite3_poc_code(poc_id)
            elif poc_id.startswith("seebug_"):
                return await self._get_seebug_poc_code(poc_id)
            else:
                return await self._get_seebug_poc_code(poc_id)

        except Exception as e:
            self._handle_error("get_poc_code", e, {"poc_id": poc_id})
            return None

    async def _get_local_poc_code(self, poc_id: str) -> Optional[str]:
        """获取本地 POC 代码.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Optional[str]: POC 代码.
        """
        try:
            poc_name = poc_id.replace("local_", "")
            base_dir = Path(__file__).parent.parent.parent
            local_path = base_dir / "poc" / f"{poc_name}.py"

            if not local_path.exists():
                logger.warning(f"本地 POC 文件不存在: {local_path}")
                return None

            with open(local_path, "r", encoding="utf-8") as f:
                poc_code = f.read()

            self.poc_cache.set(f"poc_code_{poc_id}", poc_code)
            logger.debug(f"加载本地 POC 成功: {poc_id}")
            return poc_code

        except Exception as e:
            self._handle_error("_get_local_poc_code", e, {"poc_id": poc_id})
            return None

    async def _get_pocsuite3_poc_code(self, poc_id: str) -> Optional[str]:
        """获取 Pocsuite3 POC 代码.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Optional[str]: POC 代码.
        """
        try:
            poc_name = poc_id.replace("pocsuite3_", "")
            poc_path = self.pocsuite3_agent.poc_registry.get(poc_name)

            if not poc_path:
                logger.warning(f"Pocsuite3 POC 未注册: {poc_name}")
                return None

            if not Path(poc_path).exists():
                logger.warning(f"Pocsuite3 POC 文件不存在: {poc_path}")
                return None

            with open(poc_path, "r", encoding="utf-8") as f:
                poc_code = f.read()

            self.poc_cache.set(f"poc_code_{poc_id}", poc_code)
            logger.debug(f"加载 Pocsuite3 POC 成功: {poc_id}")
            return poc_code

        except Exception as e:
            self._handle_error("_get_pocsuite3_poc_code", e, {"poc_id": poc_id})
            return None

    async def _get_seebug_poc_code(self, poc_id: str) -> Optional[str]:
        """获取 Seebug POC 代码.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Optional[str]: POC 代码.
        """
        try:
            ssvid = poc_id.replace("seebug_", "")
            return await self.download_poc_from_seebug(int(ssvid))
        except (ValueError, TypeError) as e:
            self._handle_error("_get_seebug_poc_code", e, {"poc_id": poc_id})
            return None

    async def _search_seebug_pocs_internal(
        self,
        keyword: str = "",
        page: int = 1,
        page_size: int = 10,
        force_refresh: bool = False,
        cache_key_prefix: str = "search",
        add_seebug_prefix: bool = False,
    ) -> List[POCMetadata]:
        """内部方法: 搜索 Seebug POC.

        统一处理 sync_from_seebug 和 search_seebug_pocs 的搜索逻辑,
        避免代码重复。直接使用 seebug_utils.search_poc 方法。

        Args:
            keyword: 搜索关键词.
            page: 页码.
            page_size: 每页数量.
            force_refresh: 是否强制刷新缓存.
            cache_key_prefix: 缓存键前缀.
            add_seebug_prefix: 是否在 poc_id 前添加 "seebug_" 前缀.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            self._log_operation("_search_seebug_pocs_internal", {"keyword": keyword, "page": page})

            cache_key = f"{cache_key_prefix}_{keyword}_{page}_{page_size}"

            if not force_refresh:
                cached_result = self.poc_cache.get(cache_key)
                if cached_result:
                    age = self.poc_cache.get_age(cache_key)
                    logger.debug(f"使用缓存的搜索结果,缓存年龄: {age:.2f}秒")
                    return cached_result

            response = await seebug_utils.search_poc(keyword, page, page_size)

            if not response.success:
                logger.warning(f"⚠️ Seebug 搜索失败: {response.message}")
                return []

            poc_list = response.data.get("list", []) if response.data else []

            if not poc_list:
                logger.info(f"📭 未找到匹配的 POC,关键词: {keyword}")
                return []

            poc_metadata_list = []
            with self._lock:
                for poc_item in poc_list:
                    ssvid = poc_item.get("ssvid", "")
                    poc_id = f"seebug_{ssvid}" if add_seebug_prefix else str(ssvid)

                    metadata = POCMetadata(
                        poc_name=poc_item.get("name", ""),
                        poc_id=poc_id,
                        poc_type=poc_item.get("type", "web"),
                        severity=poc_item.get("severity", "medium"),
                        cvss_score=poc_item.get("cvss_score"),
                        description=poc_item.get("description"),
                        author=poc_item.get("author"),
                        source=POCSource.SEEBUG.value,
                        version="1.0",
                        tags=poc_item.get("tags", []),
                    )
                    poc_metadata_list.append(metadata)
                    self.poc_registry[metadata.poc_id] = metadata

            self.poc_cache.set(cache_key, poc_metadata_list)

            if cache_key_prefix == "sync":
                self._last_sync_time = datetime.now()

            logger.info(f"✅ Seebug POC搜索成功,找到 {len(poc_metadata_list)} 个POC")
            return poc_metadata_list

        except Exception as e:
            self._handle_error("_search_seebug_pocs_internal", e, {"keyword": keyword})
            return []

    async def sync_from_seebug(
        self,
        keyword: str = "",
        limit: int = 100,
        force_refresh: bool = False,
    ) -> List[POCMetadata]:
        """从 Seebug 同步 POC.

        简化说明: 统一使用 _search_seebug_pocs_internal 方法处理搜索逻辑,
        避免与 search_seebug_pocs 方法的重复代码。

        Args:
            keyword: 搜索关键词.
            limit: 返回数量限制.
            force_refresh: 是否强制刷新缓存.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        return await self._search_seebug_pocs_internal(
            keyword=keyword,
            page=1,
            page_size=limit,
            force_refresh=force_refresh,
            cache_key_prefix="sync"
        )

    async def download_poc_from_seebug(self, ssvid: int) -> Optional[str]:
        """从 Seebug 下载 POC.

        简化说明: 直接使用 seebug_utils.download_poc 方法,
        避免重复实现下载逻辑。seebug_utils 内部已包含缓存机制。

        Args:
            ssvid: Seebug 漏洞 ID.

        Returns:
            Optional[str]: POC 代码.
        """
        try:
            self._log_operation("download_poc_from_seebug", {"ssvid": ssvid})

            cache_key = f"poc_code_{ssvid}"
            cached_code = self.poc_cache.get(cache_key)
            if cached_code:
                logger.debug(f"使用本地缓存的 POC 代码: {ssvid}")
                return cached_code

            response = await seebug_utils.download_poc(ssvid)

            if not response.success:
                logger.warning(f"⚠️ 从 Seebug 下载 POC 失败,SSVID: {ssvid}, 原因: {response.message}")
                return None

            poc_code = response.data.get("code", "") if response.data else ""

            if not poc_code:
                logger.warning(f"⚠️ POC 代码为空,SSVID: {ssvid}")
                return None

            self.poc_cache.set(cache_key, poc_code)

            logger.info(f"✅ 从 Seebug 下载 POC 完成,SSVID: {ssvid}, 代码长度: {len(poc_code)}")
            return poc_code

        except Exception as e:
            self._handle_error("download_poc_from_seebug", e, {"ssvid": ssvid})
            return None

    async def save_poc_to_local(
        self,
        ssvid: int,
        poc_code: str,
        category: str = "seebug",
        cve_id: Optional[str] = None,
        vuln_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """将 POC 保存到本地目录.

        Args:
            ssvid: Seebug 漏洞 ID.
            poc_code: POC 代码.
            category: POC 分类目录.
            cve_id: CVE 编号.
            vuln_name: 漏洞名称.

        Returns:
            Dict[str, Any]: 保存结果.
        """
        try:
            self._log_operation("save_poc_to_local", {"ssvid": ssvid, "category": category})

            base_dir = Path(__file__).parent.parent.parent
            poc_dir = base_dir / "poc" / category
            
            poc_dir.mkdir(parents=True, exist_ok=True)

            if cve_id:
                filename = f"{cve_id}_poc.py"
            elif vuln_name:
                safe_name = re.sub(r'[^\w\-]', '_', vuln_name)[:50]
                filename = f"{safe_name}_ssvid_{ssvid}.py"
            else:
                filename = f"ssvid_{ssvid}_poc.py"

            file_path = poc_dir / filename

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(poc_code)

            poc_id = f"seebug_{ssvid}"
            metadata = POCMetadata(
                poc_name=vuln_name or f"Seebug POC {ssvid}",
                poc_id=poc_id,
                poc_type="web",
                severity="high",
                description=f"从 Seebug 下载的 POC (SSVID: {ssvid})",
                source=POCSource.SEEBUG.value,
                version="1.0",
                tags=["seebug", "downloaded"],
            )

            with self._lock:
                self.poc_registry[poc_id] = metadata
                self.generated_poc_codes[poc_id] = poc_code

            self.poc_cache.set(f"poc_code_{poc_id}", poc_code)

            logger.info(f"✅ POC 保存成功: {file_path}")
            return {
                "success": True,
                "file_path": str(file_path),
                "poc_id": poc_id,
                "message": f"POC 已保存到 {file_path}"
            }

        except Exception as e:
            return self._handle_error("save_poc_to_local", e, {"ssvid": ssvid})


    async def load_local_poc(self, poc_path: str) -> Optional[POCMetadata]:
        """加载本地 POC.

        Args:
            poc_path: POC 文件路径.

        Returns:
            Optional[POCMetadata]: POC 元数据.
        """
        try:
            self._log_operation("load_local_poc", {"poc_path": poc_path})

            path = Path(poc_path)
            if not path.exists():
                logger.warning(f"⚠️ POC 文件不存在: {poc_path}")
                return None

            if not path.is_file():
                logger.warning(f"⚠️ 路径不是文件: {poc_path}")
                return None

            with open(path, "r", encoding="utf-8") as f:
                poc_code = f.read()

            poc_name = path.stem
            poc_id = f"local_{poc_name}"

            dependencies = self._extract_dependencies(poc_code)
            min_version = self._extract_min_version(poc_code)

            metadata = POCMetadata(
                poc_name=poc_name,
                poc_id=poc_id,
                poc_type="local",
                severity="medium",
                description=f"本地自定义 POC: {poc_name}",
                source=POCSource.LOCAL.value,
                version="1.0",
                tags=["custom"],
                dependencies=dependencies,
                min_pocsuite_version=min_version,
            )

            with self._lock:
                self.poc_registry[metadata.poc_id] = metadata

            self.poc_cache.set(f"poc_code_{poc_id}", poc_code)

            logger.info(f"✅ 加载本地 POC 完成: {poc_name}")
            return metadata

        except Exception as e:
            self._handle_error("load_local_poc", e, {"poc_path": poc_path})
            return None

    def _extract_dependencies(self, poc_code: str) -> List[POCDependency]:
        """从 POC 代码中提取依赖.

        Args:
            poc_code: POC 代码.

        Returns:
            List[POCDependency]: 依赖列表.
        """
        dependencies = []

        import_pattern = r"^(?:from\s+(\S+)|import\s+(\S+))"
        for match in re.finditer(import_pattern, poc_code, re.MULTILINE):
            module = match.group(1) or match.group(2)
            if module and not module.startswith("."):
                module = module.split(".")[0]
                dependencies.append(
                    POCDependency(
                        name=module,
                        required=True,
                        description=f"Python 模块: {module}",
                    )
                )

        return dependencies

    def _extract_min_version(self, poc_code: str) -> Optional[str]:
        """从 POC 代码中提取最低版本要求.

        Args:
            poc_code: POC 代码.

        Returns:
            Optional[str]: 最低版本号.
        """
        version_pattern = r"min_version\s*[:=]\s*[\"']?([\d.]+)[\"']?"
        match = re.search(version_pattern, poc_code)
        if match:
            return match.group(1)
        return None

    async def load_local_pocs_from_directory(
        self,
        directory: Optional[str] = None,
        pattern: str = "*.py",
    ) -> List[POCMetadata]:
        """从目录加载本地 POC.

        Args:
            directory: 目录路径.
            pattern: 文件匹配模式.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            if not directory:
                base_dir = Path(__file__).parent.parent.parent
                directory = str(base_dir / "poc")

            self._log_operation("load_local_pocs_from_directory", {"directory": directory, "pattern": pattern})

            dir_path = Path(directory)
            if not dir_path.exists():
                logger.warning(f"⚠️ 目录不存在: {directory}")
                return []

            if not dir_path.is_dir():
                logger.warning(f"⚠️ 路径不是目录: {directory}")
                return []

            poc_metadata_list = []

            for poc_file in dir_path.glob(pattern):
                if poc_file.name.startswith("__"):
                    continue
                metadata = await self.load_local_poc(str(poc_file))
                if metadata:
                    poc_metadata_list.append(metadata)

            for subdir in dir_path.iterdir():
                if subdir.is_dir() and not subdir.name.startswith(".") and subdir.name not in ["__pycache__"]:
                    for poc_file in subdir.glob(pattern):
                        if poc_file.name.startswith("__"):
                            continue
                        metadata = await self.load_local_poc(str(poc_file))
                        if metadata:
                            poc_metadata_list.append(metadata)

            logger.info(f"✅ 从目录加载 POC 完成,获取 {len(poc_metadata_list)} 个 POC")
            return poc_metadata_list

        except Exception as e:
            self._handle_error("load_local_pocs_from_directory", e, {"directory": directory})
            return []

    def get_poc_metadata(self, poc_id: str) -> Optional[POCMetadata]:
        """获取 POC 元数据.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Optional[POCMetadata]: POC 元数据.
        """
        try:
            with self._lock:
                return self.poc_registry.get(poc_id)
        except Exception as e:
            self._handle_error("get_poc_metadata", e, {"poc_id": poc_id})
            return None

    def get_all_pocs(self) -> List[POCMetadata]:
        """获取所有 POC.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            with self._lock:
                return list(self.poc_registry.values())
        except Exception as e:
            self._handle_error("get_all_pocs", e)
            return []

    def get_pocs_by_type(self, poc_type: str) -> List[POCMetadata]:
        """按类型获取 POC.

        Args:
            poc_type: POC 类型.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            with self._lock:
                return [poc for poc in self.poc_registry.values() if poc.poc_type == poc_type]
        except Exception as e:
            self._handle_error("get_pocs_by_type", e, {"poc_type": poc_type})
            return []

    def get_pocs_by_severity(self, severity: str) -> List[POCMetadata]:
        """按严重程度获取 POC.

        Args:
            severity: 严重程度.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            with self._lock:
                return [poc for poc in self.poc_registry.values() if poc.severity == severity]
        except Exception as e:
            self._handle_error("get_pocs_by_severity", e, {"severity": severity})
            return []

    def get_pocs_by_source(self, source: str) -> List[POCMetadata]:
        """按来源获取 POC.

        Args:
            source: POC 来源.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            with self._lock:
                return [poc for poc in self.poc_registry.values() if poc.source == source]
        except Exception as e:
            self._handle_error("get_pocs_by_source", e, {"source": source})
            return []

    def get_pocs_by_tags(self, tags: List[str], match_all: bool = False) -> List[POCMetadata]:
        """按标签获取 POC.

        Args:
            tags: 标签列表.
            match_all: 是否匹配所有标签.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            with self._lock:
                result = []
                for poc in self.poc_registry.values():
                    if match_all:
                        if all(tag in poc.tags for tag in tags):
                            result.append(poc)
                    else:
                        if any(tag in poc.tags for tag in tags):
                            result.append(poc)
                return result
        except Exception as e:
            self._handle_error("get_pocs_by_tags", e, {"tags": tags})
            return []

    def get_poc_statistics(self) -> Dict[str, Any]:
        """获取 POC 统计信息.

        Returns:
            Dict[str, Any]: 统计信息字典.
        """
        try:
            with self._lock:
                total_count = len(self.poc_registry)

                by_type: Dict[str, int] = {}
                by_severity: Dict[str, int] = {}
                by_source: Dict[str, int] = {}

                for poc in self.poc_registry.values():
                    by_type[poc.poc_type] = by_type.get(poc.poc_type, 0) + 1
                    by_severity[poc.severity] = by_severity.get(poc.severity, 0) + 1
                    by_source[poc.source] = by_source.get(poc.source, 0) + 1

                cache_stats = self.poc_cache.get_stats()

                return {
                    "total_count": total_count,
                    "by_type": by_type,
                    "by_severity": by_severity,
                    "by_source": by_source,
                    "cache_stats": cache_stats,
                    "last_sync_time": self._last_sync_time.isoformat() if self._last_sync_time else None,
                    "generated_pocs_count": len(self.generated_poc_codes),
                }
        except Exception as e:
            self._handle_error("get_poc_statistics", e)
            return {"total_count": 0, "error": str(e)}

    def search_pocs(self, keyword: str) -> List[POCMetadata]:
        """搜索 POC.

        Args:
            keyword: 搜索关键词.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            self._log_operation("search_pocs", {"keyword": keyword})

            keyword_lower = keyword.lower()
            results = []

            with self._lock:
                for poc in self.poc_registry.values():
                    if (
                        keyword_lower in poc.poc_name.lower()
                        or keyword_lower in (poc.description or "").lower()
                        or keyword_lower in poc.poc_id.lower()
                        or any(keyword_lower in tag.lower() for tag in poc.tags)
                    ):
                        results.append(poc)

            logger.debug(f"搜索 POC 关键词 '{keyword}' 找到 {len(results)} 个结果")
            return results

        except Exception as e:
            self._handle_error("search_pocs", e, {"keyword": keyword})
            return []

    def get_poc_dependencies(self, poc_id: str) -> List[POCDependency]:
        """获取 POC 依赖.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            List[POCDependency]: 依赖列表.
        """
        try:
            metadata = self.get_poc_metadata(poc_id)
            if not metadata:
                logger.warning(f"POC 不存在: {poc_id}")
                return []

            return metadata.dependencies

        except Exception as e:
            self._handle_error("get_poc_dependencies", e, {"poc_id": poc_id})
            return []

    def check_poc_version_compatibility(self, poc_id: str) -> Dict[str, Any]:
        """检查 POC 版本兼容性.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Dict[str, Any]: 兼容性检查结果.
        """
        try:
            self._log_operation("check_poc_version_compatibility", {"poc_id": poc_id})

            metadata = self.get_poc_metadata(poc_id)
            if not metadata:
                return {
                    "compatible": False,
                    "reason": f"POC 不存在: {poc_id}",
                    "poc_id": poc_id,
                }

            poc_version = metadata.version
            min_version = metadata.min_pocsuite_version

            result = {
                "poc_id": poc_id,
                "poc_version": poc_version,
                "current_pocsuite_version": self.CURRENT_POCSUITE_VERSION,
                "min_required_version": min_version,
                "compatible": True,
                "warnings": [],
            }

            if poc_version not in self.SUPPORTED_POC_VERSIONS:
                result["warnings"].append(f"POC 版本 {poc_version} 不在支持列表中")

            if min_version:
                if not self._compare_versions(self.CURRENT_POCSUITE_VERSION, min_version):
                    result["compatible"] = False
                    result["reason"] = (
                        f"当前 Pocsuite3 版本 {self.CURRENT_POCSUITE_VERSION} "
                        f"低于要求的最低版本 {min_version}"
                    )

            return result

        except Exception as e:
            self._handle_error("check_poc_version_compatibility", e, {"poc_id": poc_id})
            return {
                "compatible": False,
                "reason": str(e),
                "poc_id": poc_id,
            }

    def _compare_versions(self, v1: str, v2: str) -> bool:
        """比较版本号.

        Args:
            v1: 版本号1.
            v2: 版本号2.

        Returns:
            bool: v1 >= v2 返回 True.
        """
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]

            for i in range(max(len(parts1), len(parts2))):
                p1 = parts1[i] if i < len(parts1) else 0
                p2 = parts2[i] if i < len(parts2) else 0
                if p1 < p2:
                    return False
                if p1 > p2:
                    return True
            return True
        except Exception:
            return True

    def get_poc_version_info(self, poc_id: str) -> Dict[str, Any]:
        """获取 POC 版本信息.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Dict[str, Any]: 版本信息字典.
        """
        try:
            metadata = self.get_poc_metadata(poc_id)
            if not metadata:
                return {
                    "success": False,
                    "error": f"POC 不存在: {poc_id}",
                }

            return {
                "success": True,
                "poc_id": poc_id,
                "version": metadata.version,
                "created_at": metadata.created_at.isoformat() if metadata.created_at else None,
                "updated_at": metadata.updated_at.isoformat() if metadata.updated_at else None,
                "min_pocsuite_version": metadata.min_pocsuite_version,
                "source": metadata.source,
            }

        except Exception as e:
            return self._handle_error("get_poc_version_info", e, {"poc_id": poc_id})

    async def update_poc_to_latest_version(self, poc_id: str) -> Dict[str, Any]:
        """更新 POC 到最新版本.

        Args:
            poc_id: POC 唯一标识.

        Returns:
            Dict[str, Any]: 更新结果.
        """
        try:
            self._log_operation("update_poc_to_latest_version", {"poc_id": poc_id})

            metadata = self.get_poc_metadata(poc_id)
            if not metadata:
                return {
                    "success": False,
                    "error": f"POC 不存在: {poc_id}",
                }

            if metadata.source == POCSource.SEEBUG.value:
                ssvid = poc_id.replace("seebug_", "")
                new_code = await self.download_poc_from_seebug(int(ssvid))

                if new_code:
                    self.poc_cache.delete(f"poc_code_{poc_id}")
                    self.poc_cache.set(f"poc_code_{poc_id}", new_code)

                    with self._lock:
                        metadata.update_version(metadata.version, "从 Seebug 更新")

                    return {
                        "success": True,
                        "poc_id": poc_id,
                        "message": "POC 已更新到最新版本",
                    }
                else:
                    return {
                        "success": False,
                        "error": "无法从 Seebug 获取最新版本",
                    }
            else:
                return {
                    "success": False,
                    "error": f"不支持自动更新来源为 {metadata.source} 的 POC",
                }

        except Exception as e:
            return self._handle_error("update_poc_to_latest_version", e, {"poc_id": poc_id})

    def update_poc_version(
        self, poc_id: str, new_version: str, changelog: Optional[str] = None
    ) -> Dict[str, Any]:
        """更新 POC 版本.

        Args:
            poc_id: POC 唯一标识.
            new_version: 新版本号.
            changelog: 变更日志.

        Returns:
            Dict[str, Any]: 更新结果.
        """
        try:
            with self._lock:
                if poc_id not in self.poc_registry:
                    logger.warning(f"⚠️ POC 不存在: {poc_id}")
                    return {"success": False, "error": f"POC 不存在: {poc_id}"}

                self.poc_registry[poc_id].update_version(new_version, changelog)
                logger.info(f"✅ 更新 POC 版本: {poc_id} -> {new_version}")
                return {"success": True, "poc_id": poc_id, "new_version": new_version}

        except Exception as e:
            return self._handle_error(
                "update_poc_version", e, {"poc_id": poc_id, "new_version": new_version}
            )

    def clear_cache(self) -> Dict[str, Any]:
        """清除缓存.

        Returns:
            Dict[str, Any]: 清除结果.
        """
        try:
            self._log_operation("clear_cache")

            stats_before = self.poc_cache.get_stats()
            self.poc_cache.clear()

            logger.info("✅ POC 缓存已清除")
            return {
                "success": True,
                "cleared_entries": stats_before["cache_entries"],
            }

        except Exception as e:
            return self._handle_error("clear_cache", e)

    def cleanup_expired_cache(self) -> Dict[str, Any]:
        """清理过期缓存.

        Returns:
            Dict[str, Any]: 清理结果.
        """
        try:
            self._log_operation("cleanup_expired_cache")

            cleaned = self.poc_cache.cleanup_expired()

            logger.info(f"✅ 清理了 {cleaned} 个过期缓存条目")
            return {
                "success": True,
                "cleaned_entries": cleaned,
            }

        except Exception as e:
            return self._handle_error("cleanup_expired_cache", e)

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计.

        Returns:
            Dict[str, Any]: 缓存统计信息.
        """
        try:
            return self.poc_cache.get_stats()
        except Exception as e:
            self._handle_error("get_cache_stats", e)
            return {"error": str(e)}

    def invalidate_cache(self, pattern: Optional[str] = None) -> Dict[str, Any]:
        """使缓存失效.

        Args:
            pattern: 缓存键模式.

        Returns:
            Dict[str, Any]: 失效结果.
        """
        try:
            self._log_operation("invalidate_cache", {"pattern": pattern})

            invalidated = self.poc_cache.invalidate(pattern)

            logger.info(f"✅ 使 {invalidated} 个缓存条目失效")
            return {
                "success": True,
                "invalidated_entries": invalidated,
            }

        except Exception as e:
            return self._handle_error("invalidate_cache", e, {"pattern": pattern})

    def validate_poc_script(self, poc_code: str) -> Dict[str, Any]:
        """验证 POC 脚本.

        Args:
            poc_code: POC 代码.

        Returns:
            Dict[str, Any]: 验证结果.
        """
        try:
            self._log_operation("validate_poc_script")

            validation_result = validate_poc_script_code(poc_code)

            if validation_result["is_valid"]:
                logger.info("✅ POC脚本格式验证通过")
            else:
                logger.warning(f"⚠️ POC脚本格式验证失败: {validation_result['errors']}")

            return validation_result

        except Exception as e:
            self._handle_error("validate_poc_script", e)
            return {
                "is_valid": False,
                "errors": [f"验证过程出错: {str(e)}"],
            }

    async def create_verification_task(
        self,
        poc_id: str,
        target: str,
        priority: int = 5,
        task_id: Optional[str] = None,
    ) -> POCVerificationTask:
        """创建验证任务.

        Args:
            poc_id: POC 唯一标识.
            target: 目标地址.
            priority: 优先级.
            task_id: 任务 ID.

        Returns:
            POCVerificationTask: 验证任务对象.

        Raises:
            POCNotFoundError: POC 不存在.
            POCVersionIncompatibleError: POC 版本不兼容.
        """
        try:
            self._log_operation("create_verification_task", {"poc_id": poc_id, "target": target})

            poc_metadata = self.get_poc_metadata(poc_id)
            if not poc_metadata:
                raise POCNotFoundError(f"POC 不存在: {poc_id}")

            compatibility = self.check_poc_version_compatibility(poc_id)
            if not compatibility.get("compatible", True):
                raise POCVersionIncompatibleError(compatibility.get("reason", "版本不兼容"))

            verification_task = await POCVerificationTask.create(
                task_id=task_id,
                poc_name=poc_metadata.poc_name,
                poc_id=poc_id,
                target=target,
                priority=priority,
                status="pending",
                progress=0,
                config={
                    "poc_metadata": poc_metadata.to_dict(),
                    "source": poc_metadata.source,
                },
            )

            logger.info(f"✅ 创建 POC 验证任务: {poc_metadata.poc_name} -> {target}")
            return verification_task

        except (POCNotFoundError, POCVersionIncompatibleError) as e:
            raise
        except Exception as e:
            self._handle_error(
                "create_verification_task", e, {"poc_id": poc_id, "target": target}, raise_error=True
            )
            raise

    def register_generated_poc(
        self, poc_id: str, code: str, metadata: POCMetadata
    ) -> Dict[str, Any]:
        """注册生成的 POC.

        Args:
            poc_id: POC 唯一标识.
            code: POC 代码.
            metadata: POC 元数据.

        Returns:
            Dict[str, Any]: 注册结果.
        """
        try:
            self._log_operation("register_generated_poc", {"poc_id": poc_id})

            with self._lock:
                self.poc_registry[poc_id] = metadata
                self.generated_poc_codes[poc_id] = code

            logger.info(f"✅ 注册生成的 POC: {poc_id}")
            return {"success": True, "poc_id": poc_id}

        except Exception as e:
            return self._handle_error("register_generated_poc", e, {"poc_id": poc_id})

    async def search_pocsuite_pocs(
        self,
        keyword: str,
        limit: int = 10,
    ) -> List[POCMetadata]:
        """搜索 Pocsuite3 POC.

        Args:
            keyword: 搜索关键词.
            limit: 返回数量限制.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            self._log_operation("search_pocsuite_pocs", {"keyword": keyword, "limit": limit})

            poc_names = self.pocsuite3_agent.search_pocs(keyword)

            if not poc_names:
                return []

            poc_names = poc_names[:limit]

            poc_metadata_list = []
            with self._lock:
                for name in poc_names:
                    poc_id = f"pocsuite3_{name}"

                    metadata = POCMetadata(
                        poc_name=name,
                        poc_id=poc_id,
                        poc_type="web",
                        severity="high",
                        source=POCSource.POCSUITE3.value,
                        version="1.0",
                        tags=["pocsuite3"],
                    )
                    poc_metadata_list.append(metadata)
                    self.poc_registry[poc_id] = metadata

            logger.info(f"✅ Pocsuite3 POC搜索成功,找到 {len(poc_metadata_list)} 个POC")
            return poc_metadata_list

        except Exception as e:
            self._handle_error("search_pocsuite_pocs", e, {"keyword": keyword})
            return []

    async def search_seebug_pocs(
        self,
        keyword: str,
        page: int = 1,
        page_size: int = 10,
    ) -> List[POCMetadata]:
        """搜索 Seebug POC.

        简化说明: 统一使用 _search_seebug_pocs_internal 方法处理搜索逻辑,
        避免与 sync_from_seebug 方法的重复代码。

        Args:
            keyword: 搜索关键词.
            page: 页码.
            page_size: 每页数量.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        return await self._search_seebug_pocs_internal(
            keyword=keyword,
            page=page,
            page_size=page_size,
            force_refresh=False,
            cache_key_prefix="search",
            add_seebug_prefix=True
        )

    async def batch_sync_from_seebug(
        self,
        keywords: List[str],
        limit_per_keyword: int = 10,
    ) -> List[POCMetadata]:
        """批量从 Seebug 同步 POC.

        Args:
            keywords: 关键词列表.
            limit_per_keyword: 每个关键词的限制数量.

        Returns:
            List[POCMetadata]: POC 元数据列表.
        """
        try:
            self._log_operation("batch_sync_from_seebug", {"keywords_count": len(keywords)})

            all_pocs = []

            for keyword in keywords:
                pocs = await self.sync_from_seebug(keyword, limit_per_keyword)
                all_pocs.extend(pocs)

            seen_ids = set()
            unique_pocs = []
            for poc in all_pocs:
                if poc.poc_id not in seen_ids:
                    seen_ids.add(poc.poc_id)
                    unique_pocs.append(poc)

            logger.info(f"✅ 批量同步完成,共获取 {len(unique_pocs)} 个唯一POC")
            return unique_pocs

        except Exception as e:
            self._handle_error("batch_sync_from_seebug", e, {"keywords_count": len(keywords)})
            return []

    def get_error_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取错误历史.

        Args:
            limit: 返回数量限制.

        Returns:
            List[Dict[str, Any]]: 错误历史列表.
        """
        try:
            return self._sync_errors[-limit:]
        except Exception as e:
            return []

    def clear_error_history(self) -> Dict[str, Any]:
        """清除错误历史.

        Returns:
            Dict[str, Any]: 清除结果.
        """
        try:
            count = len(self._sync_errors)
            self._sync_errors = []
            logger.info(f"✅ 清除了 {count} 条错误历史记录")
            return {"success": True, "cleared_count": count}
        except Exception as e:
            return self._handle_error("clear_error_history", e)


poc_manager = POCManager()
