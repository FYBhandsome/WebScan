"""
Seebug 工具模块

统一管理 Seebug_Agent 的导入和配置，提供统一的接口访问 Seebug_Agent 功能。
整合了 API 响应封装、缓存和统计功能。

模块功能:
1. Seebug_Agent 集成
   - 自动导入和配置 Seebug_Agent
   - 提供 SeebugClient 和 SeebugAgent 的统一访问接口

2. API 响应封装
   - APIResponse: 标准化的 API 响应数据类

3. 缓存机制
   - 支持请求结果缓存
   - 可配置缓存过期时间

4. 统计功能
   - 请求计数
   - 成功/失败统计
   - 缓存命中率

使用示例:
    from backend.utils.seebug_utils import seebug_utils
    
    # 检查可用性
    if seebug_utils.is_available():
        # 验证 API Key
        result = await seebug_utils.validate_api_key()
        
        # 搜索 POC
        response = await seebug_utils.search_poc("nginx", page=1, page_size=10)
        
        # 下载 POC
        response = await seebug_utils.download_poc(ssvid=12345)
        
        # 获取统计信息
        stats = seebug_utils.get_statistics()

配置要求:
    需要在 backend/config.py 或 .env 中配置:
    - SEEBUG_API_KEY: Seebug API 密钥
    - AI_API_KEY: AI API 密钥（可选）
    - AI_BASE_URL: AI API 基础 URL（可选）

注意:
    - Seebug_Agent 需要单独安装或放置在项目根目录
    - 部分功能需要有效的 Seebug API Key
"""
import sys
import logging
import asyncio
import copy
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime

from backend.config import settings

logger = logging.getLogger(__name__)

seebug_agent_path = Path(__file__).parent.parent.parent / "Seebug_Agent"
if str(seebug_agent_path) not in sys.path:
    sys.path.insert(0, str(seebug_agent_path))

try:
    from Seebug_Agent import SeebugClient, SeebugAgent, Config
    
    SEBUG_AGENT_AVAILABLE = True
except ImportError as e:
    SEBUG_AGENT_AVAILABLE = False
    logger.warning(f"Seebug_Agent导入失败: {e}")


@dataclass
class APIResponse:
    """
    API 响应数据类
    
    用于存储 API 响应的标准化数据，提供统一的响应格式。
    
    属性:
        success: 请求是否成功
        data: 响应数据（任意类型）
        message: 响应消息
        status_code: HTTP 状态码
        execution_time: 执行时间（秒）
    
    使用示例:
        response = APIResponse(
            success=True,
            data={"poc_list": [...]},
            message="搜索成功",
            status_code=200,
            execution_time=0.5
        )
    """
    success: bool
    data: Optional[Any] = None
    message: str = ""
    status_code: int = 200
    execution_time: float = 0.0


class SeebugUtils:
    """
    Seebug 工具类
    
    提供统一的 Seebug_Agent 功能访问接口，整合缓存和统计功能。
    采用单例模式，确保全局只有一个实例。
    
    主要功能:
    1. Seebug_Agent 管理
       - 自动初始化 SeebugClient 和 SeebugAgent
       - 提供统一的访问接口
    
    2. 缓存管理
       - 支持请求结果缓存
       - 可配置缓存过期时间
       - 支持缓存清除
    
    3. 统计功能
       - 请求计数统计
       - 成功/失败率统计
       - 缓存命中率统计
    
    主要方法:
        is_available: 检查 Seebug_Agent 是否可用
        get_client: 获取 SeebugClient 实例
        get_agent: 获取 SeebugAgent 实例
        validate_api_key: 验证 API Key
        search_poc: 搜索 POC
        download_poc: 下载 POC
        get_poc_detail: 获取 POC 详情
        crawl_recent_vulnerabilities: 爬取最新漏洞
        clear_cache: 清除缓存
        get_statistics: 获取统计信息
    
    使用示例:
        from backend.utils.seebug_utils import seebug_utils
        
        # 检查可用性
        if seebug_utils.is_available():
            # 搜索 POC
            response = await seebug_utils.search_poc("nginx")
            if response.success:
                poc_list = response.data.get("list", [])
        
        # 获取统计信息
        stats = seebug_utils.get_cache_stats()
        print(f"请求总数: {stats['request_count']}")
        print(f"成功率: {stats['success_rate']:.2f}%")
    """
    
    _instance: Optional['SeebugUtils'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self.config = None
        self.client = None
        self.agent = None
        
        self.cache: Dict[str, tuple] = {}
        self.enable_cache = True
        self.request_count = 0
        self.success_count = 0
        self.error_count = 0
        
        if SEBUG_AGENT_AVAILABLE:
            self._initialize_components()
    
    def _initialize_components(self):
        self.config = Config()
        
        if hasattr(settings, 'SEEBUG_API_KEY'):
            self.config.SEEBUG_API_KEY = settings.SEEBUG_API_KEY
        
        if hasattr(settings, 'AI_API_KEY'):
            self.config.AI_API_KEY = settings.AI_API_KEY
        
        if hasattr(settings, 'AI_BASE_URL'):
            self.config.AI_BASE_URL = settings.AI_BASE_URL
        
        self.client = SeebugClient(self.config)
        self.agent = SeebugAgent(self.config)
        
        logger.info("Seebug组件初始化完成")
    
    def is_available(self) -> bool:
        return SEBUG_AGENT_AVAILABLE and self._initialized
    
    def get_client(self) -> Optional['SeebugClient']:
        return self.client if self.is_available() else None
    
    def get_agent(self) -> Optional['SeebugAgent']:
        return self.agent if self.is_available() else None
    
    def clear_cache(self):
        self.cache.clear()
        logger.info("API缓存已清除")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        return {
            "cache_entries": len(self.cache),
            "cache_enabled": self.enable_cache,
            "request_count": self.request_count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "success_rate": (
                self.success_count / self.request_count * 100
                if self.request_count > 0 else 0
            )
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "api_key_configured": bool(self.config.SEEBUG_API_KEY if self.config else None),
            "cache_enabled": self.enable_cache,
            "cache_stats": self.get_cache_stats(),
            "seebug_agent_available": self.is_available()
        }
    
    async def validate_api_key(self, api_key: Optional[str] = None) -> APIResponse:
        cache_key = f"validate_key_{(api_key or '')[:8]}"

        if self.enable_cache and cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if (datetime.now() - timestamp).total_seconds() < 3600:
                logger.info("使用缓存的API Key验证结果")
                return cached_data

        logger.info("开始验证Seebug API Key")
        self.request_count += 1

        try:
            if not self.is_available():
                return APIResponse(
                    success=False,
                    message="Seebug_Agent not available",
                    status_code=503
                )
            
            result = self.client.validate_key()
            success = result.get("status") == "success"
            message = result.get("msg", "")

            response = APIResponse(
                success=success,
                message=message,
                status_code=200 if success else 401,
                execution_time=0.0
            )

            if success:
                self.success_count += 1
                logger.info("Seebug API Key验证成功")
                if self.enable_cache:
                    self.cache[cache_key] = (response, datetime.now())
            else:
                self.error_count += 1
                logger.warning(f"Seebug API Key验证失败: {message}")

            return response

        except Exception as e:
            self.error_count += 1
            logger.error(f"验证Seebug API Key异常: {str(e)}")
            return APIResponse(
                success=False,
                message=f"验证异常: {str(e)}",
                status_code=500
            )

    async def search_poc(
        self,
        keyword: str = "",
        page: int = 1,
        page_size: int = 10
    ) -> APIResponse:
        cache_key = f"search_poc_{keyword}_{page}_{page_size}"

        if self.enable_cache and cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if (datetime.now() - timestamp).total_seconds() < 1800:
                logger.info("使用缓存的POC搜索结果")
                return cached_data

        logger.info(f"开始搜索POC: 关键词={keyword}, 页码={page}")
        self.request_count += 1

        try:
            if not self.is_available():
                return APIResponse(
                    success=False,
                    message="Seebug_Agent not available",
                    status_code=503
                )
            
            result = self.client.search_poc(keyword, page, page_size)
            success = result.get("status") == "success"
            raw_data = result.get("data", {})
            message = result.get("msg", "")
            
            if isinstance(raw_data, dict):
                poc_list = raw_data.get("list", [])
                total = raw_data.get("total", len(poc_list))
            elif isinstance(raw_data, list):
                poc_list = raw_data
                total = len(poc_list)
            else:
                poc_list = []
                total = 0
            
            data = {
                "list": poc_list,
                "total": total
            }

            response = APIResponse(
                success=success,
                data=data,
                message=message,
                status_code=200 if success else 404,
                execution_time=0.0
            )

            if success:
                self.success_count += 1
                logger.info(f"POC搜索成功: 找到{total}个结果")
                if self.enable_cache:
                    self.cache[cache_key] = (copy.deepcopy(response), datetime.now())
            else:
                self.error_count += 1
                logger.warning(f"POC搜索失败: {message}")

            return response

        except Exception as e:
            self.error_count += 1
            logger.error(f"POC搜索异常: {str(e)}")
            return APIResponse(
                success=False,
                message=f"搜索异常: {str(e)}",
                status_code=500
            )

    async def crawl_recent_vulnerabilities(self, limit: int = 20) -> APIResponse:
        logger.info(f"开始爬取最新漏洞信息, limit={limit}")
        self.request_count += 1
        
        try:
            if not self.is_available():
                return APIResponse(
                    success=False,
                    message="Seebug_Agent not available",
                    status_code=503
                )
            
            all_pocs = []
            page = 1
            max_pages = 5
            
            while len(all_pocs) < limit and page <= max_pages:
                logger.info(f"爬取第 {page} 页...")
                if hasattr(self.client, '_search_poc_web'):
                    search_result = self.client._search_poc_web("", page=page)
                else:
                    return APIResponse(success=False, message="Seebug客户端不支持爬取", status_code=501)
                
                if search_result.get("status") != "success":
                    logger.warning(f"第 {page} 页爬取失败: {search_result.get('msg')}")
                    break
                    
                page_pocs = search_result.get("data", {}).get("list", [])
                if not page_pocs:
                    logger.info(f"第 {page} 页无数据，停止爬取")
                    break
                    
                all_pocs.extend(page_pocs)
                page += 1
                
                await asyncio.sleep(1)
            
            if not all_pocs:
                self.success_count += 1
                return APIResponse(success=True, data=[], message="未找到漏洞")
                
            all_pocs = all_pocs[:limit]
            enriched_pocs = []
            
            for index, poc in enumerate(all_pocs):
                try:
                    ssvid = poc.get("ssvid")
                    logger.info(f"[{index+1}/{len(all_pocs)}] 获取详情 SSVID={ssvid}")
                    if ssvid and hasattr(self.client, '_get_poc_detail_web'):
                        detail_result = self.client._get_poc_detail_web(ssvid)
                        if detail_result.get("status") == "success":
                            detail = detail_result.get("data", {})
                            poc.update(detail)
                            
                    enriched_pocs.append(poc)
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    logger.error(f"爬取漏洞详情失败 SSVID={poc.get('ssvid')}: {e}")
                    enriched_pocs.append(poc)
            
            self.success_count += 1
            return APIResponse(
                success=True,
                data=enriched_pocs,
                message=f"成功爬取 {len(enriched_pocs)} 条漏洞数据"
            )
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"爬取漏洞数据异常: {e}")
            return APIResponse(
                success=False,
                message=f"爬取异常: {str(e)}",
                status_code=500
            )

    async def download_poc(self, ssvid: int) -> APIResponse:
        cache_key = f"download_poc_{ssvid}"

        if self.enable_cache and cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if (datetime.now() - timestamp).total_seconds() < 21600:
                logger.info(f"使用缓存的POC代码: SSVID={ssvid}")
                return cached_data

        logger.info(f"开始下载POC: SSVID={ssvid}")
        self.request_count += 1

        try:
            if not self.is_available():
                return APIResponse(
                    success=False,
                    message="Seebug_Agent not available",
                    status_code=503
                )
            
            result = self.client.download_poc(ssvid)
            success = result.get("status") == "success"
            raw_data = result.get("data", {})
            message = result.get("msg", "")
            
            poc_code = None
            if isinstance(raw_data, dict):
                poc_code = raw_data.get("poc") or raw_data.get("code", "")
            
            data = {
                "code": poc_code,
                "ssvid": ssvid
            }

            response = APIResponse(
                success=success,
                data=data,
                message=message,
                status_code=200 if success else 404,
                execution_time=0.0
            )

            if success:
                self.success_count += 1
                logger.info(f"POC下载成功: SSVID={ssvid}")
                if self.enable_cache:
                    self.cache[cache_key] = (response, datetime.now())
            else:
                self.error_count += 1
                logger.warning(f"POC下载失败: {message}")

            return response

        except Exception as e:
            self.error_count += 1
            logger.error(f"POC下载异常: {str(e)}")
            return APIResponse(
                success=False,
                message=f"下载异常: {str(e)}",
                status_code=500
            )

    async def get_poc_detail(self, ssvid: int) -> APIResponse:
        cache_key = f"poc_detail_{ssvid}"

        if self.enable_cache and cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if (datetime.now() - timestamp).total_seconds() < 21600:
                logger.info(f"使用缓存的POC详情: SSVID={ssvid}")
                return cached_data

        logger.info(f"开始获取POC详情: SSVID={ssvid}")
        self.request_count += 1

        try:
            if not self.is_available():
                return APIResponse(
                    success=False,
                    message="Seebug_Agent not available",
                    status_code=503
                )
            
            result = self.client.get_poc_detail(ssvid)
            success = result.get("status") == "success"
            data = result.get("data", {})
            message = result.get("msg", "")

            response = APIResponse(
                success=success,
                data=data,
                message=message,
                status_code=200 if success else 404,
                execution_time=0.0
            )

            if success:
                self.success_count += 1
                logger.info(f"POC详情获取成功: SSVID={ssvid}")
                if self.enable_cache:
                    self.cache[cache_key] = (response, datetime.now())
            else:
                self.error_count += 1
                logger.warning(f"POC详情获取失败: {message}")

            return response

        except Exception as e:
            self.error_count += 1
            logger.error(f"POC详情获取异常: {str(e)}")
            return APIResponse(
                success=False,
                message=f"获取详情异常: {str(e)}",
                status_code=500
            )

    def search_vulnerabilities(
        self,
        keyword: str,
        page: int = 1,
        page_size: int = 10
    ) -> Dict[str, Any]:
        if not self.is_available():
            return {"status": "error", "msg": "Seebug_Agent not available"}
        
        return self.agent.search_vulnerabilities(keyword, page, page_size)
    
    def get_vulnerability_detail(self, ssvid: str) -> Dict[str, Any]:
        if not self.is_available():
            return {"status": "error", "msg": "Seebug_Agent not available"}
        
        return self.agent.get_vulnerability_detail(ssvid)
    
    def get_api_status(self) -> Dict[str, Any]:
        if not self.is_available():
            return {"available": False, "message": "Seebug_Agent not available"}
        
        status = self.client.validate_key()
        return {
            "available": status.get("status") == "success",
            "message": status.get("msg", ""),
            "data": status
        }


seebug_utils = SeebugUtils()
