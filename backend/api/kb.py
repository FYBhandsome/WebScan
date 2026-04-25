"""
漏洞知识库 API 路由

提供漏洞知识库管理功能，支持从外部数据源同步漏洞信息。
支持 Seebug 和 Exploit-DB 等数据源。

主要功能：
- 漏洞知识库列表查询
- 漏洞详情查询
- 从外部数据源同步漏洞信息
- 支持关键词搜索和过滤
- Seebug POC 搜索和下载（使用Pocsuite3内置API）
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from backend.models import VulnerabilityKB
from tortoise.expressions import Q
from backend.config import settings
from backend.utils.seebug_utils import seebug_utils
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

class SeebugPOCSearchRequest(BaseModel):
    """
    Seebug POC 搜索请求模型
    
    Attributes:
        keyword: 搜索关键词
        page: 页码，默认为1
        page_size: 每页数量，默认为10
    """
    keyword: str
    page: int = 1
    page_size: int = 10

class SeebugPOCDownloadRequest(BaseModel):
    """
    Seebug POC 下载请求模型
    
    Attributes:
        ssvid: POC 的 SSVID
        save_to_local: 是否保存到本地目录
        category: POC 分类目录
        cve_id: CVE 编号
        vuln_name: 漏洞名称
    """
    ssvid: int
    save_to_local: bool = False
    category: str = "seebug"
    cve_id: Optional[str] = None
    vuln_name: Optional[str] = None

@router.get("/vulnerabilities", response_model=Dict[str, Any])
async def list_kb_vulnerabilities(
    page: int = 1,
    page_size: int = 10,
    keyword: Optional[str] = None,
    source: Optional[str] = None,
    has_poc: Optional[bool] = None
):
    """
    获取漏洞知识库列表
    
    支持按关键词、数据源、是否有 POC 等条件过滤，以及分页查询。
    
    Args:
        page: 页码，从 1 开始
        page_size: 每页数量
        keyword: 搜索关键词，匹配名称、CVE ID 或描述
        source: 数据源过滤，如 'seebug', 'exploit-db'
        has_poc: 是否有 POC，true/false
        
    Returns:
        Dict: 包含漏洞列表和分页信息的响应，结构如下:
            {
                "code": 200,
                "message": "获取成功",
                "data": {
                    "total": 总数,
                    "page": 当前页,
                    "page_size": 每页数量,
                    "items": [...]
                }
            }
        
    Examples:
        >>> 搜索 SQL 注入相关漏洞
        >>> GET /kb/vulnerabilities?keyword=SQL%20Injection
    """
    try:
        query = VulnerabilityKB.all()
        
        if keyword:
            query = query.filter(Q(name__icontains=keyword) | Q(cve_id__icontains=keyword) | Q(description__icontains=keyword))
        
        if source:
            try:
                query = query.filter(source=source)
            except Exception:
                logger.warning("source 字段不存在于当前数据库表中，跳过过滤")
        
        if has_poc is not None:
            try:
                query = query.filter(has_poc=has_poc)
            except Exception:
                logger.warning("has_poc 字段不存在于当前数据库表中，跳过过滤")
            
        total = await query.count()
        items = await query.offset((page - 1) * page_size).limit(page_size).order_by("-updated_at")
        
        formatted_items = []
        for item in items:
            item_dict = {
                'id': str(item.id),
                'cve_id': getattr(item, 'cve_id', None),
                'name': getattr(item, 'name', ''),
                'description': getattr(item, 'description', None),
                'severity': getattr(item, 'severity', None),
                'cvss_score': getattr(item, 'cvss_score', None),
                'affected_product': getattr(item, 'affected_product', None),
                'affected_versions': getattr(item, 'affected_versions', None),
                'poc_code': getattr(item, 'poc_code', None),
                'remediation': getattr(item, 'remediation', None),
                'references': getattr(item, 'references', None),
                'source': getattr(item, 'source', None),
                'has_poc': getattr(item, 'has_poc', False),
                'ssvid': getattr(item, 'ssvid', None),
                'created_at': item.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                'updated_at': item.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            formatted_items.append(item_dict)
            
        return {
            "code": 200,
            "message": "获取成功",
            "data": {
                "total": total,
                "page": page,
                "page_size": page_size,
                "items": formatted_items
            }
        }
    except Exception as e:
        logger.error(f"获取漏洞列表失败: {e}")
        return {
            "code": 500,
            "message": f"获取失败: {str(e)}",
            "data": None
        }

@router.get("/vulnerabilities/{kb_id}", response_model=Dict[str, Any])
async def get_kb_vulnerability(kb_id: str):
    """
    获取漏洞知识库详情
    
    根据漏洞 ID 获取详细的漏洞信息。
    
    Args:
        kb_id: 漏洞知识库 ID（字符串格式，避免前端大整数精度丢失）
        
    Returns:
        Dict: 包含漏洞详细信息的响应
        
    Raises:
        HTTPException: 当漏洞不存在时抛出 404 错误
        
    Examples:
        >>> 获取漏洞详情
        >>> GET /kb/vulnerabilities/1
    """
    try:
        kb_id_int = int(kb_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid vulnerability ID format")
    
    item = await VulnerabilityKB.get_or_none(id=kb_id_int)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    item_dict = {
        'id': str(item.id),
        'cve_id': getattr(item, 'cve_id', None),
        'name': getattr(item, 'name', ''),
        'description': getattr(item, 'description', None),
        'severity': getattr(item, 'severity', None),
        'cvss_score': getattr(item, 'cvss_score', None),
        'affected_product': getattr(item, 'affected_product', None),
        'affected_versions': getattr(item, 'affected_versions', None),
        'poc_code': getattr(item, 'poc_code', None),
        'remediation': getattr(item, 'remediation', None),
        'references': getattr(item, 'references', None),
        'source': getattr(item, 'source', None),
        'has_poc': getattr(item, 'has_poc', False),
        'ssvid': getattr(item, 'ssvid', None),
        'created_at': item.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        'updated_at': item.updated_at.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    return item_dict

async def validate_seebug_apikey(api_key: str) -> bool:
    """
    验证 Seebug API Key 是否有效（使用统一API客户端）
    
    Args:
        api_key: Seebug API Key
        
    Returns:
        bool: API Key 是否有效
    """
    response = await seebug_utils.validate_api_key(api_key)
    return response.success

async def search_seebug_poc(keyword: str, page: int = 1, page_size: int = 10) -> List[Dict[str, Any]]:
    """
    搜索 Seebug POC（使用统一API客户端）
    
    Args:
        keyword: 搜索关键词
        page: 页码
        page_size: 每页数量
        
    Returns:
        List[Dict]: POC 列表
    """
    response = await seebug_utils.search_poc(keyword, page, page_size)
    
    if response.success and response.data:
        pocs = response.data.get('list', [])
        logger.info(f"从 Seebug 搜索到 {len(pocs)} 个POC")
        return pocs
    else:
        logger.warning(f"从 Seebug 未搜索到POC: {response.message}")
        return []

async def download_seebug_poc(ssvid: int) -> Optional[str]:
    """
    下载 Seebug POC 代码（使用统一API客户端）
    
    Args:
        ssvid: POC 的 SSVID
        
    Returns:
        Optional[str]: POC 代码，失败返回 None
    """
    response = await seebug_utils.download_poc(ssvid)
    
    if response.success and response.data:
        poc_code = response.data.get('code')
        logger.info(f"从 Seebug 下载POC成功: SSVID={ssvid}")
        return poc_code
    else:
        logger.warning(f"从 Seebug 下载POC失败: {response.message}")
        return None

async def get_seebug_poc_detail(ssvid: int) -> Optional[Dict[str, Any]]:
    """
    获取 Seebug POC 详情（使用统一API客户端）
    
    Args:
        ssvid: POC 的 SSVID
        
    Returns:
        Optional[Dict]: POC 详情，失败返回 None
    """
    response = await seebug_utils.get_poc_detail(ssvid)
    
    if response.success and response.data:
        logger.info(f"从 Seebug 获取POC详情成功: SSVID={ssvid}")
        return response.data
    else:
        logger.warning(f"从 Seebug 获取POC详情失败: {response.message}")
        return None





@router.post("/search-from-seebug", response_model=Dict[str, Any])
async def search_from_seebug(request: SeebugPOCSearchRequest):
    """
    从 Seebug 实时搜索漏洞并保存到本地数据库
    
    该接口会：
    1. 调用 Seebug API 进行实时搜索
    2. 将搜索结果保存到 VulnerabilityKB 表（去重）
    3. 返回搜索结果
    
    Args:
        request: 搜索请求参数
            - keyword: 搜索关键词
            - page: 页码，默认为1
            - page_size: 每页数量，默认为10
        
    Returns:
        Dict: 包含搜索结果和保存统计的响应
            - code: 状态码
            - message: 响应消息
            - data: 包含 pocs 列表、saved_count、total
        
    Examples:
        >>> POST /kb/search-from-seebug
        >>> {
        ...     "keyword": "thinkphp",
        ...     "page": 1,
        ...     "page_size": 10
        ... }
    """
    try:
        if not await validate_seebug_apikey(settings.SEEBUG_API_KEY):
            return {
                "code": 401,
                "message": "Seebug API Key 无效，请检查配置",
                "data": None
            }
        
        poc_list = await search_seebug_poc(request.keyword, request.page, request.page_size)
        
        if not poc_list:
            return {
                "code": 200,
                "message": "未搜索到相关漏洞",
                "data": {
                    "pocs": [],
                    "saved_count": 0,
                    "total": 0
                }
            }
        
        saved_count = 0
        updated_count = 0
        saved_pocs = []
        
        for poc in poc_list:
            ssvid = poc.get('ssvid') or poc.get('id')
            if not ssvid:
                continue
            
            existing = await VulnerabilityKB.get_or_none(ssvid=ssvid)
            
            vuln_data = {
                'cve_id': poc.get('cve_id', ''),
                'name': poc.get('name', poc.get('title', poc.get('vul_name', 'Unknown'))),
                'description': poc.get('description', poc.get('summary', '')),
                'severity': poc.get('level', poc.get('severity', 'Unknown')),
                'cvss_score': float(poc.get('cvss_score', 0.0)) if poc.get('cvss_score') else 0.0,
                'affected_product': poc.get('product', poc.get('affected', '')),
                'solution': poc.get('solution', poc.get('patch', '')),
                'source': 'seebug',
                'has_poc': True,
                'ssvid': ssvid
            }
            
            if existing:
                for key, value in vuln_data.items():
                    if key not in ['ssvid', 'source']:
                        setattr(existing, key, value)
                await existing.save()
                updated_count += 1
                saved_pocs.append({
                    **vuln_data,
                    'id': str(existing.id),
                    'is_new': False
                })
            else:
                new_vuln = await VulnerabilityKB.create(**vuln_data)
                saved_count += 1
                saved_pocs.append({
                    **vuln_data,
                    'id': str(new_vuln.id),
                    'is_new': True
                })
        
        logger.info(f"从 Seebug 搜索完成: 关键词={request.keyword}, 结果数={len(poc_list)}, 新增={saved_count}, 更新={updated_count}")
        
        return {
            "code": 200,
            "message": f"搜索成功，新增 {saved_count} 条，更新 {updated_count} 条",
            "data": {
                "pocs": saved_pocs,
                "saved_count": saved_count,
                "updated_count": updated_count,
                "total": len(saved_pocs)
            }
        }
    except Exception as e:
        logger.error(f"从 Seebug 搜索失败: {e}")
        return {
            "code": 500,
            "message": f"搜索失败: {str(e)}",
            "data": None
        }


@router.post("/seebug/poc/search", response_model=Dict[str, Any])
async def search_poc(request: SeebugPOCSearchRequest):
    """
    搜索 Seebug POC
    
    Args:
        request: 搜索请求参数
        
    Returns:
        Dict: 包含 POC 列表的响应
        
    Examples:
        >>> POST /kb/seebug/poc/search
        >>> {
        ...     "keyword": "thinkphp",
        ...     "page": 1,
        ...     "page_size": 10
        ... }
    """
    try:
        # 验证 API Key
        if not await validate_seebug_apikey(settings.SEEBUG_API_KEY):
            return {
                "code": 401,
                "message": "Seebug API Key 无效",
                "data": None
            }
        
        # 搜索 POC
        poc_list = await search_seebug_poc(request.keyword, request.page, request.page_size)
        
        logger.info(f"搜索 Seebug POC 成功: 关键词={request.keyword}, 结果数={len(poc_list)}")
        
        return {
            "code": 200,
            "message": "搜索成功",
            "data": {
                "keyword": request.keyword,
                "page": request.page,
                "page_size": request.page_size,
                "total": len(poc_list),
                "pocs": poc_list
            }
        }
    except Exception as e:
        logger.error(f"搜索 Seebug POC 失败: {e}")
        return {
            "code": 500,
            "message": f"搜索失败: {str(e)}",
            "data": None
        }

@router.post("/seebug/poc/download", response_model=Dict[str, Any])
async def download_poc(request: SeebugPOCDownloadRequest):
    """
    下载 Seebug POC 代码
    
    Args:
        request: 下载请求参数，包含:
            - ssvid: POC 的 SSVID
            - save_to_local: 是否保存到本地目录（默认 False）
            - category: POC 分类目录（默认 seebug）
            - cve_id: CVE 编号（可选）
            - vuln_name: 漏洞名称（可选）
        
    Returns:
        Dict: 包含 POC 代码的响应
        
    Examples:
        >>> POST /kb/seebug/poc/download
        >>> {
        ...     "ssvid": 97343,
        ...     "save_to_local": true,
        ...     "category": "weblogic",
        ...     "cve_id": "CVE-2020-2551"
        ... }
    """
    try:
        if not await validate_seebug_apikey(settings.SEEBUG_API_KEY):
            return {
                "code": 401,
                "message": "Seebug API Key 无效",
                "data": None
            }
        
        poc_code = await download_seebug_poc(request.ssvid)
        
        if poc_code is None:
            return {
                "code": 404,
                "message": "POC 不存在或下载失败",
                "data": None
            }
        
        response_data = {
            "ssvid": request.ssvid,
            "poc_code": poc_code
        }
        
        if request.save_to_local:
            from backend.ai_agents.poc_system.poc_manager import poc_manager
            
            save_result = await poc_manager.save_poc_to_local(
                ssvid=request.ssvid,
                poc_code=poc_code,
                category=request.category,
                cve_id=request.cve_id,
                vuln_name=request.vuln_name
            )
            
            if save_result.get("success"):
                response_data["saved_to"] = save_result.get("file_path")
                response_data["poc_id"] = save_result.get("poc_id")
                logger.info(f"POC 已保存到本地: {save_result.get('file_path')}")
            else:
                logger.warning(f"POC 保存失败: {save_result.get('error')}")
        
        logger.info(f"下载 Seebug POC 成功: SSVID={request.ssvid}")
        
        return {
            "code": 200,
            "message": "下载成功",
            "data": response_data
        }
    except Exception as e:
        logger.error(f"下载 Seebug POC 失败: {e}")
        return {
            "code": 500,
            "message": f"下载失败: {str(e)}",
            "data": None
        }

@router.get("/seebug/poc/{ssvid}/detail", response_model=Dict[str, Any])
async def get_poc_detail(ssvid: int):
    """
    获取 Seebug POC 详情
    
    Args:
        ssvid: POC 的 SSVID
        
    Returns:
        Dict: 包含 POC 详情的响应
        
    Examples:
        >>> GET /kb/seebug/poc/97343/detail
    """
    try:
        # 验证 API Key
        if not await validate_seebug_apikey(settings.SEEBUG_API_KEY):
            return {
                "code": 401,
                "message": "Seebug API Key 无效",
                "data": None
            }
        
        # 获取 POC 详情
        poc_detail = await get_seebug_poc_detail(ssvid)
        
        if poc_detail is None:
            return {
                "code": 404,
                "message": "POC 不存在",
                "data": None
            }
        
        logger.info(f"获取 Seebug POC 详情成功: SSVID={ssvid}")
        
        return {
            "code": 200,
            "message": "获取成功",
            "data": poc_detail
        }
    except Exception as e:
        logger.error(f"获取 Seebug POC 详情失败: {e}")
        return {
            "code": 500,
            "message": f"获取失败: {str(e)}",
            "data": None
        }

async def fetch_seebug_data():
        """
        从 Seebug 获取漏洞数据

        使用 Seebug API 获取最新的漏洞信息。
        Seebug 是国内知名的漏洞平台，提供详细的漏洞信息和 POC。

        Returns:
            List[Dict]: 漏洞数据列表
        """
        try:
            logger.info("🔍 开始从 Seebug 获取漏洞数据 (爬虫模式)")

            response = await seebug_utils.crawl_recent_vulnerabilities(limit=50)

            if response.success and response.data:
                vulnerabilities = []
                pocs = response.data if isinstance(response.data, list) else response.data.get('list', [])
                for poc in pocs:
                    vulnerabilities.append({
                        "cve_id": poc.get("cve_id", ""),
                        "name": poc.get("name", poc.get("title", poc.get("vul_name", "Unknown"))),
                        "description": poc.get("description", poc.get("summary", "")),
                        "severity": poc.get("level", "Unknown"),
                        "cvss_score": poc.get("cvss_score", 0.0),
                        "affected_product": poc.get("product", poc.get("affected", "")),
                        "solution": poc.get("solution", poc.get("patch", "")),
                        "has_poc": True,
                        "source": "seebug",
                        "poc_code": "",
                        "ssvid": poc.get("ssvid", poc.get("id"))
                    })

                logger.info(f"✅ 从 Seebug 获取到 {len(vulnerabilities)} 条漏洞数据")
                return vulnerabilities
            else:
                logger.warning(f"⚠️ 从 Seebug 获取数据失败: {response.message}")
                logger.info(f"Seebug 响应数据类型: {type(response.data)}")
                return []

        except Exception as e:
            logger.error(f"❌ 从 Seebug 获取数据失败: {e}")
            logger.info(f"Seebug 响应数据: {response.data if 'response' in locals() else 'N/A'}")
            return []

async def fetch_exploit_db_data():
    """
    从 Exploit-DB 获取漏洞数据

    实际从 Exploit-DB 平台获取漏洞信息。
    Exploit-DB 是全球最大的漏洞利用代码数据库之一。

    Returns:
        List[Dict]: 漏洞数据列表
    """
    try:
        import httpx

        logger.info("🔍 开始从 Exploit-DB 获取漏洞数据")

        api_url = "https://www.exploit-db.com/search"

        params = {
            "limit": 20,
            "order": "date",
            "sort": "desc"
        }

        headers = {
            "User-Agent": "WebScan-AI-Security-Platform/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(api_url, params=params, headers=headers)
            response.raise_for_status()

            try:
                data = response.json()

                vulnerabilities = []
                if isinstance(data, dict) and "data" in data:
                    for item in data["data"]:
                        cve_id = ""
                        if "cve" in item and item["cve"]:
                            cve_id = item["cve"][0] if isinstance(item["cve"], list) else item["cve"]

                        vulnerabilities.append({
                            "cve_id": cve_id,
                            "name": item.get("name", item.get("title", "Unknown")),
                            "description": item.get("description", item.get("summary", "")),
                            "severity": item.get("severity", "Unknown"),
                            "cvss_score": item.get("cvss_score", 0.0),
                            "affected_product": item.get("product", item.get("affected", "")),
                            "solution": item.get("solution", item.get("patch", "")),
                            "has_poc": True,
                            "source": "exploit-db",
                            "poc_code": item.get("exploit", "")
                        })
                elif isinstance(data, list):
                    for item in data:
                        cve_id = ""
                        if "cve" in item and item["cve"]:
                            cve_id = item["cve"][0] if isinstance(item["cve"], list) else item["cve"]

                        vulnerabilities.append({
                            "cve_id": cve_id,
                            "name": item.get("name", item.get("title", "Unknown")),
                            "description": item.get("description", item.get("summary", "")),
                            "severity": item.get("severity", "Unknown"),
                            "cvss_score": item.get("cvss_score", 0.0),
                            "affected_product": item.get("product", item.get("affected", "")),
                            "solution": item.get("solution", item.get("patch", "")),
                            "has_poc": True,
                            "source": "exploit-db",
                            "poc_code": item.get("exploit", "")
                        })

                logger.info(f"✅ 从 Exploit-DB 获取到 {len(vulnerabilities)} 条漏洞数据")
                return vulnerabilities
            except Exception as json_error:
                logger.warning(f"⚠️ Exploit-DB 返回的不是 JSON 格式: {json_error}")
                logger.info(f"Exploit-DB 响应内容类型: {response.headers.get('content-type', 'unknown')}")
                logger.info(f"Exploit-DB API 可能已更改或需要认证，跳过此数据源")
                return []

    except httpx.HTTPStatusError as e:
        logger.warning(f"⚠️ Exploit-DB HTTP 错误: {e.response.status_code}")
        return []
    except Exception as e:
        logger.error(f"❌ 从 Exploit-DB 获取数据失败: {e}")
        return []

async def sync_vulnerabilities_task():
    """
    后台同步漏洞数据任务
    
    从 Seebug 和 Exploit-DB 等数据源同步漏洞信息到本地数据库。
    该任务在后台异步执行，不阻塞主线程。
    """
    logger.info("开始同步漏洞知识库...")
    
    count = 0
    
    try:
        # 1. 从 Seebug 同步
        seebug_data = await fetch_seebug_data()
        logger.info(f"从 Seebug 获取到 {len(seebug_data)} 条数据")
        for data in seebug_data:
            try:
                exists = await VulnerabilityKB.get_or_none(cve_id=data['cve_id'])
                if not exists:
                    await VulnerabilityKB.create(**data)
                    count += 1
            except Exception as e:
                logger.error(f"保存 Seebug 数据失败: {e}, 数据: {data}")

        # 2. 从 Exploit-DB 同步
        edb_data = await fetch_exploit_db_data()
        logger.info(f"从 Exploit-DB 获取到 {len(edb_data)} 条数据")
        for data in edb_data:
            try:
                exists = await VulnerabilityKB.get_or_none(cve_id=data['cve_id'])
                if not exists:
                    await VulnerabilityKB.create(**data)
                    count += 1
            except Exception as e:
                logger.error(f"保存 Exploit-DB 数据失败: {e}, 数据: {data}")
                
    except Exception as e:
        logger.error(f"同步漏洞知识库失败: {e}")
            
    logger.info(f"同步完成，新增 {count} 条漏洞信息")

@router.post("/sync")
async def sync_vulnerabilities(background_tasks: BackgroundTasks):
    """
    触发漏洞库同步
    
    在后台启动漏洞数据同步任务。
    
    Args:
        background_tasks: FastAPI 后台任务管理器
        
    Returns:
        Dict: 同步任务启动响应，结构如下:
            {
                "message": "Sync task started",
                "status": "running"
            }
        
    Examples:
        >>> 触发同步
        >>> POST /kb/sync
    """
    background_tasks.add_task(sync_vulnerabilities_task)
    return {"message": "Sync task started", "status": "running"}
