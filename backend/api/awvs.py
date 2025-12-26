"""
AWVS 漏洞扫描相关的 API 路由
整合 AVWS 工具包的功能
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import logging
import json
import re
from bs4 import BeautifulSoup
from config import settings

# 导入 AWVS API 类
import sys
sys.path.append('d:\\AI_WebSecurity\\backend')
from AVWS.API.Scan import Scan
from AVWS.API.Target import Target
from AVWS.API.Vuln import Vuln
from AVWS.API.Dashboard import Dashboard

logger = logging.getLogger(__name__)

router = APIRouter()


# 请求模型
class AWVSScanRequest(BaseModel):
    url: str
    scan_type: str = "full_scan"


class AWVSTargetRequest(BaseModel):
    address: str
    description: Optional[str] = None


# 响应模型
class APIResponse(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


def get_awvs_client():
    """获取AWVS客户端实例"""
    return {
        'api_url': settings.AWVS_API_URL,
        'api_key': settings.AWVS_API_KEY
    }


# ==================== 获取所有扫描任务 ====================
@router.get("/scans", response_model=APIResponse)
async def get_all_scans():
    """
    获取所有扫描任务列表
    """
    try:
        client = get_awvs_client()
        s = Scan(client['api_url'], client['api_key'])
        data = s.get_all()
        
        logger.info(f"获取扫描任务列表成功，共 {len(data)} 个任务")
        return APIResponse(code=200, message="获取成功", data=data)
    except Exception as e:
        logger.error(f"获取扫描任务列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 创建新的扫描任务 ====================
@router.post("/scan", response_model=APIResponse)
async def create_scan(request: AWVSScanRequest):
    """
    创建新的扫描任务
    """
    try:
        client = get_awvs_client()
        
        # 先添加目标
        t = Target(client['api_url'], client['api_key'])
        target_id = t.add(request.url)
        
        if target_id is None:
            return APIResponse(code=400, message="添加目标失败", data=None)
        
        # 创建扫描任务
        s = Scan(client['api_url'], client['api_key'])
        status_code = s.add(target_id, request.scan_type)
        
        if status_code == 200:
            logger.info(f"创建扫描任务成功: {request.url}")
            return APIResponse(code=200, message="扫描任务创建成功", data={"target_id": target_id})
        else:
            return APIResponse(code=400, message="创建扫描任务失败", data=None)
            
    except Exception as e:
        logger.error(f"创建扫描任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 获取目标的漏洞结果 ====================
@router.get("/vulnerabilities/{target_id}", response_model=APIResponse)
async def get_target_vulnerabilities(target_id: str):
    """
    获取指定目标的漏洞列表
    """
    try:
        client = get_awvs_client()
        d = Vuln(client['api_url'], client['api_key'])
        
        vuln_details = json.loads(d.search(None, None, "open", target_id=target_id))
        data = []
        
        if 'vulnerabilities' in vuln_details:
            for idx, target in enumerate(vuln_details['vulnerabilities'], 1):
                item = {
                    'id': idx,
                    'severity': target['severity'],
                    'target': target['affects_url'],
                    'vuln_id': target['vuln_id'],
                    'vuln_name': target['vt_name'],
                    'time': re.sub(r'T|\..*$', " ", target['last_seen'])
                }
                data.append(item)
        
        logger.info(f"获取目标 {target_id} 的漏洞列表成功，共 {len(data)} 个漏洞")
        return APIResponse(code=200, message="获取成功", data=data)
    except Exception as e:
        logger.error(f"获取漏洞列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 获取漏洞详情 ====================
@router.get("/vulnerability/{vuln_id}", response_model=APIResponse)
async def get_vulnerability_detail(vuln_id: str):
    """
    获取指定漏洞的详细信息
    """
    try:
        client = get_awvs_client()
        d = Vuln(client['api_url'], client['api_key'])
        data = d.get(vuln_id)
        
        if not data:
            return APIResponse(code=404, message="漏洞不存在", data=None)
        
        # 解析HTML内容
        parameter_list = BeautifulSoup(data['details'], features="html.parser").findAll('span')
        request_list = BeautifulSoup(data['details'], features="html.parser").findAll('li')
        
        data_dict = {
            'affects_url': data['affects_url'],
            'last_seen': re.sub(r'T|\..*$', " ", data['last_seen']),
            'vt_name': data['vt_name'],
            'details': data['details'].replace("  ", '').replace('</p>', ''),
            'request': data['request'],
            'recommendation': data['recommendation'].replace('<br/>', '\n')
        }
        
        try:
            data_dict['parameter_name'] = parameter_list[0].contents[0]
            data_dict['parameter_data'] = parameter_list[1].contents[0]
        except:
            pass
        
        num = 1
        try:
            test_str = ''
            for i in range(len(request_list)):
                test_str += str(request_list[i].contents[0]) + str(request_list[i].contents[1]).replace('<strong>', '').replace('</strong>', '') + '\n'
                num += 1
            data_dict['tests_performed'] = test_str
            data_dict['num'] = num
        except:
            pass
        
        data_dict['details'] = data_dict['details'].replace('class="bb-dark"', 'style="color: #ff0000"')
        
        logger.info(f"获取漏洞 {vuln_id} 详情成功")
        return APIResponse(code=200, message="获取成功", data=data_dict)
    except Exception as e:
        logger.error(f"获取漏洞详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 获取漏洞排名 ====================
@router.get("/vulnerabilities/rank", response_model=APIResponse)
async def get_vulnerability_rank():
    """
    获取漏洞排名（前5名）
    """
    try:
        client = get_awvs_client()
        d = Dashboard(client['api_url'], client['api_key'])
        data = json.loads(d.stats())["top_vulnerabilities"]
        
        vuln_rank = []
        for i in range(min(5, len(data))):
            tem = {
                'name': data[i]['name'],
                'value': data[i]['count']
            }
            vuln_rank.append(tem)
        
        logger.info("获取漏洞排名成功")
        return APIResponse(code=200, message="获取成功", data=vuln_rank)
    except Exception as e:
        logger.error(f"获取漏洞排名失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 获取漏洞统计 ====================
@router.get("/vulnerabilities/stats", response_model=APIResponse)
async def get_vulnerability_stats():
    """
    获取漏洞统计信息
    """
    try:
        client = get_awvs_client()
        d = Dashboard(client['api_url'], client['api_key'])
        data = json.loads(d.stats())["vuln_count_by_criticality"]
        
        result = {}
        if data.get('high') is not None:
            vuln_high_count = [i for i in data['high'].values()]
            result['high'] = vuln_high_count
        if data.get('normal') is not None:
            vuln_normal_count = [i for i in data['normal'].values()]
            result['normal'] = vuln_normal_count
        
        logger.info("获取漏洞统计成功")
        return APIResponse(code=200, message="获取成功", data=result)
    except Exception as e:
        logger.error(f"获取漏洞统计失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 获取所有目标 ====================
@router.get("/targets", response_model=APIResponse)
async def get_all_targets():
    """
    获取所有目标列表
    """
    try:
        client = get_awvs_client()
        t = Target(client['api_url'], client['api_key'])
        data = t.get_all()
        
        logger.info(f"获取目标列表成功，共 {len(data) if data else 0} 个目标")
        return APIResponse(code=200, message="获取成功", data=data)
    except Exception as e:
        logger.error(f"获取目标列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 添加目标 ====================
@router.post("/target", response_model=APIResponse)
async def add_target(request: AWVSTargetRequest):
    """
    添加新的扫描目标
    """
    try:
        client = get_awvs_client()
        t = Target(client['api_url'], client['api_key'])
        
        target_id = t.add(request.address, request.description)
        
        if target_id:
            logger.info(f"添加目标成功: {request.address}")
            return APIResponse(code=200, message="添加成功", data={"target_id": target_id})
        else:
            return APIResponse(code=400, message="添加目标失败", data=None)
            
    except Exception as e:
        logger.error(f"添加目标失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 健康检查 ====================
@router.get("/health", response_model=APIResponse)
async def awvs_health_check():
    """
    检查AWVS服务连接状态
    """
    try:
        client = get_awvs_client()
        d = Dashboard(client['api_url'], client['api_key'])
        stats = d.stats()
        
        if stats:
            return APIResponse(code=200, message="AWVS服务连接正常", data={"status": "connected"})
        else:
            return APIResponse(code=503, message="AWVS服务连接失败", data={"status": "disconnected"})
    except Exception as e:
        logger.error(f"AWVS健康检查失败: {str(e)}")
        return APIResponse(code=503, message="AWVS服务连接失败", data={"status": "disconnected", "error": str(e)})
