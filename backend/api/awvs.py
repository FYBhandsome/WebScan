"""
AWVS 漏洞扫描相关的 API 路由
整合 AVWS 工具包的功能
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any

import logging
import json
import re
import asyncio
import time
import os
import requests
from datetime import datetime
from io import BytesIO

from functools import partial
from tortoise.functions import Count
from urllib.parse import urlparse
from backend.config import settings
from backend.models import Task, Vulnerability, Report
from backend.api.common import APIResponse

# 导入 AWVS API 类
from backend.AVWS.API.Target import Target
from backend.AVWS.API.Scan import Scan
from backend.AVWS.API.Base import Base as AWVSBase
from backend.AVWS.API.Vuln import Vuln
from backend.AVWS.API.Dashboard import Dashboard
from backend.AVWS.API.Report import Report as AWVSReport

# 导入 POC 函数
from backend.poc.weblogic.cve_2020_2551_poc import poc as cve_2020_2551_poc
from backend.poc.weblogic.cve_2018_2628_poc import poc as cve_2018_2628_poc
from backend.poc.weblogic.cve_2018_2894_poc import poc as cve_2018_2894_poc
from backend.poc.weblogic import cve_2020_14756_poc, cve_2023_21839_poc
from backend.poc.struts2.struts2_009_poc import poc as struts2_009_poc
from backend.poc.struts2.struts2_032_poc import poc as struts2_032_poc
from backend.poc.tomcat.cve_2017_12615_poc import poc as cve_2017_12615_poc
from backend.poc.tomcat import cve_2022_22965_poc, cve_2022_47986_poc
from backend.poc.jboss.cve_2017_12149_poc import poc as cve_2017_12149_poc
from backend.poc.nexus.cve_2020_10199_poc import poc as cve_2020_10199_poc
from backend.poc.drupal.cve_2018_7600_poc import poc as cve_2018_7600_poc

logger = logging.getLogger(__name__)

router = APIRouter()



async def run_sync(func, *args, **kwargs):
    """在线程池中运行同步阻塞函数"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(func, *args, **kwargs))


# 请求模型
class AWVSScanRequest(BaseModel):
    url: str
    scan_type: str = "full_scan"


class AWVSTargetRequest(BaseModel):
    address: str
    description: Optional[str] = None


class AWVSReportRequest(BaseModel):
    scan_id: str
    template_id: str = "developer"
    report_format: str = "html"


class AWVSReportGenerateRequest(BaseModel):
    task_id: int
    template_id: str = "developer"
    report_format: str = "html"
    enable_ai_analysis: bool = True


def get_awvs_client():
    """获取AWVS客户端实例"""
    return {
        'api_url': settings.AWVS_API_URL,
        'api_key': settings.AWVS_API_KEY
    }

def map_awvs_status(awvs_status: str) -> str:
    """
    映射 AWVS 状态到系统状态
    AWVS: processing, completed, failed, aborted, queued, scheduled
    System: running, completed, failed, cancelled, pending
    """
    status_map = {
        'processing': 'running',
        'queued': 'pending',
        'scheduled': 'pending',
        'aborted': 'cancelled',
        'completed': 'completed',
        'failed': 'failed'
    }
    return status_map.get(awvs_status, awvs_status)

def map_severity(awvs_severity: int, vuln_title: str) -> str:
    """
    映射 AWVS 严重程度到系统 5 级分类
    AWVS: 3=High, 2=Medium, 1=Low, 0=Info
    System: Critical, High, Medium, Low, Info
    """
    try:
        s = int(awvs_severity)
    except:
        return "Info"
        
    if s >= 3:
        # 特殊规则:SQL注入、RCE 等提升为 Critical
        critical_keywords = ['SQL Injection', 'Remote Code Execution', 'RCE', 'Command Injection']
        if any(k.lower() in vuln_title.lower() for k in critical_keywords):
            return "Critical"
        return "High"
    elif s == 2:
        return "Medium"
    elif s == 1:
        return "Low"
    else:
        return "Info"

async def sync_vulnerabilities(scan_id: str, scan_session_id: str, task_id: int):
    """同步指定扫描的漏洞信息"""
    try:
        client = get_awvs_client()
        s = Scan(client['api_url'], client['api_key'])
        
        # 获取漏洞列表 (使用线程池避免阻塞)
        vulns = await run_sync(s.get_vulns, scan_id, scan_session_id)


        if not vulns:
            return

        for v in vulns:
            vuln_id = v.get('vuln_id')
            if not vuln_id:
                continue
                
            # 检查漏洞是否已存在
            existing_vuln = await Vulnerability.filter(source_id=vuln_id, task_id=task_id).first()
            
            # 映射严重程度
            severity = map_severity(v.get('severity', 0), v.get('vt_name', ''))
            
            # 获取详细信息 (仅对中高危漏洞或不存在的漏洞获取详情,以减少请求量)
            description = v.get('description', f"See AWVS for details. Target: {v.get('affects_url')}")
            remediation = v.get('recommendation', '')
            
            if severity in ['Critical', 'High', 'Medium'] or not existing_vuln:
                try:
                    detail = await run_sync(s.get_vuln_detail, scan_id, scan_session_id, vuln_id)
                    if detail:
                        description = detail.get('description', description)
                        remediation = detail.get('recommendation', remediation)
                        # 清理HTML标签 (简单处理)
                        description = re.sub(r'<[^>]+>', '', description)
                        remediation = re.sub(r'<[^>]+>', '', remediation)
                except Exception as e:
                    logger.warning(f"获取漏洞详情失败: {str(e)}")

            if existing_vuln:
                # 更新状态和严重程度
                existing_vuln.status = v.get('status', 'open')
                existing_vuln.severity = severity
                existing_vuln.description = description
                existing_vuln.remediation = remediation
                # 更新漏洞类型（如果需要）
                vuln_type = v.get('vt_name', 'Unknown')
                if len(vuln_type) > 255:
                    vuln_type = vuln_type[:252] + "..."
                    logger.warning(f"漏洞类型名称过长，已截断: {v.get('vt_name', '')[:50]}...")
                existing_vuln.vuln_type = vuln_type
                await existing_vuln.save()
            else:
                # 创建新漏洞
                vuln_type = v.get('vt_name', 'Unknown')
                # 截断过长的漏洞类型名称（避免超过数据库字段限制）
                if len(vuln_type) > 255:
                    vuln_type = vuln_type[:252] + "..."
                    logger.warning(f"漏洞类型名称过长，已截断: {v.get('vt_name', '')[:50]}...")
                
                await Vulnerability.create(
                    task_id=task_id,
                    vuln_type=vuln_type,
                    severity=severity,
                    title=v.get('vt_name', 'Unknown'),
                    description=description,
                    remediation=remediation,
                    url=v.get('affects_url'),
                    status=v.get('status', 'open'),
                    source_id=vuln_id
                )
                
    except Exception as e:
        logger.error(f"同步漏洞失败 (ScanID: {scan_id}): {str(e)}")


async def sync_scans_from_awvs():
    """从AWVS同步扫描任务到数据库"""
    try:
        client = get_awvs_client()
        
        # 检查AWVS配置是否有效
        if not client['api_url'] or not client['api_key']:
            logger.warning("AWVS API配置不完整，跳过同步")
            return
            
        s = Scan(client['api_url'], client['api_key'])
        
        # 获取AWVS中所有扫描 (使用线程池，添加超时)
        try:
            awvs_scans = await asyncio.wait_for(run_sync(s.get_all), timeout=8.0)
        except asyncio.TimeoutError:
            logger.warning("获取AWVS扫描列表超时")
            return
        except Exception as api_error:
            logger.warning(f"获取AWVS扫描列表失败: {str(api_error)}")
            return

        if not awvs_scans:
            logger.info("AWVS中没有扫描任务")
            return


        # 获取数据库中所有AWVS任务
        # 注意:这里假设task_type='awvs_scan'
        db_tasks = await Task.filter(task_type='awvs_scan').all()
        db_task_map = {}
        for task in db_tasks:
            config = json.loads(task.config) if task.config else {}
            scan_id = config.get('scan_id')
            if scan_id:
                db_task_map[scan_id] = task

        # 同步更新 (限制最多10条)
        synced_count = 0
        max_sync_count = 10
        
        for scan in awvs_scans:
            if synced_count >= max_sync_count:
                logger.info(f"已达到同步数量限制 ({max_sync_count}条)，停止同步")
                break
                
            scan_id = scan.get('scan_id')
            target_id = scan.get('target_id')
            
            # 构建result JSON
            result_json = json.dumps(scan)
            
            current_session = scan.get('current_session', {})
            raw_status = current_session.get('status', 'unknown')
            status = map_awvs_status(raw_status)
            progress = current_session.get('progress', 0)
            scan_session_id = current_session.get('scan_session_id')
            
            target_task = None
            
            if scan_id in db_task_map:
                # 更新现有任务
                task = db_task_map[scan_id]
                task.status = status
                task.progress = progress
                task.result = result_json
                await task.save()
                target_task = task
            else:
                # 检查是否存在未关联scan_id的同目标任务
                # 优先通过 target_id 匹配 (更准确)
                existing_task = None
                
                # 获取所有未关联 scan_id 的活跃任务
                pending_tasks = await Task.filter(
                    task_type='awvs_scan',
                    status__in=['pending', 'submitted', 'processing', 'running']
                ).all()
                
                for p_task in pending_tasks:
                    p_config = json.loads(p_task.config) if p_task.config else {}
                    # 检查 scan_id 是否已存在 (如果已存在说明是其他任务)
                    if p_config.get('scan_id'):
                        continue
                        
                    # 匹配 target_id
                    if target_id and p_config.get('target_id') == target_id:
                        existing_task = p_task
                        break
                    
                    # 降级匹配: target URL (忽略末尾斜杠)
                    t1 = p_task.target.rstrip('/')
                    t2 = scan.get('target', {}).get('address', '').rstrip('/')
                    if t1 and t2 and t1 == t2:
                        existing_task = p_task
                        break
                
                if existing_task:
                    # 关联现有任务
                    existing_task.status = status
                    existing_task.progress = progress
                    existing_task.result = result_json
                    # 更新配置中的scan_id
                    config = json.loads(existing_task.config)
                    config['scan_id'] = scan_id
                    existing_task.config = json.dumps(config)
                    await existing_task.save()
                    # 更新映射防止重复处理
                    db_task_map[scan_id] = existing_task
                    target_task = existing_task
                else:
                    # 创建新任务(可能是直接在AWVS创建的)
                    target_address = scan.get('target', {}).get('address', 'Unknown Target')
                    new_task = await Task.create(
                        task_name=f"AWVS Scan: {target_address}",
                        task_type='awvs_scan',
                        target=target_address,
                        status=status,
                        progress=progress,
                        config=json.dumps({'scan_id': scan_id, 'target_id': target_id}),
                        result=result_json
                    )
                    db_task_map[scan_id] = new_task
                    target_task = new_task
            
            # 同步漏洞数据 (仅当任务处于处理中或已完成时)
            if target_task and scan_session_id and status in ['running', 'completed', 'cancelled', 'processing', 'aborted']:
                await sync_vulnerabilities(scan_id, scan_session_id, target_task.id)
                synced_count += 1
                
    except Exception as e:
        logger.error(f"同步AWVS扫描任务失败: {str(e)}")


# ====== 获取所有扫描任务 ======
@router.get("/scans", response_model=APIResponse)
async def get_all_scans():
    """
    获取所有扫描任务列表 (从数据库获取,暂不同步AWVS数据)
    
    注意: 由于AWVS数据量过大，暂时禁用自动同步功能。
    如需同步，请手动调用 /awvs/sync 接口。
    """
    try:
        logger.info("[AWVS扫描列表] 开始获取扫描列表")
        
        # 暂时禁用AWVS同步，直接从数据库读取
        # 同步功能已迁移到独立的 /awvs/sync 接口
        # 如需同步，请手动调用该接口
        
        # 从数据库读取
        tasks = await Task.filter(task_type='awvs_scan').order_by('-created_at').all()

        
        data = []
        for task in tasks:
            scan_data = {}
            if task.result:
                try:
                    scan_data = json.loads(task.result)
                except:
                    pass
            
            # 基础数据回退
            if not scan_data:
                scan_data = {
                    'target': {'address': task.target},
                    'profile_name': 'Unknown',
                    'current_session': {'status': task.status, 'severity_counts': {}, 'start_date': str(task.created_at)},
                    'target_id': json.loads(task.config).get('target_id') if task.config else None
                }
            
            # 使用数据库中的漏洞统计覆盖 AWVS 原始统计
            # 这样可以反映我们自定义的严重程度映射 (例如 SQLi -> Critical)
            db_counts = await Vulnerability.filter(task_id=task.id).group_by('severity').annotate(count=Count('id')).values('severity', 'count')
            
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            total_db_count = 0
            for item in db_counts:
                sev = str(item['severity']).lower()
                if sev in severity_counts:
                    severity_counts[sev] = item['count']
                    total_db_count += item['count']
            
            # 更新统计数据
            if 'current_session' not in scan_data:
                scan_data['current_session'] = {}
            
            # 仅当数据库有数据时才覆盖,或者如果原始数据中没有统计信息
            # 这样即使数据库同步失败,也能保留 AWVS 原始统计
            if total_db_count > 0 or not scan_data['current_session'].get('severity_counts'):
                scan_data['current_session']['severity_counts'] = severity_counts
            
            # 确保状态同步
            scan_data['current_session']['status'] = task.status
            
            # 确保 scan_id/target_id 存在
            if task.config:
                try:
                    config = json.loads(task.config)
                    if not scan_data.get('scan_id') and config.get('scan_id'):
                        scan_data['scan_id'] = config.get('scan_id')
                    if not scan_data.get('target_id') and config.get('target_id'):
                        scan_data['target_id'] = config.get('target_id')
                except:
                    pass
            
            # 确保task_name存在
            if not scan_data.get('task_name'):
                scan_data['task_name'] = task.task_name
            
            # 确保target信息完整
            if not scan_data.get('target'):
                scan_data['target'] = {'address': task.target, 'description': task.task_name}
            elif not scan_data['target'].get('description'):
                scan_data['target']['description'] = task.task_name
            
            # 确保scan_id存在（用于前端点击跳转）
            if not scan_data.get('scan_id'):
                scan_data['scan_id'] = str(task.id)
            
            data.append(scan_data)
        
        logger.info(f"获取扫描任务列表成功,共 {len(data)} 个任务")
        return APIResponse(code=200, message="获取成功", data=data)
    except Exception as e:
        logger.error(f"获取扫描任务列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 获取目标漏洞列表 ======
@router.get("/vulnerabilities/{target_id}", response_model=APIResponse)
async def get_target_vulnerabilities(target_id: str):
    """
    获取指定目标的漏洞列表
    """
    try:
        client = get_awvs_client()
        v = Vuln(client['api_url'], client['api_key'])


        
        # 搜索该目标的所有已打开的漏洞
        # search 方法返回的是 JSON 字符串,需要解析
        result_text = v.search(
            severity=None,
            criticality=None,
            status='open',
            target_id=target_id
        )


        
        data = []
        if result_text:
            try:
                result_json = json.loads(result_text)
                vulnerabilities = result_json.get('vulnerabilities', [])
                
                # Severity mapping
                severity_map = {
                    3: 'High',
                    2: 'Medium',
                    1: 'Low',
                    0: 'Info'
                }


                
                for val in vulnerabilities:
                    # Handle severity if it's an integer
                    severity_val = val.get('severity')
                    if isinstance(severity_val, int):
                        severity = severity_map.get(severity_val, 'Info')
                    else:
                        severity = str(severity_val) if severity_val is not None else 'Info'
                        
                    data.append({
                        'vuln_id': val.get('vuln_id'),
                        'severity': severity,
                        'vuln_name': val.get('vt_name'),
                        'target': val.get('affects_url'),
                        'time': val.get('last_seen', '').replace('T', ' ').split('.')[0] if val.get('last_seen') else ''
                    })
            except json.JSONDecodeError:
                logger.error(f"解析漏洞数据失败: {result_text}")
                
        return APIResponse(code=200, message="获取漏洞列表成功", data=data)
    except Exception as e:
        logger.error(f"获取漏洞列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 获取漏洞详情 ======
@router.get("/vulnerability/{vuln_id}", response_model=APIResponse)
async def get_vulnerability_detail(vuln_id: str):
    """
    获取漏洞详情
    """
    try:
        client = get_awvs_client()
        v = Vuln(client['api_url'], client['api_key'])
        
        vuln_data = v.get(vuln_id)


        if vuln_data:
            return APIResponse(code=200, message="获取漏洞详情成功", data=vuln_data)
        else:
            return APIResponse(code=404, message="未找到漏洞信息", data=None)
            
    except Exception as e:
        logger.error(f"获取漏洞详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 创建新的扫描任务 ======
@router.post("/scan", response_model=APIResponse)
async def create_scan(request: AWVSScanRequest):
    """
    创建新的扫描任务
    """
    try:
        logger.info(f"[AWVS扫描] 开始处理请求 | 目标: {request.url} | 扫描类型: {request.scan_type}")
        
        client = get_awvs_client()
        
        # 1. 在数据库创建 Pending 任务
        logger.info(f"[AWVS扫描] 创建任务 | 目标: {request.url}")
        task = await Task.create(
            task_name=f"AWVS Scan: {request.url}",
            task_type='awvs_scan',
            target=request.url,
            status='pending',
            progress=0,
            config=json.dumps({'scan_type': request.scan_type})
        )
        logger.info(f"[AWVS扫描] 任务创建成功 | 任务ID: {task.id}")
        
        # 2. 提交任务到执行队列
        from backend.task_executor import task_executor
        
        scan_config = {'scan_type': request.scan_type, 'profile': request.scan_type}
        await task_executor.start_task(task.id, request.url, scan_config)
        logger.info(f"[AWVS扫描] 任务已启动执行 | 任务ID: {task.id}")
        
        return APIResponse(code=200, message="扫描任务已提交到队列", data={"task_id": task.id, "status": "queued"})
            
    except Exception as e:
        logger.error(f"[AWVS扫描] 任务执行失败 | 目标: {request.url} | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))




# ====== 获取漏洞排名 ======
@router.get("/vulnerabilities/rank", response_model=APIResponse)
async def get_vulnerability_rank():
    """
    获取漏洞排名(前5名)
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


# ====== 获取漏洞统计 ======
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


# ====== 获取所有目标 ======
@router.get("/targets", response_model=APIResponse)
async def get_all_targets():
    """
    获取所有目标列表
    """
    try:
        logger.info("[AWVS目标列表] 开始获取目标列表")
        client = get_awvs_client()
        t = Target(client['api_url'], client['api_key'])
        data = t.get_all()
        
        logger.info(f"[AWVS目标列表] 获取成功 | 目标数量: {len(data) if data else 0}")
        return APIResponse(code=200, message="获取成功", data=data)
    except Exception as e:
        logger.error(f"[AWVS目标列表] 获取失败 | 错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 添加目标 ======
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


# ====== 删除目标 ======
@router.delete("/target/{target_id}", response_model=APIResponse)
async def delete_target(target_id: str):
    """
    删除扫描目标
    """
    try:
        client = get_awvs_client()
        t = Target(client['api_url'], client['api_key'])
        
        result = t.delete(target_id)
        
        if result:
            logger.info(f"删除目标成功: {target_id}")
            return APIResponse(code=200, message="删除成功", data={"target_id": target_id})
        else:
            return APIResponse(code=400, message="删除目标失败", data=None)
            
    except Exception as e:
        logger.error(f"删除目标失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 获取目标详情 ======
@router.get("/target/{target_id}", response_model=APIResponse)
async def get_target_detail(target_id: str):
    """
    获取目标详情
    """
    try:
        client = get_awvs_client()
        t = Target(client['api_url'], client['api_key'])
        
        target_data = t.get(target_id)
        
        if target_data:
            return APIResponse(code=200, message="获取成功", data=target_data)
        else:
            return APIResponse(code=404, message="目标不存在", data=None)
            
    except Exception as e:
        logger.error(f"获取目标详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== 健康检查 ======
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



# ====== 中间件POC扫描相关 ======

class MiddlewareScanRequest(BaseModel):
    url: str
    cve_id: str


class MiddlewareScanStartRequest(BaseModel):
    url: str
    cve_id: str


def POC_Check(url: str, CVE_id: str) -> tuple:
    """
    执行POC检查
    :param url: 目标URL
    :param CVE_id: CVE ID
    :return: (是否漏洞, 消息)
    """
    try:
        parsed = urlparse(url)
        ip = parsed.hostname or parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        CVE_id_clean = CVE_id.replace('-', "_")
        
        # Weblogic
        if CVE_id_clean == "CVE_2020_2551":
            result = cve_2020_2551_poc.poc(url)
        elif CVE_id_clean == "CVE_2018_2628":
            result = cve_2018_2628_poc.poc(ip, port, 0)
        elif CVE_id_clean == "CVE_2018_2894":
            result = cve_2018_2894_poc.poc(url, "weblogic")
        elif CVE_id_clean == "CVE_2020_14756":
            result = cve_2020_14756_poc(url)
        elif CVE_id_clean == "CVE_2023_21839":
            result = cve_2023_21839_poc(url)
        # drupal
        elif CVE_id_clean == "CVE_2018_7600":
            result = cve_2018_7600_poc.poc(url)
        # Tomcat
        elif CVE_id_clean == "CVE_2017_12615":
            result = cve_2017_12615_poc.poc(url)
        elif CVE_id_clean == "CVE_2022_22965":
            result = cve_2022_22965_poc(url)
        elif CVE_id_clean == "CVE_2022_47986":
            result = cve_2022_47986_poc(url)
        # JBoss
        elif CVE_id_clean == "CVE_2017_12149":
            result = cve_2017_12149_poc.poc(url)
        # Nexus
        elif CVE_id_clean == "CVE_2020_10199":
            result = cve_2020_10199_poc.poc(ip, port, "admin")
        # Struts2
        elif CVE_id_clean == "Struts2_009":
            result = struts2_009_poc.poc(url)
        elif CVE_id_clean == "Struts2_032":
            result = struts2_032_poc.poc(url)
        else:
            return False, f"未知的CVE ID: {CVE_id}"
        
        if isinstance(result, tuple):
            return result
        else:
            return result, f"{CVE_id}: 扫描完成"
    except Exception as e:
        logger.error(f"POC检查失败: {str(e)}")
        return False, f"{CVE_id}: 扫描失败 - {str(e)}"


@router.post("/middleware/scan", response_model=APIResponse)
async def middleware_scan(request: MiddlewareScanRequest):
    """
    创建中间件POC扫描任务(插入数据库)
    """
    global middleware_scan_time
    
    try:
        url = request.url
        CVE_id = request.cve_id.replace('-', "_")
        middleware_scan_time = time.time()
        
        # 创建任务记录
        task = await Task.create(
            task_name=f"Middleware POC Scan: {CVE_id}",
            task_type='middleware_poc_scan',
            target=url,
            status='running',
            progress=0,
            config=json.dumps({
                'cve_id': CVE_id,
                'scan_time': middleware_scan_time
            })
        )
        
        logger.info(f"创建中间件扫描任务成功: {url} - {CVE_id}")
        return APIResponse(code=200, message="创建扫描任务成功", data={"task_id": task.id})
    except Exception as e:
        logger.error(f"创建中间件扫描任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/middleware/scan/start", response_model=APIResponse)
async def start_middleware_scan(request: MiddlewareScanStartRequest, background_tasks: BackgroundTasks):
    """
    启动中间件POC扫描(后台任务)
    """
    try:
        url = request.url
        CVE_id = request.cve_id.replace('-', "_")
        
        # 在后台执行扫描
        async def run_middleware_scan():
            try:
                # 等待数据插入成功
                await asyncio.sleep(2)
                
                # 查找运行中的任务
                tasks = await Task.filter(
                    task_type='middleware_poc_scan',
                    target=url,
                    status='running'
                ).all()
                
                for task in tasks:
                    config = json.loads(task.config) if task.config else {}
                    if config.get('cve_id') == CVE_id:
                        # 执行POC检查
                        result, message = await asyncio.to_thread(POC_Check, url, CVE_id)
                        
                        # 更新任务状态
                        task.status = 'completed'
                        task.progress = 100
                        task.result = json.dumps({
                            'vulnerable': result,
                            'message': message
                        })
                        
                        # 如果存在漏洞,创建漏洞记录
                        if result:
                            await Vulnerability.create(
                                task_id=task.id,
                                vuln_type=CVE_id,
                                severity='high',
                                title=f"{CVE_id} 漏洞检测",
                                description=message,
                                url=url,
                                status='open'
                            )
                        
                        await task.save()
                        logger.info(f"中间件扫描完成: {url} - {CVE_id} - 结果: {result}")
                        
            except Exception as e:
                logger.error(f"中间件扫描执行失败: {str(e)}")
        
        background_tasks.add_task(run_middleware_scan)
        
        logger.info(f"启动中间件扫描: {url} - {CVE_id}")
        return APIResponse(code=200, message="扫描任务已启动", data=None)
    except Exception as e:
        logger.error(f"启动中间件扫描失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/middleware/scans", response_model=APIResponse)
async def get_middleware_scans():
    """
    获取所有中间件POC扫描任务
    """
    try:
        tasks = await Task.filter(task_type='middleware_poc_scan').order_by('-created_at').all()
        
        data = []
        for task in tasks:
            scan_data = {
                'id': task.id,
                'task_name': task.task_name,
                'target': task.target,
                'status': task.status,
                'progress': task.progress,
                'created_at': task.created_at.isoformat(),
                'updated_at': task.updated_at.isoformat()
            }
            
            if task.config:
                try:
                    config = json.loads(task.config)
                    scan_data['cve_id'] = config.get('cve_id')
                except:
                    pass
            
            if task.result:
                try:
                    result = json.loads(task.result)
                    scan_data['vulnerable'] = result.get('vulnerable', False)
                    scan_data['message'] = result.get('message', '')
                except:
                    pass
            
            data.append(scan_data)
        
        logger.info(f"获取中间件扫描列表成功,共 {len(data)} 个任务")
        return APIResponse(code=200, message="获取成功", data=data)
    except Exception as e:
        logger.error(f"获取中间件扫描列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/middleware/poc-list", response_model=APIResponse)
async def get_middleware_poc_list():
    """
    获取支持的中间件POC列表
    """
    try:
        poc_list = [
            {
                'cve_id': 'CVE-2020-2551',
                'name': 'WebLogic CVE-2020-2551',
                'description': 'WebLogic Server 反序列化漏洞',
                'severity': '高危',
                'middleware': 'WebLogic'
            },
            {
                'cve_id': 'CVE-2018-2628',
                'name': 'WebLogic CVE-2018-2628',
                'description': 'WebLogic Server 反序列化漏洞',
                'severity': '高危',
                'middleware': 'WebLogic'
            },
            {
                'cve_id': 'CVE-2018-2894',
                'name': 'WebLogic CVE-2018-2894',
                'description': 'WebLogic Server 任意文件上传漏洞',
                'severity': '高危',
                'middleware': 'WebLogic'
            },
            {
                'cve_id': 'CVE-2018-7600',
                'name': 'drupal CVE-2018-7600',
                'description': 'drupal 远程代码执行漏洞',
                'severity': '高危',
                'middleware': 'drupal'
            },
            {
                'cve_id': 'CVE-2017-12615',
                'name': 'Tomcat CVE-2017-12615',
                'description': 'Tomcat 任意文件写入漏洞',
                'severity': '高危',
                'middleware': 'Tomcat'
            },
            {
                'cve_id': 'CVE-2017-12149',
                'name': 'JBoss CVE-2017-12149',
                'description': 'JBoss 反序列化漏洞',
                'severity': '高危',
                'middleware': 'JBoss'
            },
            {
                'cve_id': 'CVE-2020-10199',
                'name': 'Nexus CVE-2020-10199',
                'description': 'Nexus Repository Manager 远程代码执行漏洞',
                'severity': '高危',
                'middleware': 'Nexus'
            },
            {
                'cve_id': 'Struts2-009',
                'name': 'Struts2 S2-009',
                'description': 'Struts2 远程代码执行漏洞',
                'severity': '高危',
                'middleware': 'Struts2'
            },
            {
                'cve_id': 'Struts2-032',
                'name': 'Struts2 S2-032',
                'description': 'Struts2 远程代码执行漏洞',
                'severity': '高危',
                'middleware': 'Struts2'
            }
        ]
        
        logger.info("获取中间件POC列表成功")
        return APIResponse(code=200, message="获取成功", data=poc_list)
    except Exception as e:
        logger.error(f"获取中间件POC列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== AWVS 报告管理相关 ======

REPORT_TEMPLATES = {
    "developer": {
        "id": "11111111-1111-1111-1111-111111111111",
        "name": "Developer（开发人员报告）",
        "description": "详细的技术报告，包含漏洞复现和修复建议"
    },
    "quick": {
        "id": "11111111-1111-1111-1111-111111111112",
        "name": "Quick（快速报告）",
        "description": "精简的快速报告"
    },
    "executive_summary": {
        "id": "11111111-1111-1111-1111-111111111113",
        "name": "Executive Summary（管理层摘要报告）",
        "description": "面向管理层的执行摘要，无技术细节"
    },
    "hipaa": {
        "id": "11111111-1111-1111-1111-111111111114",
        "name": "HIPAA 合规报告",
        "description": "HIPAA 合规性审计报告"
    },
    "affected_items": {
        "id": "11111111-1111-1111-1111-111111111115",
        "name": "Affected Items（受影响项报告）",
        "description": "仅列出受漏洞影响的资产"
    },
    "cwe_2011": {
        "id": "11111111-1111-1111-1111-111111111116",
        "name": "CWE 2011 报告",
        "description": "CWE 分类报告"
    },
    "iso_27001": {
        "id": "11111111-1111-1111-1111-111111111117",
        "name": "ISO 27001 合规报告",
        "description": "ISO 27001 合规报告"
    },
    "nist_SP800_53": {
        "id": "11111111-1111-1111-1111-111111111118",
        "name": "NIST SP800 53 合规报告",
        "description": "NIST 合规报告"
    },
    "owasp_top_10_2013": {
        "id": "11111111-1111-1111-1111-111111111119",
        "name": "OWASP Top 10 2013",
        "description": "OWASP Top10 2013 报告"
    },
    "pci_dss_3.2": {
        "id": "11111111-1111-1111-1111-111111111120",
        "name": "PCI DSS 3.2 合规报告",
        "description": "PCI DSS 支付行业合规报告"
    }
}

REPORT_FORMATS = ["html", "pdf", "json"]


async def generate_ai_analysis_for_report(task_id: int, vulnerabilities: list) -> dict:
    """
    为报告生成AI分析结果
    
    Args:
        task_id: 任务ID
        vulnerabilities: 漏洞列表
    
    Returns:
        AI分析结果字典
    """
    try:
        from langchain_openai import ChatOpenAI
        
        task = await Task.get_or_none(id=task_id)
        if not task:
            return {}
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_types = set()
        
        for vuln in vulnerabilities:
            sev = str(vuln.get('severity', 'info')).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            vuln_types.add(vuln.get('vuln_type', vuln.get('vt_name', 'Unknown')))
        
        prompt = f"""请分析以下Web安全扫描结果并提供专业建议：

扫描目标: {task.target}
扫描时间: {task.created_at.strftime('%Y-%m-%d %H:%M:%S')}

漏洞统计:
- 严重: {severity_counts['critical']} 个
- 高危: {severity_counts['high']} 个
- 中危: {severity_counts['medium']} 个
- 低危: {severity_counts['low']} 个
- 信息: {severity_counts['info']} 个

发现漏洞类型: {', '.join(list(vuln_types)[:10])}

请提供:
1. 整体安全风险评估（简要）
2. 优先修复建议（Top 3）
3. 长期安全改进建议

请用简洁专业的语言回答，不超过500字。"""

        if settings.OPENAI_API_KEY:
            llm = ChatOpenAI(
                model=settings.MODEL_ID,
                temperature=0.7,
                openai_api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL
            )
            
            from langchain_core.messages import HumanMessage, SystemMessage
            messages = [
                SystemMessage(content="你是一位专业的网络安全分析师，擅长Web安全漏洞分析和风险评估。"),
                HumanMessage(content=prompt)
            ]
            
            response = await asyncio.to_thread(llm.invoke, messages)
            ai_content = response.content
            
            return {
                "summary": ai_content,
                "severity_distribution": severity_counts,
                "vuln_types": list(vuln_types),
                "risk_level": "critical" if severity_counts['critical'] > 0 or severity_counts['high'] > 3 else 
                              "high" if severity_counts['high'] > 0 else 
                              "medium" if severity_counts['medium'] > 0 else "low",
                "generated_at": datetime.now().isoformat(),
                "model": settings.MODEL_ID
            }
        
        return {
            "summary": "AI分析服务暂不可用，请检查API配置",
            "severity_distribution": severity_counts,
            "vuln_types": list(vuln_types),
            "risk_level": "unknown",
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"生成AI分析失败: {str(e)}")
        return {
            "summary": f"AI分析生成失败: {str(e)}",
            "error": str(e),
            "generated_at": datetime.now().isoformat()
        }


@router.get("/report/templates", response_model=APIResponse)
async def get_report_templates():
    """
    获取可用的报告模板列表
    """
    try:
        templates = []
        for key, value in REPORT_TEMPLATES.items():
            templates.append({
                "id": key,
                "template_id": value["id"],
                "name": value["name"],
                "description": value["description"]
            })
        
        logger.info("获取报告模板列表成功")
        return APIResponse(code=200, message="获取成功", data={
            "templates": templates,
            "formats": REPORT_FORMATS
        })
    except Exception as e:
        logger.error(f"获取报告模板列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report/generate", response_model=APIResponse)
async def generate_awvs_report(request: AWVSReportGenerateRequest, background_tasks: BackgroundTasks):
    """
    生成AWVS扫描报告并保存到数据库
    
    Args:
        request: 包含task_id, template_id, report_format, enable_ai_analysis
    
    Returns:
        报告ID和状态
    """
    try:
        logger.info(f"[AWVS报告生成] 开始处理 | 任务ID: {request.task_id} | 模板: {request.template_id}")
        
        task = await Task.get_or_none(id=request.task_id).prefetch_related('vulnerabilities')
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        config = json.loads(task.config) if task.config else {}
        scan_id = config.get('scan_id')
        
        if not scan_id:
            raise HTTPException(status_code=400, detail="该任务未关联AWVS扫描ID")
        
        template_info = REPORT_TEMPLATES.get(request.template_id)
        if not template_info:
            raise HTTPException(status_code=400, detail=f"不支持的报告模板: {request.template_id}")
        
        if request.report_format not in REPORT_FORMATS:
            raise HTTPException(status_code=400, detail=f"不支持的报告格式: {request.report_format}")
        
        report_record = await Report.create(
            task_id=task.id,
            report_name=f"AWVS Report - {task.target}",
            report_type=request.report_format,
            content=json.dumps({
                "status": "generating",
                "scan_id": scan_id,
                "template_id": request.template_id,
                "format": request.report_format
            })
        )
        
        async def generate_report_background():
            try:
                client = get_awvs_client()
                awvs_report = AWVSReport(client['api_url'], client['api_key'])
                
                template_uuid = template_info["id"]
                
                generate_data = {
                    "template_id": template_uuid,
                    "source": {
                        "list_type": "scans",
                        "id_list": [scan_id]
                    }
                }
                
                headers = {
                    'X-Auth': client['api_key'],
                    'content-type': 'application/json'
                }
                
                report_api = f"{client['api_url']}/api/v1/reports"
                
                response = await asyncio.to_thread(
                    requests.post,
                    report_api,
                    json=generate_data,
                    headers=headers,
                    verify=False,
                    timeout=60
                )
                
                if response.status_code not in [200, 201]:
                    raise Exception(f"AWVS报告生成失败: HTTP {response.status_code}")
                
                location = response.headers.get('Location', '')
                awvs_report_id = location.split('/')[-1] if location else None
                
                if not awvs_report_id:
                    raise Exception("无法获取AWVS报告ID")
                
                logger.info(f"[AWVS报告生成] AWVS报告ID: {awvs_report_id}")
                
                await asyncio.sleep(5)
                
                download_url = f"{client['api_url']}/reports/download/{awvs_report_id}.{request.report_format}"
                
                report_response = await asyncio.to_thread(
                    requests.get,
                    download_url,
                    headers=headers,
                    verify=False,
                    timeout=120
                )
                
                if report_response.status_code != 200:
                    raise Exception(f"报告下载失败: HTTP {report_response.status_code}")
                
                report_content = report_response.content
                
                reports_dir = os.path.join(settings.UPLOAD_DIR, "awvs_reports")
                os.makedirs(reports_dir, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"awvs_report_{task.id}_{timestamp}.{request.report_format}"
                file_path = os.path.join(reports_dir, filename)
                
                with open(file_path, 'wb') as f:
                    f.write(report_content)
                
                logger.info(f"[AWVS报告生成] 报告文件已保存: {file_path}")
                
                vulnerabilities = await Vulnerability.filter(task_id=task.id).all()
                vuln_list = []
                for v in vulnerabilities:
                    vuln_list.append({
                        "vuln_type": v.vuln_type,
                        "severity": v.severity,
                        "title": v.title,
                        "url": v.url,
                        "description": v.description,
                        "remediation": v.remediation
                    })
                
                ai_analysis_result = None
                if request.enable_ai_analysis:
                    logger.info(f"[AWVS报告生成] 开始AI分析")
                    ai_analysis_result = await generate_ai_analysis_for_report(task.id, vuln_list)
                
                report_data = {
                    "status": "completed",
                    "scan_id": scan_id,
                    "awvs_report_id": awvs_report_id,
                    "template_id": request.template_id,
                    "template_name": template_info["name"],
                    "format": request.report_format,
                    "vulnerabilities": vuln_list,
                    "vulnerability_count": len(vuln_list),
                    "target": task.target,
                    "scan_time": task.created_at.isoformat(),
                    "generated_at": datetime.now().isoformat()
                }
                
                report_record.content = json.dumps(report_data, ensure_ascii=False)
                report_record.file_path = file_path
                if ai_analysis_result:
                    report_record.ai_analysis = json.dumps(ai_analysis_result, ensure_ascii=False)
                    report_record.analyzed_at = datetime.now()
                    report_record.analysis_model = ai_analysis_result.get("model", "unknown")
                await report_record.save()
                
                logger.info(f"[AWVS报告生成] 报告生成完成 | 报告ID: {report_record.id}")
                
            except Exception as e:
                logger.error(f"[AWVS报告生成] 后台任务失败: {str(e)}")
                report_record.content = json.dumps({
                    "status": "failed",
                    "error": str(e)
                })
                await report_record.save()
        
        background_tasks.add_task(generate_report_background)
        
        return APIResponse(
            code=200, 
            message="报告生成任务已启动，请稍后查询", 
            data={
                "report_id": report_record.id,
                "status": "generating"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[AWVS报告生成] 请求处理失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports", response_model=APIResponse)
async def get_all_reports(
    task_id: Optional[int] = None,
    report_type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """
    获取报告列表
    
    Args:
        task_id: 可选，筛选指定任务的报告
        report_type: 可选，筛选指定类型的报告
        limit: 返回数量限制
        offset: 偏移量
    """
    try:
        query = Report.all()
        
        if task_id:
            query = query.filter(task_id=task_id)
        if report_type:
            query = query.filter(report_type=report_type)
        
        total = await query.count()
        reports = await query.order_by('-created_at').limit(limit).offset(offset)
        
        data = []
        for report in reports:
            report_data = {
                "id": report.id,
                "task_id": report.task_id,
                "report_name": report.report_name,
                "report_type": report.report_type,
                "has_file": report.file_path is not None,
                "has_ai_analysis": report.ai_analysis is not None,
                "analyzed_at": report.analyzed_at.isoformat() if report.analyzed_at else None,
                "analysis_model": report.analysis_model,
                "created_at": report.created_at.isoformat(),
                "updated_at": report.updated_at.isoformat()
            }
            
            if report.content:
                try:
                    content = json.loads(report.content)
                    report_data["status"] = content.get("status", "unknown")
                    report_data["vulnerability_count"] = content.get("vulnerability_count", 0)
                    report_data["target"] = content.get("target", "")
                except:
                    report_data["status"] = "unknown"
            
            data.append(report_data)
        
        return APIResponse(
            code=200, 
            message="获取成功", 
            data={
                "total": total,
                "reports": data,
                "limit": limit,
                "offset": offset
            }
        )
    except Exception as e:
        logger.error(f"获取报告列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{report_id}", response_model=APIResponse)
async def get_report_detail(report_id: int):
    """
    获取报告详情
    
    Args:
        report_id: 报告ID
    """
    try:
        report = await Report.get_or_none(id=report_id).prefetch_related('task')
        if not report:
            raise HTTPException(status_code=404, detail="报告不存在")
        
        report_data = {
            "id": report.id,
            "task_id": report.task_id,
            "report_name": report.report_name,
            "report_type": report.report_type,
            "file_path": report.file_path,
            "created_at": report.created_at.isoformat(),
            "updated_at": report.updated_at.isoformat()
        }
        
        if report.content:
            try:
                report_data["content"] = json.loads(report.content)
            except:
                report_data["content"] = report.content
        
        if report.ai_analysis:
            try:
                report_data["ai_analysis"] = json.loads(report.ai_analysis)
            except:
                report_data["ai_analysis"] = report.ai_analysis
        
        if report.analyzed_at:
            report_data["analyzed_at"] = report.analyzed_at.isoformat()
        
        if report.analysis_model:
            report_data["analysis_model"] = report.analysis_model
        
        return APIResponse(code=200, message="获取成功", data=report_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取报告详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{report_id}/download")
async def download_report(report_id: int):
    """
    下载报告文件
    
    Args:
        report_id: 报告ID
    """
    try:
        report = await Report.get_or_none(id=report_id)
        if not report:
            raise HTTPException(status_code=404, detail="报告不存在")
        
        if not report.file_path or not os.path.exists(report.file_path):
            raise HTTPException(status_code=404, detail="报告文件不存在")
        
        file_ext = report.report_type
        filename = f"{report.report_name}.{file_ext}"
        
        with open(report.file_path, 'rb') as f:
            file_content = f.read()
        
        media_types = {
            "html": "text/html",
            "pdf": "application/pdf",
            "json": "application/json"
        }
        media_type = media_types.get(file_ext, "application/octet-stream")
        
        logger.info(f"[AWVS报告下载] 下载报告 | 报告ID: {report_id} | 文件: {filename}")
        
        return StreamingResponse(
            BytesIO(file_content),
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"下载报告失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/report/{report_id}", response_model=APIResponse)
async def delete_report(report_id: int):
    """
    删除报告
    
    Args:
        report_id: 报告ID
    """
    try:
        report = await Report.get_or_none(id=report_id)
        if not report:
            raise HTTPException(status_code=404, detail="报告不存在")
        
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
                logger.info(f"[AWVS报告删除] 删除文件: {report.file_path}")
            except Exception as e:
                logger.warning(f"删除报告文件失败: {str(e)}")
        
        await report.delete()
        
        logger.info(f"[AWVS报告删除] 报告已删除 | 报告ID: {report_id}")
        return APIResponse(code=200, message="删除成功", data={"report_id": report_id})
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除报告失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/{task_id}/report", response_model=APIResponse)
async def get_scan_report(task_id: int):
    """
    获取指定扫描任务的报告
    
    Args:
        task_id: 任务ID
    """
    try:
        task = await Task.get_or_none(id=task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        
        reports = await Report.filter(task_id=task_id).order_by('-created_at').all()
        
        if not reports:
            return APIResponse(
                code=200, 
                message="该任务暂无报告", 
                data={
                    "task_id": task_id,
                    "reports": [],
                    "has_report": False
                }
            )
        
        data = []
        for report in reports:
            report_data = {
                "id": report.id,
                "report_name": report.report_name,
                "report_type": report.report_type,
                "has_file": report.file_path is not None,
                "has_ai_analysis": report.ai_analysis is not None,
                "created_at": report.created_at.isoformat()
            }
            
            if report.content:
                try:
                    content = json.loads(report.content)
                    report_data["status"] = content.get("status", "unknown")
                    report_data["vulnerability_count"] = content.get("vulnerability_count", 0)
                except:
                    pass
            
            data.append(report_data)
        
        return APIResponse(
            code=200, 
            message="获取成功", 
            data={
                "task_id": task_id,
                "reports": data,
                "has_report": True,
                "total": len(data)
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取扫描报告失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))



