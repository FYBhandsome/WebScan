"""
AI 对话 API 路由

提供 AI 对话功能,支持创建对话实例、发送消息、获取历史等。
使用 LangChain 和 AI模型实现智能对话。
使用 LangChain 0.3.x 的消息历史管理进行对话记忆。

主要功能:
- 创建和管理对话实例
- 发送消息并获取 AI 响应
- 对话历史记录查询
- 对话记忆管理
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from uuid import UUID, uuid4
from tortoise.expressions import Q
from datetime import datetime
import logging

from backend.models import AIChatInstance, AIChatMessage
from backend.config import settings
from backend.api.common import APIResponse
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.chat_history import InMemoryChatMessageHistory
from langchain_core.messages import HumanMessage, AIMessage

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI对话"])

_llm = None

def get_llm():
    global _llm
    if _llm is None:
        _llm = ChatOpenAI(
            model=settings.MODEL_ID,
            temperature=0.7,
            openai_api_key=settings.OPENAI_API_KEY,
            base_url=settings.OPENAI_BASE_URL,
            streaming=True
        )
    return _llm

SYSTEM_PROMPT = """
# Role
你是WebScan AI，一位专业的Web安全顾问。你拥有丰富的渗透测试、漏洞分析和安全加固经验，致力于帮助用户解决Web安全问题。

# Expertise Areas
- OWASP Top 10漏洞分析与防护（SQL注入、XSS、CSRF、文件上传、SSRF等）
- 常见Web框架漏洞（Spring Boot、Struts2、ThinkPHP、WordPress、Drupal、Joomla等）
- 网络安全扫描与渗透测试方法论
- 安全加固与最佳实践建议
- 漏洞修复方案与代码审计
- CVE漏洞分析与POC验证

# Response Guidelines

## 1. 专业性要求
- 提供准确、基于最新安全研究的专业建议
- 引用具体的CVE编号或安全标准（如OWASP、CWE）增强可信度
- 对不确定的问题诚实说明，建议查阅官方文档

## 2. 沟通风格
- 根据用户背景调整技术深度：对新手详细解释，对专家直接给方案
- 使用清晰的结构：问题分析 → 影响评估 → 解决方案 → 预防措施
- 重要信息使用**加粗**标记，代码使用```代码块```

## 3. 漏洞分析流程
当用户提供扫描报告或漏洞信息时，按以下结构响应：
1. **漏洞概述**：漏洞类型、严重程度、影响范围
2. **危害分析**：可能的攻击场景、潜在影响
3. **修复方案**：具体的代码示例和配置修改
4. **预防措施**：安全编码建议和最佳实践

## 4. 安全合规
- 涉及敏感操作时提醒用户遵守法律法规
- 不提供恶意利用代码，仅提供防御性建议
- 强调授权测试的重要性

# Example Interactions

## Example 1: 漏洞咨询
用户: "发现一个SQL注入漏洞，怎么修复？"
助手: 
**漏洞概述**: SQL注入(CWE-89)是一种严重的安全漏洞，攻击者可通过构造恶意输入执行任意SQL命令。

**危害分析**:
- 数据泄露：可获取数据库全部数据
- 权限提升：可能获取数据库管理员权限
- 系统控制：某些情况下可执行系统命令

**修复方案**:
```python
# 错误示例 - 直接拼接
query = "SELECT * FROM users WHERE id = " + user_input

# 正确示例 - 参数化查询
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
```

**预防措施**:
1. 所有数据库查询使用参数化语句
2. 输入验证：白名单过滤
3. 最小权限原则：数据库账户仅授予必要权限

## Example 2: 扫描报告解读
用户: "扫描报告显示有XSS漏洞，严重吗？"
助手:
**漏洞评估**: XSS（跨站脚本）漏洞严重程度取决于类型：
- **存储型XSS**: 高危，影响所有访问用户
- **反射型XSS**: 中高危，需要诱导用户点击
- **DOM型XSS**: 中危，依赖前端处理

**建议**: 请提供具体的XSS类型和触发位置，我可以给出针对性的修复方案。

# Response Format
- 使用清晰的段落结构和列表
- 技术术语首次出现时提供简要解释
- 代码示例完整且可直接使用
- 复杂问题分步骤解答
"""

# 对话历史缓存
conversation_history_cache: Dict[str, InMemoryChatMessageHistory] = {}


async def get_or_create_history(chat_instance_id: UUID) -> InMemoryChatMessageHistory:
    """
    获取或创建对话历史
    
    从缓存中获取对话历史,如果不存在则创建新的历史对象并加载历史消息。
    
    Args:
        chat_instance_id: 对话实例 ID
        
    Returns:
        InMemoryChatMessageHistory: 对话历史对象,包含历史对话内容
    """
    chat_id = str(chat_instance_id)
    
    if chat_id not in conversation_history_cache:
        history = InMemoryChatMessageHistory()
        
        # 加载历史消息到历史中
        history_messages = await AIChatMessage.filter(
            chat_instance_id=chat_instance_id
        ).order_by("created_at")
        
        for msg in history_messages:
            if msg.role == "user":
                history.add_message(HumanMessage(content=msg.content))
            elif msg.role == "assistant":
                history.add_message(AIMessage(content=msg.content))
        
        conversation_history_cache[chat_id] = history
        logger.info(f"✅ 创建对话历史: {chat_id}")
    
    return conversation_history_cache[chat_id]


async def clear_history(chat_instance_id: UUID):
    """
    清除对话历史
    
    从缓存中删除指定对话实例的历史对象。
    
    Args:
        chat_instance_id: 对话实例 ID
    """
    chat_id = str(chat_instance_id)
    if chat_id in conversation_history_cache:
        del conversation_history_cache[chat_id]
        logger.info(f"✅ 清除对话历史: {chat_id}")


@router.post("/chat/instances", response_model=APIResponse)
async def create_chat_instance(
    chat_name: Optional[str] = None,
    chat_type: Optional[str] = "general",
    user_id: Optional[str] = None
):
    """
    创建新的对话实例
    
    创建一个新的对话会话,并初始化对话历史。
    
    Args:
        chat_name: 对话名称,如果不提供则自动生成
        chat_type: 对话类型,默认为 'general'
        user_id: 用户 ID,可选
        
    Returns:
        Dict: 包含对话实例信息的响应,结构如下:
            {
                "code": 200,
                "message": "对话实例创建成功",
                "data": {
                    "chat_instance_id": "对话ID",
                    "chat_name": "对话名称",
                    "chat_type": "对话类型",
                    "created_at": "创建时间",
                    "updated_at": "更新时间"
                }
            }
        
    Raises:
        HTTPException: 创建失败时抛出 500 错误
        
    Examples:
        >>> 创建新对话
        >>> POST /chat/instances
        >>> {
        ...     "chat_name": "漏洞分析",
        ...     "chat_type": "vulnerability",
        ...     "user_id": "user123"
        ... }
    """
    try:
        chat_instance = await AIChatInstance.create(
            id=uuid4(),
            user_id=user_id,
            chat_name=chat_name or f"新对话_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            chat_type=chat_type,
            status="active"
        )
        
        # 初始化对话历史
        await get_or_create_history(chat_instance.id)
        
        logger.info(f"✅ 创建对话实例: {chat_instance.id}")
        
        return {
            "code": 200,
            "message": "对话实例创建成功",
            "data": {
                "chat_instance_id": str(chat_instance.id),
                "chat_name": chat_instance.chat_name,
                "chat_type": chat_instance.chat_type,
                "created_at": chat_instance.created_at,
                "updated_at": chat_instance.updated_at
            }
        }
    except Exception as e:
        logger.error(f"❌ 创建对话实例失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"创建对话实例失败: {str(e)}")


@router.get("/chat/instances", response_model=APIResponse)
async def list_chat_instances(
    user_id: Optional[str] = None,
    status: Optional[str] = "active",
    page: int = 1,
    page_size: int = 20
):
    """
    列出对话实例
    
    获取对话实例列表,支持按用户 ID 和状态过滤,以及分页查询。
    
    Args:
        user_id: 用户 ID,用于过滤
        status: 对话状态,默认为 'active'
        page: 页码,从 1 开始
        page_size: 每页数量
        
    Returns:
        Dict: 包含对话实例列表的响应,结构如下:
            {
                "code": 200,
                "message": "查询对话实例成功",
                "data": {
                    "items": [...],
                    "total": 总数,
                    "page": 当前页,
                    "page_size": 每页数量,
                    "total_pages": 总页数
                }
            }
        
    Raises:
        HTTPException: 查询失败时抛出 500 错误
        
    Examples:
        >>> 获取所有活跃对话
        >>> GET /chat/instances?status=active
    """
    try:
        query = Q()
        if user_id:
            query &= Q(user_id=user_id)
        if status:
            query &= Q(status=status)
        
        instances = await AIChatInstance.filter(query) \
            .order_by("-updated_at") \
            .offset((page - 1) * page_size) \
            .limit(page_size)
        
        total = await AIChatInstance.filter(query).count()
        
        instance_list = []
        for instance in instances:
            # 获取最新一条消息
            latest_message = await AIChatMessage.filter(
                chat_instance_id=instance.id
            ).order_by("-created_at").first()
            
            instance_list.append({
                "chat_instance_id": str(instance.id),
                "chat_name": instance.chat_name,
                "chat_type": instance.chat_type,
                "status": instance.status,
                "created_at": instance.created_at,
                "updated_at": instance.updated_at,
                "latest_message": {
                    "role": latest_message.role if latest_message else None,
                    "content": latest_message.content[:100] if latest_message else None,
                    "created_at": latest_message.created_at if latest_message else None
                } if latest_message else None
            })
        
        return {
            "code": 200,
            "message": "查询对话实例成功",
            "data": {
                "items": instance_list,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size
            }
        }
    except Exception as e:
        logger.error(f"❌ 查询对话实例失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"查询对话实例失败: {str(e)}")


class SimpleChatRequest(BaseModel):
    """简单聊天请求模型"""
    message: str
    context: Optional[Dict[str, Any]] = None


@router.post("/chat", response_model=Dict[str, Any])
async def simple_chat(request: SimpleChatRequest):
    """
    简单聊天接口
    
    直接发送消息并获取AI响应，不需要创建对话实例。
    适用于前端悬浮球AI对话功能。
    
    Args:
        request: 聊天请求，包含消息内容和可选的上下文
        
    Returns:
        Dict: 包含AI响应的回复，结构如下:
            {
                "code": 200,
                "message": "对话成功",
                "data": {
                    "response": "AI回复内容",
                    "model": "使用的模型",
                    "tokens_used": 使用的token数
                }
            }
        
    Raises:
        HTTPException: 当API密钥未配置或调用失败时抛出错误
        
    Examples:
        >>> 简单对话
        >>> POST /chat
        >>> {
        ...     "message": "请帮我分析SQL注入漏洞",
        ...     "context": {}
        ... }
    """
    try:
        if not settings.OPENAI_API_KEY:
            raise HTTPException(
                status_code=500,
                detail="AI API密钥未配置，请在.env文件中设置OPENAI_API_KEY"
            )
        
        logger.info(f"收到简单聊天请求: {request.message[:50]}...")
        
        # 使用LangChain调用AI
        from langchain_core.messages import HumanMessage
        
        messages = [HumanMessage(content=request.message)]
        
        response = await get_llm().ainvoke(messages)
        
        ai_response = response.content
        
        logger.info(f"✅ AI响应成功: {ai_response[:50]}...")
        
        return {
            "code": 200,
            "message": "对话成功",
            "data": {
                "response": ai_response,
                "model": settings.MODEL_ID,
                "tokens_used": getattr(response, 'response_metadata', {}).get('total_tokens', 0)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ 简单对话失败: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"AI对话失败: {str(e)}"
        )


@router.get("/connection-status", response_model=Dict[str, Any])
async def get_ai_connection_status():
    """
    获取AI连接状态
    
    检查AI模型连接配置和连接状态。
    
    Returns:
        Dict: 包含AI连接状态的响应，结构如下:
            {
                "code": 200,
                "message": "获取状态成功",
                "data": {
                    "configured": true/false,
                    "api_key_set": true/false,
                    "base_url": "API基础URL",
                    "model_id": "模型ID",
                    "connection_test": "success/failed",
                    "error_message": "错误信息（如果有）"
                }
            }
    """
    status_data = {
        "configured": False,
        "api_key_set": False,
        "base_url": settings.OPENAI_BASE_URL,
        "model_id": settings.MODEL_ID,
        "connection_test": "not_tested",
        "error_message": None
    }
    
    if settings.OPENAI_API_KEY:
        status_data["api_key_set"] = True
        status_data["configured"] = True
        
        try:
            logger.info("🔍 测试AI连接...")
            from langchain_core.messages import HumanMessage
            
            test_response = await get_llm().ainvoke([
                HumanMessage(content="你好，请回复'连接成功'")
            ])
            
            if test_response and test_response.content:
                status_data["connection_test"] = "success"
                status_data["test_response"] = test_response.content[:100]
                logger.info(f"✅ AI连接测试成功: {test_response.content[:50]}")
            else:
                status_data["connection_test"] = "failed"
                status_data["error_message"] = "AI响应为空"
                logger.warning("⚠️ AI连接测试失败: 响应为空")
                
        except Exception as e:
            status_data["connection_test"] = "failed"
            status_data["error_message"] = str(e)
            logger.error(f"❌ AI连接测试失败: {str(e)}")
    else:
        status_data["error_message"] = "OPENAI_API_KEY未配置"
        logger.warning("⚠️ OPENAI_API_KEY未配置")
    
    return {
        "code": 200,
        "message": "获取AI连接状态成功",
        "data": status_data
    }


@router.post("/test-analysis", response_model=Dict[str, Any])
async def test_ai_analysis():
    """
    测试AI分析功能
    
    执行一个简单的AI分析测试，验证分析流程是否正常工作。
    
    Returns:
        Dict: 包含测试结果的响应
    """
    try:
        from backend.ai_agents.analyzers.ai_analyzer import AIAnalyzer
        
        logger.info("🧪 开始测试AI分析功能...")
        
        analyzer = AIAnalyzer()
        
        test_vulnerabilities = [
            {
                "id": "test-001",
                "title": "测试SQL注入漏洞",
                "vuln_type": "SQLInjection",
                "severity": "high",
                "url": "https://test.example.com/api/users?id=1",
                "description": "测试描述"
            }
        ]
        
        test_tool_results = {
            "port_scan": {"open_ports": [80, 443]},
            "vuln_scan": {"vulnerabilities_found": 1}
        }
        
        test_target_context = {
            "target": "https://test.example.com",
            "domain": "test.example.com"
        }
        
        result = await analyzer.analyze_scan_results(
            test_vulnerabilities,
            test_tool_results,
            test_target_context
        )
        
        logger.info("✅ AI分析测试完成")
        
        return {
            "code": 200,
            "message": "AI分析测试成功",
            "data": {
                "test_passed": True,
                "result": result.to_dict() if hasattr(result, 'to_dict') else str(result),
                "analyzer_status": {
                    "llm_client_available": analyzer.llm_client is not None,
                    "model_id": getattr(analyzer, 'model_id', None)
                }
            }
        }
        
    except Exception as e:
        logger.error(f"❌ AI分析测试失败: {str(e)}")
        return {
            "code": 500,
            "message": f"AI分析测试失败: {str(e)}",
            "data": {
                "test_passed": False,
                "error": str(e)
            }
        }


async def process_chat_message(chat_instance_id: str, message: str) -> Dict[str, Any]:
    """
    处理 WebSocket 聊天消息
    
    Args:
        chat_instance_id: 对话实例 ID
        message: 用户消息
        
    Returns:
        Dict: 包含响应内容的字典
    """
    try:
        from uuid import UUID
        
        if not chat_instance_id:
            chat_instance = await AIChatInstance.create(
                id=uuid4(),
                chat_name="新对话",
                chat_type="general",
                status="active"
            )
            chat_instance_id = str(chat_instance.id)
        else:
            try:
                chat_instance = await AIChatInstance.get(id=UUID(chat_instance_id))
            except:
                chat_instance = await AIChatInstance.create(
                    id=uuid4(),
                    chat_name="新对话",
                    chat_type="general",
                    status="active"
                )
                chat_instance_id = str(chat_instance.id)
        
        user_message = await AIChatMessage.create(
            chat_instance_id=chat_instance_id,
            role="user",
            content=message,
            message_type="text"
        )
        
        history = await get_or_create_history(UUID(chat_instance_id))
        history.add_message(HumanMessage(content=message))
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            MessagesPlaceholder(variable_name="history"),
            ("human", "{input}")
        ])
        
        history_messages = await history.aget_messages()
        
        chain = prompt | get_llm()
        response = await chain.ainvoke({
            "history": history_messages,
            "input": message
        })
        
        response_content = response.content
        history.add_message(AIMessage(content=response_content))
        
        ai_message = await AIChatMessage.create(
            chat_instance_id=chat_instance_id,
            role="assistant",
            content=response_content,
            message_type="text"
        )
        
        chat_instance.updated_at = datetime.now()
        await chat_instance.save()
        
        return {
            "content": response_content,
            "chat_instance_id": chat_instance_id,
            "message_id": ai_message.id
        }
        
    except Exception as e:
        logger.error(f"❌ 处理聊天消息失败: {str(e)}")
        return {
            "content": f"抱歉，处理消息时发生错误: {str(e)}",
            "error": str(e)
        }


async def get_chat_history(chat_instance_id: str) -> List[Dict[str, Any]]:
    """
    获取聊天历史
    
    Args:
        chat_instance_id: 对话实例 ID
        
    Returns:
        List: 消息历史列表
    """
    try:
        from uuid import UUID
        
        if not chat_instance_id:
            return []
            
        messages = await AIChatMessage.filter(
            chat_instance_id=UUID(chat_instance_id)
        ).order_by("created_at")
        
        return [
            {
                "id": msg.id,
                "role": msg.role,
                "content": msg.content,
                "created_at": msg.created_at.isoformat() if msg.created_at else None
            }
            for msg in messages
        ]
        
    except Exception as e:
        logger.error(f"❌ 获取聊天历史失败: {str(e)}")
        return []
