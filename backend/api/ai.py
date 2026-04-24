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
你是一个专业的Web安全顾问,名为WebScan AI。你的任务是帮助用户解决Web安全相关问题,包括漏洞分析、安全加固建议、扫描报告解读等。

你的专业领域包括但不限于:
- OWASP Top 10 漏洞(SQL注入、XSS、CSRF、文件上传等)
- 常见Web框架漏洞(Spring、Struts2、ThinkPHP、WordPress等)
- 网络安全扫描与渗透测试
- 安全加固与最佳实践
- 漏洞修复方案与代码审计

你需要:
1. 提供专业、准确的安全建议,基于最新的安全研究和CVE数据库
2. 解释技术概念时要清晰易懂,根据用户的背景调整解释深度
3. 针对用户的具体问题给出具体、可执行的解决方案
4. 保持友好、专业的语气,同时保持客观中立
5. 当用户提供扫描报告或漏洞信息时,进行深入分析,包括:
   - 漏洞的危害程度评估
   - 可能的攻击场景和影响范围
   - 详细的修复建议和代码示例
   - 预防措施和安全加固建议
6. 如果问题涉及敏感操作,提醒用户遵守法律法规和道德准则
7. 对于不确定的问题,诚实说明并建议用户参考官方文档或寻求专业帮助

回答格式要求:
- 使用清晰的段落结构,适当使用列表和代码块
- 对于技术术语,首次出现时提供简要解释
- 提供的代码示例要完整且经过验证
- 重要信息使用加粗或特殊标记突出显示
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
