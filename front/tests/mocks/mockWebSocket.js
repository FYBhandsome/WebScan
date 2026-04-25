export const mockWebSocket = {
  connect: () => {
    console.log('Mock WebSocket connected')
    return {
      send: (message) => console.log('Mock send:', message),
      close: () => console.log('Mock WebSocket closed'),
      onmessage: null,
      onopen: null,
      onclose: null,
      onerror: null
    }
  },
  
  messages: {
    taskUpdate: {
      type: 'task:update',
      payload: {
        task_id: 'task-123',
        status: 'running',
        progress: 50,
        message: '正在扫描...'
      }
    },
    
    taskProgress: {
      type: 'task:progress',
      payload: {
        task_id: 'task-123',
        current_step: 3,
        total_steps: 10,
        step_name: '端口扫描'
      }
    },
    
    taskCompleted: {
      type: 'task:completed',
      payload: {
        task_id: 'task-123',
        status: 'completed',
        result: {
          vulnerabilities: 5,
          scan_time: 120
        }
      }
    },
    
    taskFailed: {
      type: 'task:failed',
      payload: {
        task_id: 'task-123',
        error: '扫描超时',
        details: '目标服务器响应超时'
      }
    },
    
    stageUpdate: {
      type: 'stage:update',
      payload: {
        task_id: 'task-123',
        stage: 'info_collection',
        data: {
          status: 'completed',
          duration: 30.5
        }
      }
    },
    
    subgraphProgress: {
      type: 'subgraph:progress',
      payload: {
        task_id: 'task-123',
        subgraph_type: 'planning',
        status: 'running',
        progress: 50
      }
    },
    
    toolExecution: {
      type: 'tool:execution',
      payload: {
        task_id: 'task-123',
        tool_name: 'nmap',
        status: 'running',
        output: 'Starting Nmap scan...'
      }
    },
    
    vulnerabilityFound: {
      type: 'vulnerability_found',
      payload: {
        task_id: 'task-123',
        vulnerability: {
          name: 'XSS漏洞',
          severity: 'high',
          url: 'http://example.com/search?q=test'
        }
      }
    },
    
    aiMessage: {
      type: 'ai_message',
      payload: {
        conversation_id: 'conv-123',
        message: '我正在分析目标...',
        type: 'text'
      }
    },
    
    aiProgress: {
      type: 'progress',
      payload: {
        stage: '信息收集',
        progress: 30,
        details: '正在收集子域名信息'
      }
    }
  }
}

export default mockWebSocket
