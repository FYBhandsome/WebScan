export const mockApi = {
  kb: {
    getVulnerabilities: () => ({
      code: 200,
      message: '获取成功',
      data: [
        {
          id: 1,
          name: 'SQL注入漏洞',
          severity: 'high',
          description: '存在SQL注入漏洞',
          solution: '使用参数化查询',
          references: ['https://owasp.org'],
          created_at: '2024-01-01T00:00:00'
        }
      ]
    }),
    
    searchFromSeebug: () => ({
      code: 200,
      message: '搜索成功',
      data: {
        total: 10,
        page: 1,
        page_size: 20,
        items: [
          {
            ssvid: 'SSVID-12345',
            name: 'CVE-2020-1234',
            type: 'SQL注入',
            level: '高危',
            publish_time: '2024-01-01'
          }
        ]
      }
    })
  },
  
  settings: {
    getSettings: () => ({
      code: 200,
      message: '获取成功',
      data: {
        general: {
          systemName: 'WebScan AI',
          language: 'zh-CN'
        },
        scan: {
          defaultDepth: 2,
          defaultConcurrency: 5
        }
      }
    }),
    
    getSystemInfo: () => ({
      code: 200,
      message: '获取成功',
      data: {
        version: '1.0.0',
        platform: {
          system: 'Windows',
          release: '10'
        },
        uptime: '10天 5小时 30分钟',
        resources: {
          cpu: { usage: '45%' },
          memory: { usage: '60%' }
        }
      }
    })
  },
  
  tasks: {
    getTasks: () => ({
      code: 200,
      message: '获取成功',
      data: {
        total: 5,
        items: [
          {
            id: 1,
            name: '扫描任务-1',
            status: 'completed',
            target: 'http://example.com',
            created_at: '2024-01-01T00:00:00'
          }
        ]
      }
    }),
    
    getTask: (id) => ({
      code: 200,
      message: '获取成功',
      data: {
        id: id,
        name: '扫描任务-1',
        status: 'completed',
        target: 'http://example.com',
        progress: 100,
        created_at: '2024-01-01T00:00:00',
        completed_at: '2024-01-01T01:00:00'
      }
    })
  },
  
  ai: {
    chat: () => ({
      code: 200,
      message: '成功',
      data: {
        response: '这是AI的回复内容',
        conversation_id: 'conv-123'
      }
    })
  },
  
  aiAgents: {
    startScan: () => ({
      code: 200,
      message: '任务创建成功',
      data: {
        task_id: 1,
        status: 'pending',
        target: 'http://example.com',
        created_at: '2024-01-01T00:00:00Z'
      }
    }),
    
    getTask: (id) => ({
      code: 200,
      message: '获取成功',
      data: {
        id: id,
        target: 'http://example.com',
        status: 'running',
        progress: 50,
        created_at: '2024-01-01T00:00:00Z'
      }
    }),
    
    getTasks: () => ({
      code: 200,
      message: '获取成功',
      data: {
        tasks: [
          {
            id: 1,
            target: 'http://example.com',
            status: 'completed',
            progress: 100,
            created_at: '2024-01-01T00:00:00Z'
          }
        ],
        total: 1,
        page: 1,
        page_size: 10
      }
    }),
    
    getTools: () => ({
      code: 200,
      message: '获取成功',
      data: {
        tools: [
          { name: 'nmap', description: '端口扫描工具' },
          { name: 'sqlmap', description: 'SQL注入检测工具' }
        ]
      }
    }),
    
    getConfig: () => ({
      code: 200,
      message: '获取成功',
      data: {
        max_concurrent_tasks: 5,
        default_timeout: 300,
        ai_model: 'gpt-4'
      }
    }),
    
    generateReport: () => ({
      code: 200,
      message: '报告生成成功',
      data: {
        report_id: 1,
        status: 'completed',
        download_url: '/api/ai_agents/reports/1/download'
      }
    }),
    
    executePOC: () => ({
      code: 200,
      message: 'POC执行成功',
      data: {
        execution_id: 1,
        status: 'completed',
        result: {
          vulnerable: true,
          details: '存在漏洞'
        }
      }
    })
  }
}

export default mockApi
