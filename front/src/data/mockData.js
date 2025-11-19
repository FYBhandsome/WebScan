// TODO: 替换为真实的后端API数据
// 这些是模拟数据，用于前端开发和测试

// 扫描任务数据
export const mockScanTasks = [
  {
    id: 1,
    name: '电商网站安全扫描',
    targetUrl: 'https://shop.example.com',
    status: 'completed', // waiting, running, completed, failed
    priority: 'high', // low, medium, high, critical
    scanType: '深度扫描',
    startTime: '2024-11-17 14:30',
    endTime: '2024-11-17 16:45',
    progress: 100,
    vulnerabilityCount: {
      high: 3,
      medium: 8,
      low: 12,
      total: 23
    }
  },
  {
    id: 2,
    name: '企业官网检测',
    targetUrl: 'https://company.example.com',
    status: 'running',
    priority: 'medium',
    scanType: '快速扫描',
    startTime: '2024-11-17 16:00',
    endTime: null,
    progress: 65,
    vulnerabilityCount: null
  },
  {
    id: 3,
    name: 'API接口安全测试',
    targetUrl: 'https://api.example.com/v1/users',
    status: 'waiting',
    priority: 'critical',
    scanType: '自定义规则',
    startTime: '2024-11-17 18:00',
    endTime: null,
    progress: 0,
    vulnerabilityCount: null
  },
  {
    id: 4,
    name: '管理后台扫描',
    targetUrl: 'https://admin.example.com/dashboard',
    status: 'failed',
    priority: 'high',
    scanType: '深度扫描',
    startTime: '2024-11-17 10:15',
    endTime: '2024-11-17 10:18',
    progress: 15,
    vulnerabilityCount: null,
    errorMessage: '目标服务器连接超时'
  }
]

// 漏洞数据
export const mockVulnerabilities = [
  {
    id: 1,
    taskId: 1,
    title: 'SQL注入漏洞 - 用户登录接口',
    type: 'sql-injection',
    priority: 'high',
    severity: 'critical',
    description: '在用户登录接口发现SQL注入漏洞，攻击者可能通过构造恶意SQL语句绕过身份验证或获取数据库敏感信息。该漏洞位于登录验证逻辑中，未对用户输入进行充分的参数化查询处理。',
    technicalDetails: '漏洞出现在 /api/login 接口的用户名验证逻辑中。应用程序直接将用户输入拼接到SQL查询语句中，没有使用预编译语句或参数绑定，导致攻击者可以注入恶意SQL代码。',
    location: '/api/login',
    method: 'POST',
    parameter: 'username',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    impact: '数据泄露、身份验证绕过',
    discoveredAt: '2024-11-17 15:23',
    status: 'unfixed', // unfixed, fixed, false-positive
    payload: `username: admin' OR '1'='1' --\npassword: anything`,
    response: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "success": true,\n  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",\n  "user": {\n    "id": 1,\n    "username": "admin",\n    "role": "administrator"\n  }\n}`,
    references: [
      'https://owasp.org/www-project-top-ten/2017/A1_2017-Injection',
      'https://cwe.mitre.org/data/definitions/89.html'
    ]
  },
  {
    id: 2,
    taskId: 1,
    title: '跨站脚本攻击 - 评论功能',
    type: 'xss',
    priority: 'medium',
    severity: 'high',
    description: '评论功能未对用户输入进行充分过滤，存在存储型XSS漏洞，攻击者可以注入恶意脚本代码。',
    technicalDetails: '在产品评论提交接口中，用户输入的评论内容直接存储到数据库并在页面上显示，未进行HTML编码或内容过滤。',
    location: '/product/comment',
    method: 'POST',
    parameter: 'content',
    cvssScore: 6.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
    impact: '会话劫持、钓鱼攻击',
    discoveredAt: '2024-11-17 15:45',
    status: 'unfixed',
    payload: `<script>alert('XSS')</script>`,
    response: `评论已发布成功`,
    references: [
      'https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)',
      'https://cwe.mitre.org/data/definitions/79.html'
    ]
  },
  {
    id: 3,
    taskId: 1,
    title: '文件上传漏洞 - 头像上传',
    type: 'file-upload',
    priority: 'high',
    severity: 'critical',
    description: '头像上传功能未对文件类型进行严格验证，可能被上传恶意脚本文件。',
    technicalDetails: '文件上传接口仅检查文件扩展名，未验证文件内容和MIME类型，攻击者可以上传PHP、JSP等可执行文件。',
    location: '/user/avatar',
    method: 'POST',
    parameter: 'avatar',
    cvssScore: 8.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    impact: '远程代码执行',
    discoveredAt: '2024-11-17 16:12',
    status: 'fixed',
    payload: `shell.php`,
    response: `文件上传成功`,
    references: [
      'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
      'https://cwe.mitre.org/data/definitions/434.html'
    ]
  }
]

// 仪表盘统计数据
export const mockDashboardStats = {
  todayScans: 12,
  highRiskVulns: 5,
  weeklyTrend: -15, // 负数表示下降，正数表示上升
  completedScans: 89,
  totalTasks: 156,
  activeScans: 3
}

// 漏洞趋势数据
export const mockTrendData = [
  { date: '11-11', high: 3, medium: 5, low: 8 },
  { date: '11-12', high: 2, medium: 7, low: 6 },
  { date: '11-13', high: 4, medium: 3, low: 9 },
  { date: '11-14', high: 1, medium: 6, low: 7 },
  { date: '11-15', high: 5, medium: 4, low: 5 },
  { date: '11-16', high: 2, medium: 8, low: 6 },
  { date: '11-17', high: 3, medium: 5, low: 7 }
]

// 最新扫描结果
export const mockRecentScans = [
  {
    id: 1,
    name: '电商网站安全扫描',
    url: 'https://shop.example.com',
    time: '2小时前',
    status: 'completed',
    vulnerabilities: { high: 2, medium: 5, low: 8 }
  },
  {
    id: 2,
    name: '企业官网检测',
    url: 'https://company.example.com',
    time: '4小时前',
    status: 'running',
    vulnerabilities: null
  },
  {
    id: 3,
    name: 'API接口安全测试',
    url: 'https://api.example.com',
    time: '6小时前',
    status: 'completed',
    vulnerabilities: { high: 0, medium: 3, low: 2 }
  }
]

// AI分析数据
export const mockAIAnalysis = {
  riskAssessment: '本次扫描发现多个高危漏洞，特别是SQL注入和身份验证绕过漏洞需要立即修复。整体安全风险等级为"高"。',
  keyFindings: [
    '发现3个高危漏洞，其中SQL注入漏洞风险最高',
    '用户输入验证机制存在多处缺陷',
    '身份验证和授权机制需要加强',
    '文件上传功能安全控制不足'
  ],
  recommendations: '建议立即修复所有高危漏洞，加强输入验证和输出编码，实施严格的身份验证机制，并定期进行安全测试。',
  priorityReason: '该漏洞被评为高危是因为它允许攻击者完全绕过身份验证机制，直接以管理员身份登录系统。这种攻击可能导致整个系统被完全控制，包括用户数据泄露、系统配置修改等严重后果。',
  riskCorrelation: '该SQL注入模式与2023年某知名电商平台的安全事件相似，当时攻击者利用类似漏洞获取了数百万用户的敏感信息。建议立即修复以避免类似风险。',
  falsePositive: false,
  fpReason: '经过验证，该漏洞确实存在且可被利用。测试显示攻击者可以成功绕过登录验证并获取管理员权限。'
}

// 修复建议步骤
export const mockFixSteps = [
  {
    title: '使用参数化查询',
    description: '将所有SQL查询改为使用预编译语句和参数绑定，避免直接拼接用户输入。',
    code: `// 修复前（有漏洞）\nString query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";\n\n// 修复后（安全）\nString query = "SELECT * FROM users WHERE username=? AND password=?";\nPreparedStatement stmt = connection.prepareStatement(query);\nstmt.setString(1, username);\nstmt.setString(2, password);`
  },
  {
    title: '输入验证和过滤',
    description: '对所有用户输入进行严格的验证和过滤，拒绝包含SQL关键字的输入。',
    code: `// 输入验证示例\nif (username.matches(".*[';\"\\\\-\\\\-].*")) {\n    throw new SecurityException("Invalid characters in username");\n}`
  },
  {
    title: '最小权限原则',
    description: '确保数据库连接使用的账户只具有必要的最小权限，限制潜在损害。'
  },
  {
    title: '安全测试',
    description: '部署修复后进行全面的安全测试，确保漏洞已被完全修复且不影响正常功能。'
  }
]

// 报告数据
export const mockReports = [
  {
    id: 1,
    name: '电商网站安全扫描报告',
    taskName: '电商网站安全扫描',
    taskId: 1,
    format: 'pdf',
    size: '2.3 MB',
    createdAt: '2024-11-17 16:45',
    downloadUrl: '/api/reports/1/download'
  },
  {
    id: 2,
    name: '企业官网检测报告',
    taskName: '企业官网检测',
    taskId: 2,
    format: 'html',
    size: '1.8 MB',
    createdAt: '2024-11-17 14:20',
    downloadUrl: '/api/reports/2/download'
  },
  {
    id: 3,
    name: 'API接口安全测试报告',
    taskName: 'API接口安全测试',
    taskId: 3,
    format: 'json',
    size: '456 KB',
    createdAt: '2024-11-17 12:15',
    downloadUrl: '/api/reports/3/download'
  }
]

// 系统设置数据
export const mockSettings = {
  general: {
    systemName: 'WebScan AI',
    language: 'zh-CN',
    timezone: 'Asia/Shanghai',
    autoUpdate: true
  },
  scan: {
    defaultDepth: '2',
    defaultConcurrency: 5,
    requestTimeout: 30,
    userAgent: 'WebScan AI Security Scanner 1.0',
    followRedirects: true,
    enableCookies: true
  },
  notification: {
    emailEnabled: false,
    smtpServer: '',
    smtpPort: 587,
    senderEmail: '',
    recipientEmails: '',
    events: ['high-vulnerability', 'scan-complete']
  },
  security: {
    sessionTimeout: 120,
    requireHttps: true,
    enableTwoFactor: false,
    allowedIPs: ''
  }
}

// 扫描规则数据
export const mockScanRules = [
  { id: 1, name: 'SQL注入检测', description: '检测SQL注入漏洞', enabled: true, category: 'injection' },
  { id: 2, name: 'XSS检测', description: '检测跨站脚本攻击', enabled: true, category: 'xss' },
  { id: 3, name: 'CSRF检测', description: '检测跨站请求伪造', enabled: true, category: 'csrf' },
  { id: 4, name: '文件上传检测', description: '检测文件上传漏洞', enabled: true, category: 'upload' },
  { id: 5, name: '目录遍历检测', description: '检测目录遍历漏洞', enabled: false, category: 'traversal' },
  { id: 6, name: '命令注入检测', description: '检测命令注入漏洞', enabled: true, category: 'injection' }
]

// 通知数据
export const mockNotifications = [
  {
    id: 1,
    title: '高危漏洞发现',
    message: '在 shop.example.com 发现 SQL 注入漏洞',
    type: 'high-vulnerability',
    time: '5分钟前',
    read: false
  },
  {
    id: 2,
    title: '扫描任务完成',
    message: '企业官网安全扫描已完成',
    type: 'scan-complete',
    time: '1小时前',
    read: false
  },
  {
    id: 3,
    title: '系统更新',
    message: '漏洞库已更新到最新版本',
    type: 'system-update',
    time: '2小时前',
    read: true
  }
]

// API密钥数据
export const mockApiKeys = [
  {
    id: 1,
    name: '默认API密钥',
    key: 'wsa_1234567890abcdef1234567890abcdef',
    masked: 'wsa_****************************abc123',
    createdAt: '2024-11-15 10:30',
    lastUsed: '2024-11-17 20:15',
    permissions: ['read', 'write']
  }
]

// 用户信息
export const mockUserInfo = {
  id: 1,
  username: 'admin',
  email: 'admin@webscan.ai',
  role: 'administrator',
  avatar: null,
  lastLogin: '2024-11-17 20:00',
  permissions: ['scan:create', 'scan:read', 'scan:update', 'scan:delete', 'report:generate', 'settings:manage']
}
