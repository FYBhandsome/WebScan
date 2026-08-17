const FIELD_LABELS = {
  server: 'Web 服务器',
  title: '页面标题',
  ip: 'IP 地址',
  host: '主机名',
  hostname: '主机名',
  status_code: '响应状态',
  open_ports: '开放端口',
  ports: '开放端口',
  total_count: '数量',
  subdomains: '已发现子域名',
  directories: '已发现目录',
  files: '已发现文件',
  found_paths: '已发现路径',
  waf_detected: 'WAF 状态',
  waf_type: 'WAF 类型',
  waf: 'WAF 类型',
  cdn_detected: 'CDN 状态',
  cdn_provider: 'CDN 服务商',
  cms_name: 'CMS',
  cms_version: 'CMS 版本',
  cms: 'CMS',
  pages: '已发现页面',
  urls: '已发现页面',
  location: '地理位置',
  isp: '运营商',
  provider: '服务提供商',
  domain: '域名',
  weight: '站点权重',
  website_name: '站点名称',
  record: '备案信息',
  tls_version: 'TLS 版本',
  cipher: '加密套件',
  allowed_methods: '允许的 HTTP 方法',
  redirect_location: '重定向地址',
  target_url: '目标地址',
}

const INTERNAL_FIELDS = new Set([
  'success', 'error', 'metadata', 'data', 'raw', 'headers',
  'request_response_log', 'result', 'vulnerabilities', 'timestamp',
  'result_status',
])

const hasValue = (value) => value !== undefined && value !== null && value !== ''

const toDisplayText = (value) => {
  if (!hasValue(value)) return ''
  if (typeof value === 'boolean') return value ? '是' : '否'
  if (Array.isArray(value)) return value.map(toDisplayText).filter(Boolean).join('、')
  if (typeof value === 'object') {
    return Object.entries(value)
      .map(([key, item]) => {
        const text = toDisplayText(item)
        return text ? `${FIELD_LABELS[key] || key}：${text}` : ''
      })
      .filter(Boolean)
      .join('；')
  }
  return String(value).trim()
}

const unwrapToolResult = (result) => {
  let value = result
  for (let depth = 0; depth < 4; depth += 1) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) break
    const isEnvelope = Object.prototype.hasOwnProperty.call(value, 'data') && (
      Object.prototype.hasOwnProperty.call(value, 'success') ||
      Object.prototype.hasOwnProperty.call(value, 'metadata') ||
      Object.prototype.hasOwnProperty.call(value, 'error')
    )
    if (!isEnvelope || !value.data || typeof value.data !== 'object') break
    value = value.data
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

const item = (label, value, href = '') => {
  const text = toDisplayText(value)
  return text ? { label, value: text, href } : null
}

const compactItems = (items) => items.filter(Boolean)

const formatIpItems = (ip) => {
  const text = toDisplayText(ip)
  if (!text) return []
  const match = text.match(/^([^（(\s]+)\s*[（(](.+)[）)]$/)
  if (!match) return [item('IP 地址', text)]
  return compactItems([
    item('IP 地址', match[1]),
    item('IP 归属信息', match[2].replace(/^物理地址\s*[:：]\s*/, '')),
  ])
}

const formatBaseInfo = (data) => {
  const responseItems = []
  if (hasValue(data.code)) {
    const code = String(data.code)
    responseItems.push(item(
      '访问状态',
      /^2\d{2}$/.test(code) ? `网站可正常访问（HTTP ${code}）` : `HTTP 响应状态：${code}`,
    ))
  } else if (hasValue(data.msg)) {
    responseItems.push(item('查询状态', data.msg))
  }
  responseItems.push(...compactItems([
    item('Web 服务器', data.server),
    item('网站技术', data.language),
    item('页面标题', data.title),
    item('服务器操作系统', data.os),
  ]))

  const networkItems = compactItems([
    item('域名', data.domain),
    ...formatIpItems(data.ip),
  ])
  const registrationItems = compactItems([
    item('注册信息查询入口', data.register, /^https?:\/\//i.test(String(data.register || '')) ? data.register : ''),
  ])

  return [
    { title: '服务与响应', items: compactItems(responseItems) },
    { title: '域名与网络', items: networkItems },
    { title: '注册信息', items: registrationItems },
  ].filter(group => group.items.length)
}

const formatSummaryItems = (summary) => {
  if (!Array.isArray(summary)) return []
  return compactItems(summary.map(entry => {
    if (!entry || typeof entry !== 'object') return null
    const label = FIELD_LABELS[entry.label] || entry.label
    return item(label, entry.value)
  }))
}

const formatGenericItems = (data) => compactItems(
  Object.entries(data)
    .filter(([key]) => !INTERNAL_FIELDS.has(key))
    .map(([key, value]) => item(FIELD_LABELS[key] || key.replace(/_/g, ' '), value))
)

/**
 * Converts heterogeneous tool output into display-only groups.  The API's
 * original result remains untouched; this only removes transport envelopes
 * and translates known collection fields for the UI.
 */
export const formatInformationResult = (toolName, resultData) => {
  const rawData = unwrapToolResult(resultData?.result)
  if (toolName === 'baseinfo_scan') {
    const groups = formatBaseInfo(rawData)
    if (groups.length) return groups
  }

  const summaryItems = formatSummaryItems(resultData?.information_summary)
  if (summaryItems.length) return [{ title: '', items: summaryItems }]

  const genericItems = formatGenericItems(rawData)
  return genericItems.length ? [{ title: '', items: genericItems }] : []
}
