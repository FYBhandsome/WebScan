/**
 * 工作流数据标准化工具
 * 
 * 提供统一的工作流数据转换和渲染工具
 */

export class WorkflowStatus {
  static PENDING = 'pending'
  static RUNNING = 'running'
  static COMPLETED = 'completed'
  static FAILED = 'failed'
  static CANCELLED = 'cancelled'
  static SKIPPED = 'skipped'
  
  static getLabel(status) {
    const labels = {
      'pending': '等待中',
      'running': '运行中',
      'completed': '已完成',
      'success': '已完成',
      'failed': '失败',
      'error': '失败',
      'cancelled': '已取消',
      'skipped': '已跳过'
    }
    return labels[status?.toLowerCase()] || status || '未知'
  }
  
  static getType(status) {
    const types = {
      'pending': 'info',
      'running': 'primary',
      'completed': 'success',
      'success': 'success',
      'failed': 'danger',
      'error': 'danger',
      'cancelled': 'warning',
      'skipped': 'warning'
    }
    return types[status?.toLowerCase()] || 'info'
  }
  
  static isFinished(status) {
    return ['completed', 'success', 'failed', 'error', 'cancelled', 'skipped'].includes(status?.toLowerCase())
  }
}

export class WorkflowDataNormalizer {
  static normalizeExecutionHistory(history) {
    if (!Array.isArray(history)) {
      return []
    }
    
    return history.map((record, index) => {
      return this.normalizeExecutionRecord(record, index)
    })
  }
  
  static normalizeExecutionRecord(record, index = 0) {
    if (!record || typeof record !== 'object') {
      return null
    }
    
    const normalized = {
      step_number: record.step_number || index + 1,
      node_id: record.node_id || record.node_name || `node-${index}`,
      node_name: record.node_name || record.task || '未知任务',
      node_type: record.node_type || 'unknown',
      status: this.normalizeStatus(record.status),
      
      task: record.task || record.node_name || record.tool_name,
      tool_name: record.tool_name || record.task,
      
      timestamp: record.timestamp || record.start_time,
      timestamp_iso: record.timestamp_iso || record.start_time_iso,
      
      execution_time: this.normalizeExecutionTime(record),
      duration_ms: record.duration_ms,
      
      input_params: record.input_params || record.input_data || {},
      output_data: record.output_data || {},
      
      error: record.error || record.error_message,
      error_message: record.error_message || record.error,
      
      metadata: record.metadata || {}
    }
    
    Object.keys(normalized).forEach(key => {
      if (normalized[key] === undefined || normalized[key] === null) {
        delete normalized[key]
      }
    })
    
    return normalized
  }
  
  static normalizeExecutionTime(record) {
    if (record.execution_time !== undefined) {
      return record.execution_time
    }
    
    if (record.duration_ms !== undefined) {
      return record.duration_ms / 1000
    }
    
    if (record.start_time && record.end_time) {
      return (record.end_time - record.start_time)
    }
    
    return 0
  }
  
  static normalizeStatus(status) {
    if (!status) return 'pending'
    
    const statusStr = typeof status === 'string' ? status.toLowerCase() : status.value || 'pending'
    
    const statusMap = {
      'success': 'completed',
      'completed': 'completed',
      'running': 'running',
      'pending': 'pending',
      'failed': 'failed',
      'error': 'failed',
      'cancelled': 'cancelled',
      'skipped': 'skipped'
    }
    
    return statusMap[statusStr] || statusStr
  }
  
  static normalizeGraphFlow(graphFlow) {
    if (!graphFlow) {
      return null
    }
    
    if (typeof graphFlow !== 'object') {
      return null
    }
    
    const normalized = {
      subgraphs: [],
      dependencies: [],
      execution_order: []
    }
    
    if (Array.isArray(graphFlow.subgraphs)) {
      normalized.subgraphs = graphFlow.subgraphs.map(sg => this.normalizeSubgraph(sg))
    }
    
    if (Array.isArray(graphFlow.dependencies)) {
      normalized.dependencies = graphFlow.dependencies
    }
    
    if (Array.isArray(graphFlow.execution_order)) {
      normalized.execution_order = graphFlow.execution_order
    }
    
    return normalized
  }
  
  static normalizeSubgraph(subgraph) {
    if (!subgraph || typeof subgraph !== 'object') {
      return null
    }
    
    return {
      subgraph_id: subgraph.subgraph_id || subgraph.id || '',
      subgraph_name: subgraph.subgraph_name || subgraph.name || '未命名子图',
      status: this.normalizeStatus(subgraph.status),
      start_time: subgraph.start_time,
      end_time: subgraph.end_time,
      nodes: Array.isArray(subgraph.nodes) 
        ? subgraph.nodes.map(node => this.normalizeNode(node))
        : [],
      dependencies: Array.isArray(subgraph.dependencies) ? subgraph.dependencies : []
    }
  }
  
  static normalizeNode(node) {
    if (!node || typeof node !== 'object') {
      return null
    }
    
    return {
      node_id: node.node_id || node.id || '',
      node_name: node.node_name || node.name || '未知节点',
      status: this.normalizeStatus(node.status),
      execution_time: node.execution_time || node.duration_ms / 1000 || 0,
      input_params: node.input_params || node.input_data || {},
      output_data: node.output_data || {}
    }
  }
}

export class WorkflowDataProcessor {
  static processWorkflowData(rawData) {
    if (!rawData || typeof rawData !== 'object') {
      return null
    }
    
    const normalizer = WorkflowDataNormalizer
    
    const processed = {
      task_id: rawData.task_id || rawData.id || '',
      target: rawData.target || '',
      status: normalizer.normalizeStatus(rawData.status),
      progress: rawData.progress || 0,
      
      start_time: rawData.start_time,
      end_time: rawData.end_time,
      duration: rawData.duration || this.calculateDuration(rawData),
      
      execution_history: normalizer.normalizeExecutionHistory(rawData.execution_history || []),
      graph_flow: normalizer.normalizeGraphFlow(rawData.graph_flow),
      
      current_step: rawData.current_step,
      total_steps: rawData.total_steps || 0,
      completed_steps: rawData.completed_steps || 0,
      
      vulnerabilities: Array.isArray(rawData.vulnerabilities) ? rawData.vulnerabilities : [],
      tool_results: rawData.tool_results || {},
      
      metadata: rawData.metadata || {}
    }
    
    return processed
  }
  
  static calculateDuration(data) {
    if (data.duration !== undefined) {
      return data.duration
    }
    
    if (data.start_time && data.end_time) {
      return data.end_time - data.start_time
    }
    
    if (data.start_time) {
      return (Date.now() / 1000) - data.start_time
    }
    
    return null
  }
  
  static getExecutionSummary(workflowData) {
    if (!workflowData) {
      return null
    }
    
    const history = workflowData.execution_history || []
    
    const summary = {
      total_steps: history.length,
      completed_steps: history.filter(h => ['completed', 'success'].includes(h.status)).length,
      failed_steps: history.filter(h => ['failed', 'error'].includes(h.status)).length,
      running_steps: history.filter(h => h.status === 'running').length,
      pending_steps: history.filter(h => h.status === 'pending').length,
      
      total_duration: history.reduce((sum, h) => sum + (h.execution_time || 0), 0),
      
      nodes_by_type: {},
      nodes_by_status: {}
    }
    
    history.forEach(h => {
      const type = h.node_type || 'unknown'
      summary.nodes_by_type[type] = (summary.nodes_by_type[type] || 0) + 1
      
      const status = h.status
      summary.nodes_by_status[status] = (summary.nodes_by_status[status] || 0) + 1
    })
    
    return summary
  }
  
  static getTimelineData(workflowData) {
    if (!workflowData || !workflowData.execution_history) {
      return []
    }
    
    return workflowData.execution_history.map((record, index) => ({
      id: record.node_id || `step-${index}`,
      title: record.node_name || record.task || `步骤 ${index + 1}`,
      status: record.status,
      timestamp: record.timestamp_iso || record.timestamp,
      duration: record.execution_time,
      type: WorkflowStatus.getType(record.status),
      content: {
        task: record.task || record.tool_name,
        input_params: record.input_params,
        output_data: record.output_data,
        error: record.error || record.error_message
      }
    }))
  }
  
  static getGraphVisualizationData(workflowData) {
    if (!workflowData || !workflowData.graph_flow) {
      return null
    }
    
    const graphFlow = workflowData.graph_flow
    
    return {
      nodes: graphFlow.subgraphs.flatMap(sg => 
        (sg.nodes || []).map(node => ({
          id: node.node_id,
          label: node.node_name,
          status: node.status,
          subgraph: sg.subgraph_name
        }))
      ),
      edges: graphFlow.dependencies.map(dep => ({
        from: dep.from || dep.source,
        to: dep.to || dep.target,
        label: dep.label || ''
      })),
      subgraphs: graphFlow.subgraphs.map(sg => ({
        id: sg.subgraph_id,
        name: sg.subgraph_name,
        status: sg.status,
        nodeCount: (sg.nodes || []).length
      }))
    }
  }
}

export function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return '-'
  
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`
  }
  
  const minutes = Math.floor(seconds / 60)
  const secs = (seconds % 60).toFixed(0)
  
  if (minutes < 60) {
    return `${minutes}m ${secs}s`
  }
  
  const hours = Math.floor(minutes / 60)
  const mins = minutes % 60
  
  return `${hours}h ${mins}m`
}

export function formatTimestamp(timestamp) {
  if (!timestamp) return '-'
  
  try {
    let date
    if (typeof timestamp === 'number') {
      date = new Date(timestamp * 1000)
    } else if (typeof timestamp === 'string') {
      date = new Date(timestamp)
    } else {
      return timestamp
    }
    
    if (isNaN(date.getTime())) {
      return timestamp
    }
    
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  } catch {
    return timestamp
  }
}

export default {
  WorkflowStatus,
  WorkflowDataNormalizer,
  WorkflowDataProcessor,
  formatDuration,
  formatTimestamp
}
