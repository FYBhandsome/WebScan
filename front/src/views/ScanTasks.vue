<template>
  <div class="scan-tasks">
    <div class="page-header">
      <h1>扫描任务</h1>
      <div class="header-actions">
        <button class="btn-primary" @click="showCreateModal = true">
          ➕ 新建任务
        </button>
        <button class="btn-secondary" @click="loadTasks">
          🔄 刷新
        </button>
      </div>
    </div>

    <div class="filters-section">
      <div class="filter-group">
        <label>状态:</label>
        <select v-model="filters.status" @change="loadTasks">
          <option value="">全部</option>
          <option value="pending">等待中</option>
          <option value="queued">队列中</option>
          <option value="running">运行中</option>
          <option value="completed">已完成</option>
          <option value="failed">失败</option>
          <option value="cancelled">已取消</option>
        </select>
      </div>

      <div class="filter-group">
        <label>类型:</label>
        <select v-model="filters.task_type" @change="loadTasks">
          <option value="">全部</option>
          <option value="ai_agent_scan">AI Agent扫描</option>
          <option value="awvs_scan">AWVS扫描</option>
          <option value="poc_scan">POC扫描</option>
          <option value="scan_dir">目录扫描</option>
          <option value="scan_webside">网站扫描</option>
          <option value="scan_port">端口扫描</option>
          <option value="scan_cms">CMS识别</option>
          <option value="scan_comprehensive">综合扫描</option>
        </select>
      </div>

      <div class="filter-group">
        <label>搜索:</label>
        <input
          v-model="filters.search"
          type="text"
          placeholder="搜索任务名称或目标"
          @keyup.enter="loadTasks"
        />
        <button class="btn-search" @click="loadTasks">搜索</button>
      </div>

      <div class="filter-group">
        <label>日期范围:</label>
        <el-date-picker
          v-model="filters.start_date"
          type="date"
          placeholder="开始日期"
          format="YYYY-MM-DD"
          value-format="YYYY-MM-DD"
          @change="loadTasks"
          @update:model-value="(val) => filters.start_date = val || ''"
          style="width: 150px"
        />
        <span class="date-separator">至</span>
        <el-date-picker
          v-model="filters.end_date"
          type="date"
          placeholder="结束日期"
          format="YYYY-MM-DD"
          value-format="YYYY-MM-DD"
          @change="loadTasks"
          @update:model-value="(val) => filters.end_date = val || ''"
          style="width: 150px"
        />
      </div>

      <div class="filter-actions">
        <button class="btn-reset" @click="resetFilters">重置筛选</button>
      </div>
    </div>

    <div v-if="loading" class="loading-container">
      <Loading text="加载任务列表中..." />
    </div>

    <div v-else-if="!tasks || tasks.length === 0" class="empty-state">
      <div class="empty-icon">📋</div>
      <h3>暂无任务</h3>
      <p>点击"新建任务"按钮创建您的第一个扫描任务</p>
      <button class="btn-primary" @click="showCreateModal = true">
        新建任务
      </button>
    </div>

    <div v-else class="tasks-list">
      <TaskCard
        v-for="task in tasks"
        :key="task.id"
        :task="task"
        @cancel="handleCancelTask"
        @view="handleViewTask"
        @report="handleGenerateReport"
        @delete="handleDeleteTask"
      />
    </div>

    <div v-if="total > limit" class="pagination">
      <button
        class="btn-page"
        :disabled="currentPage === 1"
        @click="currentPage--; loadTasks()"
      >
        上一页
      </button>
      <span class="page-info">第 {{ currentPage }} / {{ totalPages }} 页</span>
      <button
        class="btn-page"
        :disabled="currentPage === totalPages"
        @click="currentPage++; loadTasks()"
      >
        下一页
      </button>
    </div>

    <div v-if="showCreateModal" class="modal-overlay" @click.self="showCreateModal = false">
      <div class="modal-content">
        <div class="modal-header">
          <h2>创建扫描任务</h2>
          <button class="btn-close" @click="showCreateModal = false">×</button>
        </div>
        <div class="modal-body">
          <div class="task-type-filters">
            <div class="filter-row">
              <input
                v-model="searchTaskType"
                type="text"
                placeholder="搜索任务类型..."
                class="search-input"
              />
              <select v-model="selectedCategory" class="category-select">
                <option value="">全部类别</option>
                <option v-for="(cat, key) in taskTypeCategories" :key="key" :value="key">
                  {{ cat.icon }} {{ cat.label }}
                </option>
              </select>
            </div>
          </div>

          <div class="task-type-selector">
            <button
              v-for="type in filteredTaskTypes"
              :key="type.value"
              :class="['task-type-btn', { active: selectedTaskType === type.value }]"
              @click="selectedTaskType = type.value"
              :title="type.description"
            >
              <span class="task-type-icon">{{ type.icon }}</span>
              <span class="task-type-label">{{ type.label }}</span>
              <span class="task-type-desc">{{ type.description }}</span>
            </button>
          </div>

          <div class="form-group">
            <label for="taskName">任务名称 *</label>
            <input
              id="taskName"
              v-model="newTask.task_name"
              type="text"
              placeholder="请输入任务名称"
            />
          </div>

          <div class="form-group">
            <label for="target">扫描目标 *</label>
            <input
              id="target"
              v-model="newTask.target"
              type="text"
              placeholder="请输入URL或IP地址"
            />
          </div>

          <div class="form-actions">
            <button class="btn-secondary" @click="showCreateModal = false">
              取消
            </button>
            <button class="btn-primary" :disabled="isCreating" @click="handleCreateTask">
              {{ isCreating ? '创建中...' : '创建任务' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <Alert
      v-if="errorMessage"
      type="error"
      :message="errorMessage"
      @close="errorMessage = ''"
    />
  </div>
</template>

<script>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { tasksApi } from '@/utils/api'
import TaskCard from '@/components/business/TaskCard.vue'
import Loading from '@/components/common/Loading.vue'
import Alert from '@/components/common/Alert.vue'
import { useWebSocket } from '@/utils/websocket'
import { useTaskStore } from '@/store/tasks'
import toast from '@/utils/toast'

export default {
  name: 'ScanTasks',
  components: {
    TaskCard,
    Loading,
    Alert
  },
  setup() {
    const router = useRouter()
    const route = useRoute()
    const taskStore = useTaskStore()
    const loading = ref(true)
    const errorMessage = ref('')
    const tasks = ref([])
    const total = ref(0)
    const currentPage = ref(1)
    const limit = ref(20)
    const showCreateModal = ref(false)
    const isCreating = ref(false)
    const selectedTaskType = ref('poc_scan')
    
    const { connect, on, disconnect } = useWebSocket('ws://localhost:8888/api/ws')

    const filters = ref({
      status: '',
      task_type: '',
      search: '',
      start_date: '',
      end_date: ''
    })

    const resetFilters = () => {
      filters.value = {
        status: '',
        task_type: '',
        search: '',
        start_date: '',
        end_date: ''
      }
      currentPage.value = 1
      loadTasks()
    }

    const newTask = ref({
      task_name: '',
      target: ''
    })

    const taskTypeCategories = {
      info_collection: { label: '信息收集', icon: '🔍', types: [] },
      vuln_scan: { label: '漏洞扫描', icon: '🛡️', types: [] },
      poc_verify: { label: 'POC验证', icon: '💥', types: [] },
      comprehensive: { label: '综合扫描', icon: '🎯', types: [] }
    }

    const allTaskTypes = [
      { value: 'portscan', label: '端口扫描', icon: '🔌', category: 'info_collection', description: '扫描目标开放端口' },
      { value: 'baseinfo', label: '基础信息', icon: 'ℹ️', category: 'info_collection', description: '获取网站基础信息' },
      { value: 'webside', label: '旁站查询', icon: '🌐', category: 'info_collection', description: '查询IP旁站信息' },
      { value: 'webweight', label: '权重查询', icon: '⚖️', category: 'info_collection', description: '查询网站权重' },
      { value: 'iplocating', label: 'IP定位', icon: '📍', category: 'info_collection', description: 'IP地理位置定位' },
      { value: 'cdnexist', label: 'CDN检测', icon: '☁️', category: 'info_collection', description: '检测是否使用CDN' },
      { value: 'whatcms', label: 'CMS识别', icon: '🔎', category: 'info_collection', description: '识别CMS类型' },
      { value: 'subdomain', label: '子域名收集', icon: '🔗', category: 'info_collection', description: '收集子域名信息' },
      { value: 'dirscan', label: '目录扫描', icon: '📁', category: 'info_collection', description: '扫描敏感目录' },
      { value: 'crawler', label: '网站爬虫', icon: '🕷️', category: 'info_collection', description: '爬取网站链接' },
      { value: 'loginfo', label: '日志分析', icon: '📊', category: 'info_collection', description: '分析日志信息' },
      { value: 'infoleak', label: '信息泄露', icon: '🔓', category: 'info_collection', description: '检测信息泄露' },
      
      { value: 'sqli', label: 'SQL注入', icon: '💉', category: 'vuln_scan', description: 'SQL注入漏洞扫描' },
      { value: 'xss', label: 'XSS扫描', icon: '📜', category: 'vuln_scan', description: '跨站脚本漏洞扫描' },
      { value: 'csrf', label: 'CSRF扫描', icon: '🔄', category: 'vuln_scan', description: '跨站请求伪造扫描' },
      { value: 'ssrf', label: 'SSRF扫描', icon: '🌐', category: 'vuln_scan', description: '服务端请求伪造扫描' },
      { value: 'lfi', label: 'LFI扫描', icon: '📂', category: 'vuln_scan', description: '本地文件包含扫描' },
      { value: 'cmdi', label: '命令注入', icon: '⚡', category: 'vuln_scan', description: '命令注入漏洞扫描' },
      { value: 'fileupload', label: '文件上传', icon: '📤', category: 'vuln_scan', description: '文件上传漏洞扫描' },
      { value: 'weakpass', label: '弱口令', icon: '🔑', category: 'vuln_scan', description: '弱口令检测' },
      
      { value: 'weblogic_cve_2020_2551', label: 'WebLogic CVE-2020-2551', icon: '💥', category: 'poc_verify', description: 'WebLogic T3/IIOP反序列化' },
      { value: 'weblogic_cve_2018_2628', label: 'WebLogic CVE-2018-2628', icon: '💥', category: 'poc_verify', description: 'WebLogic T3反序列化' },
      { value: 'weblogic_cve_2018_2894', label: 'WebLogic CVE-2018-2894', icon: '💥', category: 'poc_verify', description: 'WebLogic未授权访问' },
      { value: 'struts2_009', label: 'Struts2 S2-009', icon: '💥', category: 'poc_verify', description: 'Struts2 REST插件RCE' },
      { value: 'struts2_032', label: 'Struts2 S2-032', icon: '💥', category: 'poc_verify', description: 'Struts2动态方法调用RCE' },
      { value: 'tomcat_cve_2017_12615', label: 'Tomcat CVE-2017-12615', icon: '💥', category: 'poc_verify', description: 'Tomcat PUT任意文件写入' },
      { value: 'jboss_cve_2017_12149', label: 'JBoss CVE-2017-12149', icon: '💥', category: 'poc_verify', description: 'JBoss反序列化漏洞' },
      { value: 'nexus_cve_2020_10199', label: 'Nexus CVE-2020-10199', icon: '💥', category: 'poc_verify', description: 'Nexus RCE漏洞' },
      { value: 'drupal_cve_2018_7600', label: 'Drupal CVE-2018-7600', icon: '💥', category: 'poc_verify', description: 'Drupalgeddon2 RCE' },
      { value: 'thinkphp_rce', label: 'ThinkPHP RCE', icon: '💥', category: 'poc_verify', description: 'ThinkPHP远程代码执行' },
      
      { value: 'waf', label: 'WAF检测', icon: '🛡️', category: 'comprehensive', description: '检测Web应用防火墙' },
      { value: 'comprehensive', label: '综合扫描', icon: '🎯', category: 'comprehensive', description: '综合安全扫描' },
      { value: 'awvs_scan', label: 'AWVS扫描', icon: '🛡️', category: 'comprehensive', description: 'AWVS专业扫描' },
      { value: 'ai_agent_scan', label: 'AI Agent扫描', icon: '🤖', category: 'comprehensive', description: 'AI智能扫描' }
    ]

    allTaskTypes.forEach(type => {
      if (taskTypeCategories[type.category]) {
        taskTypeCategories[type.category].types.push(type)
      }
    })

    const taskTypes = allTaskTypes
    const selectedCategory = ref('')
    const searchTaskType = ref('')

    const filteredTaskTypes = computed(() => {
      let types = allTaskTypes
      if (selectedCategory.value) {
        types = taskTypeCategories[selectedCategory.value].types
      }
      if (searchTaskType.value) {
        const search = searchTaskType.value.toLowerCase()
        types = types.filter(t => 
          t.label.toLowerCase().includes(search) || 
          t.description.toLowerCase().includes(search)
        )
      }
      return types
    })

    const totalPages = computed(() => Math.ceil(total.value / limit.value))

    const loadTasks = async () => {
      loading.value = true
      errorMessage.value = ''
      try {
        const params = {
          ...filters.value,
          skip: (currentPage.value - 1) * limit.value,
          limit: limit.value
        }

        const response = await tasksApi.getTasks(params)
        
        if (response && response.code === 200) {
          tasks.value = response.data.tasks || []
          total.value = response.data.total || 0
        } else if (response && response.data) {
          tasks.value = response.data.tasks || []
          total.value = response.data.total || 0
        } else {
          throw new Error('Invalid response format')
        }
      } catch (error) {
        console.error('加载任务失败:', error)
        errorMessage.value = error.message || '加载任务列表失败'
        tasks.value = []
        total.value = 0
      } finally {
        loading.value = false
      }
    }

    const handleCancelTask = async (taskId) => {
      if (confirm('确定要取消此任务吗？')) {
        try {
          await tasksApi.cancelTask(taskId)
          await loadTasks()
        } catch {
          errorMessage.value = '取消任务失败'
        }
      }
    }

    const handleViewTask = (taskId) => {
      router.push(`/vulnerability-results?task=${taskId}`)
    }

    const handleGenerateReport = async (taskId) => {
      router.push(`/reports?task=${taskId}`)
    }

    const handleDeleteTask = async (taskId) => {
      if (confirm('确定要删除此任务吗？此操作不可恢复。')) {
        try {
          await tasksApi.deleteTask(taskId)
          await loadTasks()
        } catch {
          errorMessage.value = '删除任务失败'
        }
      }
    }

    const handleCreateTask = async () => {
      if (!newTask.value.task_name || !newTask.value.target) {
        errorMessage.value = '请填写任务名称和扫描目标'
        return
      }

      isCreating.value = true
      errorMessage.value = ''

      try {
        const taskData = {
          task_name: newTask.value.task_name,
          target: newTask.value.target,
          task_type: selectedTaskType.value,
          config: {}
        }

        const response = await tasksApi.createTask(taskData)
        if (response.code === 200) {
          showCreateModal.value = false
          newTask.value = { task_name: '', target: '' }
          await loadTasks()
        } else {
          errorMessage.value = response.message || '创建任务失败'
        }
      } catch (error) {
        errorMessage.value = error.message || '创建任务失败'
      } finally {
        isCreating.value = false
      }
    }

    const updateTaskStatus = (taskId, payload) => {
      taskId = String(taskId)
      
      const index = tasks.value.findIndex(t => 
        String(t.id) === taskId || String(t.task_id) === taskId
      )
      
      if (index !== -1) {
        tasks.value[index] = { ...tasks.value[index], ...payload }
      } else if (payload.status) {
        loadTasks()
      }
    }

    const updateTaskProgress = (taskId, progress) => {
      taskId = String(taskId)
      const index = tasks.value.findIndex(t => 
        String(t.id) === taskId || String(t.task_id) === taskId
      )
      if (index !== -1) {
        tasks.value[index].progress = progress
      }
    }

    const updateTaskCompleted = (taskId, payload) => {
      taskId = String(taskId)
      const index = tasks.value.findIndex(t => 
        String(t.id) === taskId || String(t.task_id) === taskId
      )
      if (index !== -1) {
        tasks.value[index].status = 'completed'
        tasks.value[index].progress = 100
        tasks.value[index].result = payload.result || {}
        tasks.value[index].completed_at = new Date().toISOString()
        toast.success('任务完成', `扫描任务 ${taskId.substring(0, 8)}... 已完成`)
      } else {
        loadTasks()
      }
    }
    
    const updateTaskFailed = (taskId, error) => {
      taskId = String(taskId)
      const index = tasks.value.findIndex(t => 
        String(t.id) === taskId || String(t.task_id) === taskId
      )
      if (index !== -1) {
        tasks.value[index].status = 'failed'
        tasks.value[index].error_message = error
        toast.error('任务失败', `扫描任务 ${taskId.substring(0, 8)}... 执行失败`)
      } else {
        loadTasks()
      }
    }

    onMounted(() => {
      loadTasks()

      if (route.query.task) {
        handleViewTask(parseInt(route.query.task))
      }
      
      connect()
      
      on('task:update', (payload) => {
        const data = payload.payload || payload
        updateTaskStatus(data.task_id, data)
      })
      
      on('task:progress', (payload) => {
        const data = payload.payload || payload
        updateTaskProgress(data.task_id, data.progress)
      })
      
      on('task:completed', (payload) => {
        const data = payload.payload || payload
        updateTaskCompleted(data.task_id, data)
      })
      
      on('task:failed', (payload) => {
        const data = payload.payload || payload
        updateTaskFailed(data.task_id, data.error || data.message)
      })
    })
    
    onBeforeUnmount(() => {
      disconnect()
    })

    return {
      loading,
      errorMessage,
      tasks,
      total,
      currentPage,
      limit,
      totalPages,
      filters,
      showCreateModal,
      isCreating,
      selectedTaskType,
      newTask,
      taskTypes,
      taskTypeCategories,
      allTaskTypes,
      selectedCategory,
      searchTaskType,
      filteredTaskTypes,
      loadTasks,
      resetFilters,
      handleCancelTask,
      handleViewTask,
      handleGenerateReport,
      handleDeleteTask,
      handleCreateTask
    }
  }
}
</script>

<style scoped>
.scan-tasks {
  padding: var(--spacing-xl);
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-xl);
}

.page-header h1 {
  margin: 0;
  font-size: 2.2rem;
  color: var(--text-primary);
  font-weight: 700;
  letter-spacing: 0.5px;
}

.header-actions {
  display: flex;
  gap: var(--spacing-md);
}

.header-actions .btn-primary,
.header-actions .btn-secondary {
  padding: 12px 24px;
  font-size: 15px;
  font-weight: 600;
  letter-spacing: 0.3px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
  transition: all 0.3s;
}

.header-actions .btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}

.header-actions .btn-secondary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}

.filters-section {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  background-color: #ffffff;
  border: 2px solid var(--border-color);
  border-radius: var(--border-radius-lg);
  margin-bottom: var(--spacing-lg);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.filter-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.filter-group label {
  font-weight: 600;
  color: var(--text-primary);
  white-space: nowrap;
  font-size: 14px;
  letter-spacing: 0.2px;
}

.filter-group input,
.filter-group select {
  padding: 10px 14px;
  border: 2px solid var(--border-color);
  border-radius: var(--border-radius);
  font-size: 14px;
  font-weight: 500;
  transition: all 0.3s;
  background-color: #ffffff;
  color: var(--text-primary);
  min-width: 160px;
}

.filter-group input:focus,
.filter-group select:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.15);
}

.filter-group span {
  color: var(--text-secondary);
  font-weight: 500;
  font-size: 14px;
}

.date-separator {
  margin: 0 8px;
}

.btn-search {
  padding: 10px 16px;
  background-color: var(--color-primary);
  color: #1a1a1a;
  border: none;
  border-radius: var(--border-radius);
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s;
  margin-left: 8px;
}

.btn-search:hover {
  background-color: var(--color-primary-dark);
}

.filter-actions {
  margin-left: auto;
  display: flex;
  align-items: center;
}

.btn-reset {
  padding: 10px 20px;
  background-color: #f5f5f5;
  color: #666;
  border: 2px solid #ddd;
  border-radius: var(--border-radius);
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s;
}

.btn-reset:hover {
  background-color: #e8e8e8;
  border-color: #ccc;
}

.loading-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-xxl);
  color: var(--text-secondary);
}

.empty-icon {
  font-size: 4rem;
  margin-bottom: var(--spacing-lg);
}

.empty-state h3 {
  margin: 0 0 var(--spacing-md);
  font-size: 1.5rem;
  color: var(--text-primary);
}

.empty-state p {
  margin: 0 0 var(--spacing-xl);
}

.tasks-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: var(--spacing-md);
  margin-top: var(--spacing-xl);
  padding: var(--spacing-md);
  background-color: var(--card-bg);
  border-radius: var(--border-radius);
}

.btn-page {
  padding: var(--spacing-sm) var(--spacing-md);
  background-color: var(--color-primary);
  color: #1a1a1a;
  border: none;
  border-radius: var(--border-radius);
  cursor: pointer;
  transition: all 0.3s;
}

.btn-page:hover:not(:disabled) {
  background-color: var(--color-primary-dark);
}

.btn-page:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.page-info {
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
  padding: var(--spacing-lg);
}

.modal-content {
  background-color: #ffffff;
  border-radius: var(--border-radius-lg);
  max-width: 600px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  border: 1px solid var(--border-color);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: 2px solid var(--border-color);
  background-color: #fafbfc;
}

.modal-header h2 {
  margin: 0;
  font-size: 1.35rem;
  color: var(--text-primary);
  font-weight: 700;
  letter-spacing: 0.3px;
}

.btn-close {
  background: none;
  border: none;
  font-size: 1.8rem;
  color: var(--text-secondary);
  cursor: pointer;
  padding: 0;
  line-height: 1;
  transition: all 0.3s;
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
}

.btn-close:hover {
  color: var(--text-primary);
  background-color: rgba(0, 0, 0, 0.08);
}

.modal-body {
  padding: var(--spacing-lg);
}

.task-type-filters {
  margin-bottom: var(--spacing-lg);
  padding: var(--spacing-md);
  background-color: #f8f9fa;
  border-radius: var(--border-radius);
}

.filter-row {
  display: flex;
  gap: var(--spacing-md);
  align-items: center;
}

.search-input {
  flex: 1;
  padding: 10px 14px;
  border: 2px solid var(--border-color);
  border-radius: var(--border-radius);
  font-size: 14px;
  transition: all 0.3s;
}

.search-input:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.15);
}

.category-select {
  padding: 10px 14px;
  border: 2px solid var(--border-color);
  border-radius: var(--border-radius);
  font-size: 14px;
  background-color: #ffffff;
  cursor: pointer;
  transition: all 0.3s;
  min-width: 150px;
}

.category-select:focus {
  outline: none;
  border-color: var(--primary-color);
}

.task-type-selector {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
  max-height: 400px;
  overflow-y: auto;
  padding: var(--spacing-sm);
}

.task-type-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-md);
  border: 2px solid var(--border-color);
  border-radius: var(--border-radius);
  background-color: #ffffff;
  cursor: pointer;
  transition: all 0.3s;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  min-height: 100px;
}

.task-type-btn:hover {
  border-color: var(--primary-color);
  background-color: rgba(74, 144, 226, 0.08);
  transform: translateY(-2px);
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.15);
}

.task-type-btn.active {
  border-color: var(--primary-color);
  background-color: rgba(74, 144, 226, 0.12);
  box-shadow: 0 2px 8px rgba(74, 144, 226, 0.3);
}

.task-type-icon {
  font-size: 1.8rem;
}

.task-type-label {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: 0.3px;
  text-align: center;
}

.task-type-desc {
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-align: center;
  line-height: 1.3;
  margin-top: 2px;
}

.form-group {
  margin-bottom: var(--spacing-lg);
}

.form-group label {
  display: block;
  margin-bottom: 10px;
  font-weight: 600;
  color: var(--text-primary);
  font-size: 15px;
  letter-spacing: 0.2px;
}

.form-group input {
  width: 100%;
  padding: 12px 16px;
  border: 2px solid var(--border-color);
  border-radius: var(--border-radius);
  font-size: 15px;
  font-weight: 500;
  transition: all 0.3s;
  background-color: #ffffff;
  color: var(--text-primary);
}

.form-group input:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.15);
}

.form-group input::placeholder {
  color: var(--text-muted);
  font-weight: 400;
}

.form-actions {
  display: flex;
  gap: var(--spacing-md);
  margin-top: var(--spacing-xl);
}

.btn-primary,
.btn-secondary {
  flex: 1;
  padding: var(--spacing-md) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius);
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s;
}

.btn-primary {
  background-color: var(--color-primary);
  color: rgb(30, 7, 7);
}

.btn-primary:hover:not(:disabled) {
  background-color: var(--color-primary-dark);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background-color: var(--color-secondary);
  color: #1a1a1a;
}

.btn-secondary:hover {
  background-color: var(--color-secondary-dark);
}

@media (max-width: 768px) {
  .filters-section {
    flex-direction: column;
    align-items: stretch;
  }
  
  .task-type-selector {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
