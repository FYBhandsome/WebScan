<template>
  <div class="dashboard">
    <el-page-header class="dashboard-header">
      <template #content>
        <div class="header-content">
          <h1>仪表盘</h1>
          <p class="subtitle">实时监控安全扫描状态</p>
        </div>
      </template>
    </el-page-header>

    <el-skeleton v-if="loading" :rows="10" animated />

    <div v-else class="dashboard-content">
      <el-row :gutter="20" class="stats-grid">
        <el-col :xs="24" :sm="12" :md="8" :lg="4">
          <StatCard
            icon="Search"
            :value="statistics.today_scans || 0"
            label="今日扫描"
            type="primary"
          />
        </el-col>
        <el-col :xs="24" :sm="12" :md="8" :lg="4">
          <StatCard
            icon="Warning"
            :value="statistics.high_risk_vulns || 0"
            label="高危漏洞"
            type="danger"
          />
        </el-col>
        <el-col :xs="24" :sm="12" :md="8" :lg="4">
          <StatCard
            icon="CircleCheck"
            :value="statistics.completed_scans || 0"
            label="已完成扫描"
            type="success"
          />
        </el-col>
        <el-col :xs="24" :sm="12" :md="8" :lg="4">
          <StatCard
            icon="CircleClose"
            :value="statistics.failed_scans || 0"
            label="失败扫描"
            type="warning"
          />
        </el-col>
        <el-col :xs="24" :sm="12" :md="8" :lg="4">
          <StatCard
            icon="Warning"
            :value="statistics.total_vulns || 0"
            label="总漏洞数"
            type="info"
          />
        </el-col>
        <el-col :xs="24" :sm="12" :md="8" :lg="4">
          <StatCard
            icon="DataAnalysis"
            :value="statistics.total_reports || 0"
            label="总报告数"
            type="secondary"
          />
        </el-col>
      </el-row>

      <el-row :gutter="20" class="charts-section">
        <el-col :xs="24" :md="12">
          <el-card shadow="hover">
            <template #header>
              <div class="card-header">
                <h3>漏洞趋势</h3>
              </div>
            </template>
            <div class="chart-container">
              <canvas ref="trendChart"></canvas>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="24" :md="12">
          <el-card shadow="hover">
            <template #header>
              <div class="card-header">
                <h3>漏洞分布</h3>
              </div>
            </template>
            <div class="chart-container">
              <canvas ref="distributionChart"></canvas>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- Frozen Tasks Panel -->
      <el-card v-if="frozenTasks.length > 0" shadow="hover" class="frozen-tasks-section">
        <template #header>
          <div class="card-header danger-header">
            <div class="header-title">
              <h3>⚠️ 冻结任务监控</h3>
              <el-tag type="danger" size="small">{{ frozenTasks.length }} 个异常</el-tag>
            </div>
            <span class="header-desc">以下任务运行时间已超过预设阈值的 80%，可能已卡死</span>
          </div>
        </template>
        <el-table :data="frozenTasks" style="width: 100%" size="small">
          <el-table-column prop="task_name" label="任务名称" />
          <el-table-column prop="task_type" label="类型" width="120" />
          <el-table-column prop="duration" label="运行时长" width="120">
             <template #default="{row}">
               <span class="danger-text">{{ row.duration }} min</span>
             </template>
          </el-table-column>
          <el-table-column prop="threshold" label="阈值" width="100">
             <template #default="{row}">
               {{ row.threshold }} min
             </template>
          </el-table-column>
 <el-table-column prop="progress" label="进度" width="180">
            <template #default="{row}">
              <el-progress :percentage="Math.min(100, Math.max(0, row.progress || 0))" status="exception" />
            </template>
          </el-table-column>
          <el-table-column label="操作" width="120">
            <template #default="{row}">
              <el-button type="danger" size="small" @click="handleAbortTask(row.id)">
                强制中止
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-card shadow="hover" class="recent-tasks-section">
        <template #header>
          <div class="section-header">
            <h3>最近任务</h3>
            <router-link to="/scan-tasks" class="view-all">
              查看全部 <el-icon><ArrowRight /></el-icon>
            </router-link>
          </div>
        </template>
        <el-empty v-if="recentTasks.length === 0" description="暂无任务数据" />
        <div v-else class="tasks-list">
          <TaskCard
            v-for="task in recentTasks"
            :key="task.id"
            :task="task"
            @cancel="handleCancelTask"
            @view="handleViewTask"
            @report="handleGenerateReport"
            @delete="handleDeleteTask"
          />
        </div>
      </el-card>

      <el-card shadow="hover" class="system-info-section">
        <template #header>
          <div class="section-header">
            <h3>系统信息</h3>
            <el-button
              type="primary"
              @click="loadSystemInfo"
              size="small"
            >
              <AppIcon name="Refresh" :size="14" />
              <span>刷新</span>
            </el-button>
          </div>
        </template>
        <el-descriptions v-if="systemInfo" :column="3" border>
          <el-descriptions-item label="系统版本">
            {{ systemInfo.version }}
          </el-descriptions-item>
          <el-descriptions-item label="运行时间">
            {{ systemInfo.uptime }}
          </el-descriptions-item>
          <el-descriptions-item label="CPU使用率">
            {{ systemInfo.resources?.cpu?.usage || 'N/A' }}
          </el-descriptions-item>
          <el-descriptions-item label="内存使用率">
            {{ systemInfo.resources?.memory?.usage || 'N/A' }}
          </el-descriptions-item>
          <el-descriptions-item label="磁盘使用率">
            {{ systemInfo.resources?.disk?.usage || 'N/A' }}
          </el-descriptions-item>
          <el-descriptions-item label="进程数">
            {{ systemInfo.processes?.count || 'N/A' }}
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card shadow="hover" class="server-log-section">
        <template #header>
          <div class="section-header">
            <h3>🖥️ 服务器运行日志</h3>
            <el-button
              type="primary"
              size="small"
              @click="showLogPanel = !showLogPanel"
            >
              {{ showLogPanel ? '收起' : '展开' }}
            </el-button>
          </div>
        </template>
        <ServerLogBox 
          v-if="showLogPanel" 
          height="400px"
          :auto-connect="true"
        />
        <div v-else class="log-placeholder">
          <span>点击"展开"查看实时日志</span>
        </div>
      </el-card>
    </div>

    <el-alert
      v-if="errorMessage"
      type="error"
      :title="errorMessage"
      :closable="true"
      @close="errorMessage = ''"
    />
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { tasksApi, settingsApi } from '@/utils/api'
import { ElMessageBox, ElMessage } from 'element-plus'
import { ArrowRight } from '@element-plus/icons-vue'
import StatCard from '@/components/common/StatCard.vue'
import TaskCard from '@/components/business/TaskCard.vue'
import AppIcon from '@/components/common/AppIcon.vue'
import ServerLogBox from '@/components/business/ServerLogBox.vue'
import Chart from 'chart.js/auto'

export default {
  name: 'Dashboard',
  components: {
    StatCard,
    TaskCard,
    AppIcon,
    ArrowRight,
    ServerLogBox
  },
  setup() {
    const router = useRouter()
    const loading = ref(true)
    const errorMessage = ref('')
    const statistics = ref({})
    const recentTasks = ref([])
    const frozenTasks = ref([])
    const systemInfo = ref(null)
    const trendChart = ref(null)
    const distributionChart = ref(null)
    const showLogPanel = ref(false)
    let chartInstances = null

    const loadStatistics = async () => {
      try {
        const response = await settingsApi.getStatistics(7)
        if (response.code === 200) {
          statistics.value = response.data
        }
      } catch (error) {
        console.error('加载统计数据失败:', error)
      }
    }

    const loadRecentTasks = async () => {
      try {
        const response = await tasksApi.getTasks({ limit: 5 })
        if (response.code === 200) {
          recentTasks.value = response.data.tasks || []
        }
      } catch (error) {
        console.error('加载最近任务失败:', error)
      }
    }

    const loadFrozenTasks = async () => {
      try {
        const response = await tasksApi.getTasks({ status: 'running' })
        if (response.code === 200) {
          const allTasks = response.data.tasks || []
          const frozen = []
          const threshold = 30
          const now = new Date()
          
          for (const task of allTasks) {
            if (task.created_at) {
              const created = new Date(task.created_at)
              const duration = (now - created) / 1000 / 60
              if (duration > threshold * 0.8) {
                frozen.push({
                  ...task,
                  duration: Math.round(duration),
                  threshold
                })
              }
            }
          }
          
          frozenTasks.value = frozen
        }
      } catch (error) {
        console.error('加载冻结任务失败:', error)
      }
    }

    const loadSystemInfo = async () => {
      try {
        const response = await settingsApi.getSystemInfo()
        if (response.code === 200) {
          systemInfo.value = response.data
        }
      } catch (error) {
        console.error('加载系统信息失败:', error)
        errorMessage.value = '加载系统信息失败'
      }
    }

    const initCharts = () => {
      nextTick(() => {
        if (typeof Chart === 'undefined') {
          console.warn('Chart.js未加载，跳过图表初始化')
          return
        }

        if (trendChart.value && statistics.value.trend_data) {
          const ctx = trendChart.value.getContext('2d')
          chartInstances = chartInstances || {}
          chartInstances.trend = new Chart(ctx, {
            type: 'line',
            data: {
              labels: statistics.value.trend_data.map(d => d.date),
              datasets: [
                {
                  label: '严重',
                  data: statistics.value.trend_data.map(d => d.critical),
                  borderColor: '#c0392b',
                  backgroundColor: 'rgba(192, 57, 43, 0.1)',
                  fill: true,
                  tension: 0.4
                },
                {
                  label: '高危',
                  data: statistics.value.trend_data.map(d => d.high),
                  borderColor: '#e74c3c',
                  backgroundColor: 'rgba(231, 76, 60, 0.1)',
                  fill: true,
                  tension: 0.4
                },
                {
                  label: '中危',
                  data: statistics.value.trend_data.map(d => d.medium),
                  borderColor: '#f39c12',
                  backgroundColor: 'rgba(243, 156, 18, 0.1)',
                  fill: true,
                  tension: 0.4
                },
                {
                  label: '低危',
                  data: statistics.value.trend_data.map(d => d.low),
                  borderColor: '#3498db',
                  backgroundColor: 'rgba(52, 152, 219, 0.1)',
                  fill: true,
                  tension: 0.4
                },
                {
                  label: '信息',
                  data: statistics.value.trend_data.map(d => d.info),
                  borderColor: '#95a5a6',
                  backgroundColor: 'rgba(149, 165, 166, 0.1)',
                  fill: true,
                  tension: 0.4
                }
              ]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'top'
                }
              },
              scales: {
                y: {
                  beginAtZero: true
                }
              }
            }
          })
        }

        if (distributionChart.value && statistics.value.severity_distribution) {
          const ctx = distributionChart.value.getContext('2d')
          chartInstances = chartInstances || {}
          chartInstances.distribution = new Chart(ctx, {
            type: 'doughnut',
            data: {
              labels: ['严重', '高危', '中危', '低危', '信息'],
              datasets: [{
                data: [
                  statistics.value.severity_distribution.critical || 0,
                  statistics.value.severity_distribution.high || 0,
                  statistics.value.severity_distribution.medium || 0,
                  statistics.value.severity_distribution.low || 0,
                  statistics.value.severity_distribution.info || 0
                ],
                backgroundColor: [
                  '#c0392b',
                  '#e74c3c',
                  '#f39c12',
                  '#3498db',
                  '#95a5a6'
                ]
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'right'
                }
              }
            }
          })
        }
      })
    }

    const handleCancelTask = async (taskId) => {
      try {
        await tasksApi.cancelTask(taskId)
        await loadRecentTasks()
      } catch {
        errorMessage.value = '取消任务失败'
      }
    }

    const handleViewTask = (taskId) => {
      router.push(`/scan-tasks?task=${taskId}`)
    }

    const handleGenerateReport = async (taskId) => {
      router.push(`/reports?task=${taskId}`)
    }

    const handleDeleteTask = async (taskId) => {
      try {
        await ElMessageBox.confirm('确定要删除此任务吗？', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        })
        await tasksApi.deleteTask(taskId)
        await loadRecentTasks()
        ElMessage.success('删除成功')
      } catch (error) {
        console.error('删除任务失败:', error)
      }
    }

    const handleAbortTask = async (taskId) => {
      try {
        await ElMessageBox.confirm('确定要强制中止该任务吗？', '警告', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        })
        await tasksApi.cancelTask(taskId)
        ElMessage.success('中止指令已发送')
        await loadFrozenTasks()
      } catch (e) {
        if (e !== 'cancel') {
          ElMessage.error('操作失败: ' + (e.message || '未知错误'))
        }
      }
    }

    const loadData = async () => {
      loading.value = true
      try {
        await Promise.all([
          loadStatistics(),
          loadRecentTasks(),
          loadSystemInfo(),
          loadFrozenTasks()
        ])
      } catch {
        errorMessage.value = '加载数据失败'
      } finally {
        loading.value = false
        await nextTick()
        initCharts()
      }
    }

    onMounted(() => {
      loadData()
    })

    onUnmounted(() => {
      if (chartInstances) {
        if (chartInstances.trend) {
          chartInstances.trend.destroy()
        }
        if (chartInstances.distribution) {
          chartInstances.distribution.destroy()
        }
      }
    })

    return {
      loading,
      errorMessage,
      statistics,
      recentTasks,
      frozenTasks,
      systemInfo,
      trendChart,
      distributionChart,
      showLogPanel,
      handleCancelTask,
      handleViewTask,
      handleGenerateReport,
      handleDeleteTask,
      handleAbortTask,
      loadSystemInfo
    }
  }
}
</script>

<style scoped>
.dashboard {
  padding: var(--spacing-lg);
}

.dashboard-header {
  margin-bottom: var(--spacing-lg);
}

.header-content h1 {
  margin: 0;
  font-size: 24px;
  color: var(--el-text-color-primary);
  font-weight: 700;
}

.subtitle {
  margin: var(--spacing-xs) 0 0 0;
  color: var(--el-text-color-secondary);
  font-size: 14px;
}

.dashboard-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.stats-grid {
  margin-bottom: var(--spacing-lg);
}

.charts-section {
  margin-bottom: var(--spacing-lg);
}

.card-header h3 {
  margin: 0;
  font-size: 16px;
  color: var(--el-text-color-primary);
  font-weight: 600;
}

.chart-container {
  height: 300px;
}

.recent-tasks-section,
.system-info-section {
  margin-bottom: var(--spacing-lg);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.section-header h3 {
  margin: 0;
  font-size: 16px;
  color: var(--el-text-color-primary);
  font-weight: 600;
}

.view-all {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  color: var(--el-color-primary);
  text-decoration: none;
  font-weight: 500;
  transition: all var(--transition-base);
}

.view-all:hover {
  color: var(--el-color-primary-dark-2);
}

.tasks-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.server-log-section {
  margin-bottom: var(--spacing-lg);
}

.log-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100px;
  color: var(--el-text-color-secondary);
  font-size: 14px;
}

@media (max-width: 768px) {
  .dashboard {
    padding: var(--spacing-md);
  }

  .header-content h1 {
    font-size: 20px;
  }

  .chart-container {
    height: 250px;
  }
}

@media (max-width: 480px) {
  .dashboard {
    padding: var(--spacing-sm);
  }

  .header-content h1 {
    font-size: 18px;
  }

  .subtitle {
    font-size: 12px;
  }

  .chart-container {
    height: 200px;
  }
}
</style>