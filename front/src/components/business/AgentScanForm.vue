<template>
  <div class="agent-scan-form">
    <h2>AI Agent智能扫描</h2>
    
    <form @submit.prevent="handleSubmit">
      <div class="form-group">
        <label for="target">扫描目标 *</label>
        <input
          id="target"
          v-model="formData.target"
          type="text"
          placeholder="请输入URL或IP地址"
          required
        />
        <small class="help-text">AI Agent将自动分析目标并选择最佳扫描策略</small>
      </div>

      <div class="form-group">
        <label for="taskName">任务名称 *</label>
        <input
          id="taskName"
          v-model="formData.taskName"
          type="text"
          placeholder="请输入任务名称"
          required
        />
      </div>

      <div class="form-group">
        <label>
          <input v-model="formData.enableLLMPlanning" type="checkbox" />
          <span>启用LLM智能规划</span>
        </label>
        <small class="help-text">使用大语言模型进行智能任务规划和决策</small>
      </div>

      <div class="form-group">
        <label>
          <input v-model="formData.needCustomScan" type="checkbox" />
          <span>自定义扫描</span>
        </label>
      </div>

      <div v-if="formData.needCustomScan" class="custom-scan-config">
        <div class="form-group">
          <label for="customScanType">扫描类型</label>
          <select id="customScanType" v-model="formData.customScanType">
            <option value="web">Web应用扫描</option>
            <option value="network">网络扫描</option>
            <option value="api">API接口扫描</option>
            <option value="mobile">移动应用扫描</option>
            <option value="custom">自定义扫描</option>
          </select>
        </div>

        <div class="form-group">
          <label for="customScanRequirements">扫描需求</label>
          <textarea
            id="customScanRequirements"
            v-model="formData.customScanRequirements"
            placeholder="请描述您的扫描需求，例如：检测SQL注入、XSS等漏洞..."
            rows="4"
          ></textarea>
        </div>

        <div class="form-group">
          <label for="customScanLanguage">代码生成语言</label>
          <select id="customScanLanguage" v-model="formData.customScanLanguage">
            <option value="python">Python</option>
            <option value="javascript">JavaScript</option>
            <option value="go">Go</option>
            <option value="rust">Rust</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>
          <input v-model="formData.needCapabilityEnhancement" type="checkbox" />
          <span>功能补充</span>
        </label>
        <small class="help-text">AI Agent将根据需要自动生成和集成新的扫描工具</small>
      </div>

      <div v-if="formData.needCapabilityEnhancement" class="capability-config">
        <div class="form-group">
          <label for="capabilityRequirement">功能需求</label>
          <textarea
            id="capabilityRequirement"
            v-model="formData.capabilityRequirement"
            placeholder="请描述您需要的功能，例如：需要检测XXE漏洞、需要支持特定协议..."
            rows="3"
          ></textarea>
        </div>
      </div>

      <div class="form-group">
        <label>
          <input v-model="formData.useCustomTasks" type="checkbox" />
          <span>使用自定义任务列表</span>
        </label>
      </div>

      <div v-if="formData.useCustomTasks" class="custom-tasks-config">
        <div class="form-group">
          <label>可用工具</label>
          <div class="tools-list">
            <label v-for="tool in availableTools" :key="tool.id" class="tool-item">
              <input
                v-model="formData.customTasks"
                :value="tool.id"
                type="checkbox"
              />
              <div class="tool-info">
                <span class="tool-name">{{ tool.name }}</span>
                <span class="tool-description">{{ tool.description }}</span>
              </div>
            </label>
          </div>
        </div>
      </div>

      <div class="form-actions">
        <button type="button" class="btn-secondary" @click="handleReset">
          重置
        </button>
        <button type="submit" class="btn-primary" :disabled="isSubmitting">
          {{ isSubmitting ? '启动中...' : '启动AI Agent' }}
        </button>
      </div>
    </form>

    <Alert
      v-if="errorMessage"
      type="error"
      :message="errorMessage"
      @close="errorMessage = ''"
    />
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted } from 'vue'
import { aiAgentsApi } from '@/utils/aiAgents'
import Alert from '@/components/common/Alert.vue'

export default {
  name: 'AgentScanForm',
  components: {
    Alert
  },
  emits: ['submit', 'success', 'error'],
  setup(props, { emit }) {
    const formData = ref({
      target: '',
      taskName: '',
      enableLLMPlanning: true,
      needCustomScan: false,
      customScanType: 'web',
      customScanRequirements: '',
      customScanLanguage: 'python',
      needCapabilityEnhancement: false,
      capabilityRequirement: '',
      useCustomTasks: false,
      customTasks: []
    })

    const availableTools = ref([])
    const isSubmitting = ref(false)
    const errorMessage = ref('')
    const labTargetListener = ref(null)

    const loadTools = async () => {
      try {
        const response = await aiAgentsApi.getTools()
        if (response && response.data && response.data.tools) {
          availableTools.value = response.data.tools
        } else {
          console.warn('工具列表响应格式异常:', response)
          availableTools.value = []
        }
      } catch (error) {
        console.error('加载工具列表失败:', error)
        availableTools.value = []
      }
    }

    const handleSubmit = async () => {
      if (isSubmitting.value) return

      isSubmitting.value = true
      errorMessage.value = ''

      try {
        const scanData = {
          target: formData.value.target,
          enable_llm_planning: formData.value.enableLLMPlanning,
          custom_tasks: formData.value.useCustomTasks ? formData.value.customTasks : null,
          need_custom_scan: formData.value.needCustomScan,
          custom_scan_type: formData.value.customScanType,
          custom_scan_requirements: formData.value.customScanRequirements,
          custom_scan_language: formData.value.customScanLanguage,
          need_capability_enhancement: formData.value.needCapabilityEnhancement,
          capability_requirement: formData.value.capabilityRequirement
        }

        emit('submit', { formData: formData.value, scanData })

      } catch (error) {
        errorMessage.value = error.message || error.response?.data?.message || '网络错误，请稍后重试'
        emit('error', error)
      } finally {
        isSubmitting.value = false
      }
    }

    const handleReset = () => {
      formData.value = {
        target: '',
        taskName: '',
        enableLLMPlanning: true,
        needCustomScan: false,
        customScanType: 'web',
        customScanRequirements: '',
        customScanLanguage: 'python',
        needCapabilityEnhancement: false,
        capabilityRequirement: '',
        useCustomTasks: false,
        customTasks: []
      }
      errorMessage.value = ''
    }

    onMounted(() => {
      loadTools()
      if (typeof window !== 'undefined') {
        labTargetListener.value = (event) => {
          const target = event.detail || {}
          if (!target.url) return
          formData.value.target = target.url
          formData.value.taskName = `${target.name || '公开靶场'} 扫描测试`
        }
        window.addEventListener('toskill:lab-target-selected', labTargetListener.value)
      }
    })

    onUnmounted(() => {
      if (typeof window !== 'undefined' && labTargetListener.value) {
        window.removeEventListener('toskill:lab-target-selected', labTargetListener.value)
        labTargetListener.value = null
      }
    })

    return {
      formData,
      availableTools,
      isSubmitting,
      errorMessage,
      handleSubmit,
      handleReset
    }
  }
}
</script>

<style scoped>
.agent-scan-form {
  max-width: 900px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.agent-scan-form h2 {
  margin-bottom: var(--spacing-xl);
  color: var(--text-primary);
}

.form-group {
  margin-bottom: var(--spacing-lg);
}

.form-group label {
  display: block;
  margin-bottom: var(--spacing-sm);
  font-weight: 500;
  color: var(--text-primary);
}

.form-group input[type="text"],
.form-group input[type="number"],
.form-group select,
.form-group textarea {
  width: 100%;
  padding: var(--spacing-sm) var(--spacing-md);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  font-size: 1rem;
  transition: border-color 0.3s;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--color-primary);
}

.form-group textarea {
  resize: vertical;
  min-height: 100px;
}

.help-text {
  display: block;
  margin-top: var(--spacing-xs);
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.custom-scan-config,
.capability-config,
.custom-tasks-config {
  margin-left: var(--spacing-lg);
  padding-left: var(--spacing-lg);
  border-left: 2px solid var(--color-primary);
}

.tools-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: var(--spacing-md);
  margin-top: var(--spacing-md);
}

.tool-item {
  display: flex;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  cursor: pointer;
  transition: all 0.3s;
}

.tool-item:hover {
  background-color: var(--color-primary-bg);
  border-color: var(--color-primary);
}

.tool-item input[type="checkbox"] {
  cursor: pointer;
  margin-top: 4px;
}

.tool-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.tool-name {
  font-weight: 600;
  color: var(--text-primary);
}

.tool-description {
  font-size: 0.875rem;
  color: var(--text-secondary);
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
  background: linear-gradient(135deg, var(--color-primary) 0%, var(--color-accent) 100%);
  color: #1a1a1a;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
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
</style>
