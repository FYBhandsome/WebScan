<template>
  <div id="page-settings" class="page active">
    <div class="page-header">
      <h2>系统设置</h2>
      <div class="page-header-meta">
        <p class="page-subtitle">配置服务器连接与扫描参数</p>
        <span class="autosave-status" :class="{ 'is-saving': autosaveState === 'saving' }">
          <Check :size="14" />
          {{ autosaveMessage }}
        </span>
      </div>
    </div>

    <div class="settings-container">
      <div class="settings-card settings-card--connection">
        <div class="card-header">
          <Server :size="20" class="card-icon" />
          <span class="card-title">服务器连接</span>
        </div>
        <div class="card-body">
          <div class="field-row">
            <label class="field-label">
              <Globe :size="16" class="label-icon" />
              API 地址
            </label>
            <input
              type="text"
              class="settings-input"
              v-model="settings.apiUrl"
              placeholder="http://localhost:8081"
            />
          </div>
          <div class="field-row">
            <label class="field-label">
              <Radio :size="16" class="label-icon" />
              WebSocket 地址
            </label>
            <input
              type="text"
              class="settings-input"
              v-model="settings.wsUrl"
              placeholder="ws://localhost:8081"
            />
          </div>
          <div class="card-footer-actions">
            <button class="btn-test" @click="testConn" :disabled="connState === 'testing'">
              <Loader v-if="connState === 'testing'" :size="14" class="spinning" />
              <Wifi v-else :size="14" />
              测试连接
            </button>
            <Transition name="fade-status">
              <div v-if="connState !== 'idle'" class="conn-result" :class="connState">
                <span class="conn-dot"></span>
                <span class="conn-text">{{ connMessage }}</span>
              </div>
            </Transition>
          </div>
        </div>
      </div>

      <div class="settings-card settings-card--scan">
        <div class="card-header">
          <Clock :size="20" class="card-icon" />
          <span class="card-title">扫描配置</span>
        </div>
        <div class="card-body">
          <div class="field-row">
            <label class="field-label">
              扫描超时
            </label>
            <div class="timeout-field">
              <input
                type="number"
                class="settings-input"
                v-model="settings.timeout"
                placeholder="300"
                min="10"
                max="3600"
              />
              <span class="timeout-suffix">秒</span>
            </div>
            <p class="field-hint">范围 10-3600 秒，默认 300 秒（5 分钟）</p>
          </div>
        </div>
      </div>

      <div class="settings-card settings-card--wide">
        <div class="card-header">
          <Database :size="20" class="card-icon" />
          <span class="card-title">RAG 知识库</span>
        </div>
        <div class="card-body">
          <div v-if="ragLoading" class="rag-loading">
            <Loader :size="16" class="spinning" />
            正在读取知识库状态…
          </div>
          <template v-else-if="ragStatus">
            <div class="rag-status-grid">
              <div class="rag-status-item">
                <span class="rag-status-label">模型已加载</span>
                <span class="rag-status-value" :class="ragStatus.embed_model_loaded ? 'is-ready' : 'is-error'">
                  {{ ragStatus.embed_model_loaded ? '是' : '否' }}
                </span>
              </div>
              <div class="rag-status-item">
                <span class="rag-status-label">索引就绪</span>
                <span class="rag-status-value" :class="ragStatus.ready ? 'is-ready' : 'is-error'">
                  {{ ragStatus.ready ? '是' : '否' }}
                </span>
              </div>
              <div class="rag-status-item">
                <span class="rag-status-label">索引状态</span>
                <span class="rag-status-value" :class="`status-${ragStatus.index_status}`">
                  {{ formatRagStatus(ragStatus.index_status) }}
                </span>
              </div>
              <div class="rag-status-item">
                <span class="rag-status-label">知识文档</span>
                <span class="rag-status-value">{{ ragStatus.document_count }} 个</span>
              </div>
            </div>
            <p class="rag-model">嵌入模型：{{ ragStatus.embed_model || '未配置' }} · 版本：{{ ragStatus.knowledge_base_version || '未生成' }}</p>
            <p v-if="ragStatus.model_load_error" class="rag-error">{{ ragStatus.model_load_error }}</p>
            <p v-else-if="!ragStatus.enabled" class="rag-hint">RAG 当前未启用，无法重建向量索引。</p>
            <div class="card-footer-actions rag-actions">
              <button
                class="btn-rebuild-rag"
                @click="confirmRebuildRagIndex"
                :disabled="rebuilding || !ragStatus.enabled"
              >
                <Loader v-if="rebuilding" :size="15" class="spinning" />
                <RefreshCw v-else :size="15" />
                {{ rebuilding ? '正在重建索引…' : '重建向量索引' }}
              </button>
              <button class="btn-refresh-rag" @click="refreshRagStatus" :disabled="rebuilding">
                <RefreshCw :size="14" :class="{ spinning: ragLoading }" />
                刷新状态
              </button>
            </div>
          </template>
          <div v-else class="rag-unavailable">
            <AlertCircle :size="16" />
            <span>{{ ragError || '无法读取 RAG 知识库状态' }}</span>
            <button class="btn-refresh-rag" @click="refreshRagStatus">重试</button>
          </div>
        </div>
      </div>

      <div class="settings-card settings-card--wide">
        <div class="card-header">
          <Database :size="20" class="card-icon" />
          <span class="card-title">数据管理</span>
        </div>
        <div class="card-body">
          <div class="data-management-layout">
            <div class="data-info-row">
              <div class="data-info-item">
                <span class="data-info-label">记忆数据占用</span>
                <span class="data-info-value">{{ storageUsage.label }}</span>
              </div>
              <div class="data-info-item">
                <span class="data-info-label">会话数量</span>
                <span class="data-info-value">{{ conversationState.conversations.length }} / 20</span>
              </div>
            </div>
            <p class="data-hint">
              <span>记忆数据包括：会话记录、扫描状态、界面偏好（不含服务器配置与脚本历史）。</span>
              <span>超过 24 小时的数据将自动清理。</span>
            </p>
            <button class="btn-clear-memory" @click="confirmClearMemory">
              <Trash2 :size="14" />
              清除所有记忆数据
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, onMounted, onBeforeUnmount, watch } from 'vue'
import { Server, Globe, Radio, Clock, Check, Wifi, Loader, Database, Trash2, RefreshCw, AlertCircle } from 'lucide-vue-next'
import { API } from '../../services/api.js'
import { ws } from '../../services/websocket.js'
import { showToast, showModal, conversationState, clearAllMemoryData, getStorageUsage } from '../../store.js'

const STORAGE_KEY = 'toskill_settings'

function loadSettings() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      return JSON.parse(raw)
    }
  } catch (e) { /* ignore */ }
  return null
}

const saved = loadSettings()

const settings = reactive({
  apiUrl: saved?.apiUrl || 'http://localhost:8081',
  wsUrl: saved?.wsUrl || `ws://localhost:8081${API.WS_PATH}`,
  timeout: saved?.timeout || 300
})

if (saved) {
  API.setBaseUrl(settings.apiUrl)
}

const connState = ref('idle')
const connMessage = ref('')
const storageUsage = ref({ bytes: 0, label: '0 B' })
const ragStatus = ref(null)
const ragLoading = ref(false)
const rebuilding = ref(false)
const ragError = ref('')
const autosaveState = ref('saved')
const autosaveMessage = ref('更改将自动保存')
let autosaveTimer = null
let reconnectAfterAutosave = false

const refreshStorageUsage = () => {
  storageUsage.value = getStorageUsage()
}

onMounted(() => {
  refreshStorageUsage()
  refreshRagStatus()
})

const persistSettings = () => {
  autosaveTimer = null
  API.setBaseUrl(settings.apiUrl)
  ws.setUrl(settings.wsUrl)

  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    apiUrl: settings.apiUrl,
    wsUrl: settings.wsUrl,
    timeout: settings.timeout
  }))

  if (reconnectAfterAutosave) {
    ws.disconnect()
    void ws.connect().catch(() => {})
    reconnectAfterAutosave = false
  }
  autosaveState.value = 'saved'
  autosaveMessage.value = '已自动保存'
}

const scheduleAutoSave = (current, previous) => {
  autosaveState.value = 'saving'
  autosaveMessage.value = '正在自动保存…'
  reconnectAfterAutosave ||= current[0] !== previous[0] || current[1] !== previous[1]
  clearTimeout(autosaveTimer)
  autosaveTimer = setTimeout(persistSettings, 600)
}

watch(
  () => [settings.apiUrl, settings.wsUrl, settings.timeout],
  scheduleAutoSave
)

onBeforeUnmount(() => {
  if (autosaveTimer) {
    clearTimeout(autosaveTimer)
    persistSettings()
  }
})

const testConn = async () => {
  connState.value = 'testing'
  connMessage.value = '正在检测服务器连通性...'

  const start = performance.now()

  try {
    await API.healthCheck()
    const elapsed = Math.round(performance.now() - start)
    connState.value = 'success'
    connMessage.value = `连接成功  ·  响应时间 ${elapsed}ms`
  } catch (error) {
    connState.value = 'error'
    connMessage.value = error.message || '无法连接到服务器'
  }
}

const formatRagStatus = (status) => ({
  ready: '最新',
  rebuilding: '重建中',
  disabled: '未启用',
  not_ready: '未就绪',
  error: '异常'
}[status] || '未知')

const refreshRagStatus = async () => {
  ragLoading.value = true
  ragError.value = ''
  try {
    const response = await API.getRagStatus()
    ragStatus.value = response.data || null
    if (!ragStatus.value) {
      ragError.value = '服务器未返回知识库状态'
    }
  } catch (error) {
    ragStatus.value = null
    ragError.value = error.message || '无法连接到 RAG 管理服务'
  } finally {
    ragLoading.value = false
  }
}

const confirmRebuildRagIndex = () => {
  showModal(
    '重建向量索引',
    '将根据当前知识库文档重新生成向量索引。重建期间可继续使用旧索引；完成后将自动切换到新索引。<br><br>是否继续？',
    rebuildRagIndex
  )
}

const rebuildRagIndex = async () => {
  rebuilding.value = true
  ragError.value = ''
  try {
    const response = await API.rebuildRagIndex()
    ragStatus.value = response.data || ragStatus.value
    showToast(response.message || 'RAG 向量索引重建成功', 'success')
  } catch (error) {
    ragError.value = error.message || 'RAG 向量索引重建失败'
    showToast(ragError.value, 'error')
  } finally {
    rebuilding.value = false
    await refreshRagStatus()
  }
}

const confirmClearMemory = () => {
  showModal(
    '清除所有记忆数据',
    '此操作将清除所有会话记录、扫描状态与界面偏好数据，<strong>不可撤销</strong>。<br><br>清除后页面将自动刷新，应用回到初始状态。<br><br>是否继续？',
    () => {
      clearAllMemoryData()
      showToast('已清除所有记忆数据', 'success')
      // 延迟刷新，让 toast 显示
      setTimeout(() => {
        location.reload()
      }, 500)
    }
  )
}
</script>

<style scoped>
.page-header {
  margin-bottom: 32px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
}

.page-header h2 {
  font-size: 24px;
  font-weight: 600;
  color: #000000;
  margin: 0;
}

.page-header-meta {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 12px 18px;
}

.page-subtitle {
  font-size: 14px;
  color: #888888;
  margin: 0;
}

.autosave-status {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: #059669;
  font-size: 12px;
  white-space: nowrap;
}

.autosave-status.is-saving {
  color: #71717A;
}

.settings-container {
  width: 100%;
  max-width: 1180px;
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(360px, 1fr);
  gap: 20px;
}

.settings-card {
  background: #FAFAFA;
  border: 1px solid #EAEAEA;
}

.settings-card--wide {
  grid-column: 1 / -1;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 24px 0;
}

.card-icon {
  color: #888888;
  flex-shrink: 0;
}

.card-title {
  font-size: 18px;
  font-weight: 600;
  color: #000000;
}

.card-body {
  padding: 20px 24px 24px;
}

.field-row {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
}

.field-row:last-child {
  margin-bottom: 0;
}

.field-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 500;
  color: #52525B;
  white-space: nowrap;
  flex-shrink: 0;
  min-width: 130px;
}

.label-icon {
  color: #888888;
  flex-shrink: 0;
}

.settings-input {
  flex: 1;
  min-width: 0;
  padding: 10px 14px;
  font-size: 14px;
  font-family: inherit;
  color: #000000;
  background: #FFFFFF;
  border: 1px solid #E4E4E7;
  outline: none;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.settings-input:focus {
  border-color: #10B981;
  box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
}

.settings-input::placeholder {
  color: #A1A1AA;
}

.timeout-field {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 0 0 auto;
}

.timeout-field .settings-input {
  flex: none;
  width: 100px;
}

.timeout-suffix {
  font-size: 14px;
  color: #52525B;
  flex-shrink: 0;
}

.field-hint {
  margin: 0;
  font-size: 12px;
  color: #A1A1AA;
  line-height: 1.4;
  white-space: nowrap;
}

.settings-card--scan .field-row {
  flex-wrap: wrap;
  row-gap: 8px;
}

.settings-card--scan .field-hint {
  flex-basis: 100%;
  margin-left: 0px;
  white-space: normal;
}

.rag-status-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.rag-status-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 5px;
  min-height: 72px;
  padding: 10px 12px;
  border: 1px solid #E4E4E7;
  background: #FFFFFF;
  text-align: center;
}

.rag-status-label {
  font-size: 12px;
  color: #888888;
}

.rag-status-value {
  font-size: 16px;
  font-weight: 600;
  color: #18181B;
}

.rag-status-value.is-ready,
.rag-status-value.status-ready {
  color: #059669;
}

.rag-status-value.is-error,
.rag-status-value.status-error {
  color: #DC2626;
}

.rag-status-value.status-rebuilding,
.rag-status-value.status-not_ready,
.rag-status-value.status-disabled {
  color: #A16207;
}

.rag-model,
.rag-hint,
.rag-error {
  margin: 14px 0 0;
  font-size: 12px;
  line-height: 1.5;
}

.rag-model,
.rag-hint {
  color: #71717A;
}

.rag-error {
  color: #DC2626;
}

.rag-loading,
.rag-unavailable {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 38px;
  color: #71717A;
  font-size: 13px;
}

.rag-unavailable {
  color: #DC2626;
}

.rag-unavailable .btn-refresh-rag {
  margin-left: auto;
}

.rag-actions {
  margin-top: 16px;
}

.btn-rebuild-rag,
.btn-refresh-rag {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  padding: 8px 16px;
  font-family: inherit;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-rebuild-rag {
  color: #FFFFFF;
  background: #111827;
  border: 1px solid #111827;
}

.btn-rebuild-rag:hover:not(:disabled) {
  background: #059669;
  border-color: #059669;
}

.btn-refresh-rag {
  color: #52525B;
  background: transparent;
  border: 1px solid #D4D4D8;
}

.btn-refresh-rag:hover:not(:disabled) {
  color: #000000;
  border-color: #000000;
  background: #F4F4F5;
}

.btn-rebuild-rag:disabled,
.btn-refresh-rag:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.card-footer-actions {
  margin-top: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  flex-wrap: wrap;
}

.btn-test {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 8px 18px;
  font-size: 13px;
  font-weight: 500;
  font-family: inherit;
  color: #000000;
  background: transparent;
  border: 1px solid #E4E4E7;
  cursor: pointer;
  transition: all 0.15s ease;
  white-space: nowrap;
}

.btn-test:hover:not(:disabled) {
  border-color: #000000;
  background: #F4F4F5;
}

.btn-test:active:not(:disabled) {
  transform: scale(0.97);
}

.btn-test:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.spinning {
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.conn-result {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  font-size: 13px;
  background: #F4F4F5;
  border-left: 3px solid;
  line-height: 1;
}

.conn-result.success {
  border-color: #10B981;
  color: #000000;
}

.conn-result.error {
  border-color: #FF3B30;
  color: #000000;
}

.conn-result.testing {
  border-color: #888888;
  color: #52525B;
}

.conn-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.conn-result.success .conn-dot {
  background: #10B981;
}

.conn-result.error .conn-dot {
  background: #FF3B30;
}

.conn-result.testing .conn-dot {
  background: #888888;
  animation: dot-pulse 1.2s ease-in-out infinite;
}

@keyframes dot-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

.conn-text {
  white-space: nowrap;
}

.fade-status-enter-active {
  transition: opacity 0.25s ease, transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

.fade-status-leave-active {
  transition: opacity 0.2s ease, transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

.fade-status-enter-from {
  opacity: 0;
  transform: translateX(-8px);
}

.fade-status-leave-to {
  opacity: 0;
  transform: translateX(-8px);
}

.data-management-layout {
  display: grid;
  grid-template-columns: minmax(220px, 0.9fr) minmax(320px, 1.5fr) auto;
  align-items: center;
  gap: 24px;
}

/* 数据管理卡片样式 */
.data-info-row {
  display: flex;
  gap: 24px;
}

.data-info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.data-info-label {
  font-size: 12px;
  color: #888888;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.data-info-value {
  font-size: 18px;
  font-weight: 600;
  color: #000000;
  font-variant-numeric: tabular-nums;
}

.data-hint {
  margin: 0;
  font-size: 12px;
  color: #A1A1AA;
  line-height: 1.6;
  text-align: left;
}

.data-hint span {
  display: block;
}

.btn-clear-memory {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 8px 18px;
  font-size: 13px;
  font-weight: 500;
  font-family: inherit;
  color: #FF3B30;
  background: transparent;
  border: 1px solid #FF3B30;
  cursor: pointer;
  transition: all 0.15s ease;
  white-space: nowrap;
}

.btn-clear-memory:hover {
  background: #FEF2F2;
}

.btn-clear-memory:active {
  transform: scale(0.97);
}

@media (max-width: 1024px) {
  .settings-container {
    max-width: 100%;
    grid-template-columns: 1fr;
  }

  .settings-card--wide {
    grid-column: auto;
  }

  .rag-status-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .data-management-layout {
    grid-template-columns: minmax(0, 1fr) auto;
  }

  .data-hint {
    grid-column: 1 / -1;
    grid-row: 2;
  }
}

@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    gap: 8px;
  }

  .page-header-meta {
    justify-content: flex-start;
  }

  .card-header {
    padding: 16px 16px 0;
  }

  .card-body {
    padding: 16px;
  }

  .field-row {
    flex-direction: column;
    align-items: stretch;
    gap: 8px;
  }

  .field-label {
    min-width: auto;
  }

  .field-hint {
    white-space: normal;
  }

  .settings-card--scan .field-hint {
    margin-left: 0;
  }

  .timeout-field {
    flex: 1;
  }

  .timeout-field .settings-input {
    flex: 1;
    width: auto;
  }

  .rag-status-grid {
    grid-template-columns: 1fr;
  }

  .data-management-layout {
    grid-template-columns: 1fr;
    gap: 16px;
  }

  .data-hint {
    grid-column: auto;
    grid-row: auto;
  }

  .rag-unavailable {
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .rag-unavailable .btn-refresh-rag {
    width: 100%;
    margin-left: 0;
  }

  .card-footer-actions {
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
  }

  .btn-test {
    justify-content: center;
  }

  .conn-result {
    justify-content: center;
  }

  .btn-clear-memory {
    width: 100%;
    justify-content: center;
  }
}
</style>
