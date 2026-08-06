<template>
  <div id="page-settings" class="page active">
    <div class="page-header">
      <h2>系统设置</h2>
      <p class="page-subtitle">配置服务器连接与扫描参数</p>
    </div>

    <div class="settings-container">
      <div class="settings-card">
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

      <div class="settings-card">
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

      <div class="settings-card rag-card">
        <div class="card-header">
          <Database :size="20" class="card-icon" />
          <span class="card-title">RAG 知识库</span>
        </div>
        <div class="card-body">
          <div v-if="ragError" class="rag-error">{{ ragError }}</div>
          <div class="rag-status-grid">
            <div class="rag-status-item"><span>模式</span><strong>{{ ragConfig.mode || '—' }}</strong></div>
            <div class="rag-status-item"><span>模型已加载</span><strong>{{ ragConfig.model_loaded ? '是' : '否' }}</strong></div>
            <div class="rag-status-item"><span>索引就绪</span><strong>{{ ragConfig.index_ready ? '是' : '否' }}</strong></div>
            <div class="rag-status-item"><span>索引状态</span><strong>{{ ragConfig.index_stale ? '已过期' : '最新' }}</strong></div>
            <div v-if="ragConfig.last_error" class="rag-status-item rag-status-item--error"><span>最近错误</span><strong>{{ ragConfig.last_error }}</strong></div>
          </div>
          <div class="rag-actions">
            <label class="field-label" for="rag-mode">运行模式</label>
            <select id="rag-mode" class="settings-input rag-mode-select" :value="ragConfig.mode" :disabled="ragLoading || ragModeChanging" @change="changeRagMode">
              <option v-for="mode in ragConfig.allowed_modes || ['mapping', 'vector']" :key="mode" :value="mode">{{ mode }}</option>
            </select>
            <button class="btn-test" :disabled="ragLoading || ragRebuilding" @click="rebuildIndex">
              <Loader v-if="ragRebuilding" :size="14" class="spinning" />
              <RefreshCw v-else :size="14" />
              {{ ragRebuilding ? `重建中（${ragRebuildStatus.status || 'queued'}）` : '重建向量索引' }}
            </button>
          </div>
          <div class="rag-upload">
            <label class="btn-test upload-label">
              <Upload :size="14" /> 上传 md/txt 文档
              <input type="file" accept=".md,.txt,text/markdown,text/plain" hidden @change="uploadDocument" />
            </label>
            <span v-if="ragUploading" class="field-hint">上传中...</span>
          </div>
          <div class="rag-documents">
            <div class="rag-documents-header"><strong>知识库文档</strong><button class="link-button" @click="loadRagData">刷新</button></div>
            <div v-if="!ragDocuments.length" class="field-hint">暂无 md/txt 文档</div>
            <button v-for="document in ragDocuments" :key="document.filename" class="rag-document" @click="viewDocument(document.filename)">
              <FileText :size="15" /> <span>{{ document.filename }}</span><small>{{ document.size }} B</small>
            </button>
          </div>
          <div v-if="selectedDocument" class="rag-document-viewer">
            <div class="rag-documents-header"><strong>{{ selectedDocument.filename }}</strong><button class="link-button" @click="selectedDocument = null">关闭</button></div>
            <pre>{{ selectedDocument.content }}</pre>
          </div>
        </div>
      </div>

      <div class="settings-card">
        <div class="card-body card-body--action">
          <button class="btn-save" @click="save">
            <Save :size="16" />
            保存设置
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { Database, FileText, Globe, Clock, Loader, Radio, RefreshCw, Save, Server, Upload, Wifi } from 'lucide-vue-next'
import { API } from '../../services/api.js'
import { ws } from '../../services/websocket.js'
import { showToast } from '../../store.js'

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
const ragConfig = reactive({ allowed_modes: ['mapping', 'vector'] })
const ragDocuments = ref([])
const selectedDocument = ref(null)
const ragError = ref('')
const ragLoading = ref(false)
const ragModeChanging = ref(false)
const ragUploading = ref(false)
const ragRebuilding = ref(false)
const ragRebuildStatus = reactive({ status: '', progress: 0 })
let ragPollTimer = null

const loadRagData = async () => {
  ragLoading.value = true
  ragError.value = ''
  try {
    const [config, documents] = await Promise.all([API.getRagConfig(), API.getRagDocuments()])
    Object.assign(ragConfig, config)
    ragDocuments.value = documents
  } catch (error) {
    ragError.value = error.message || '无法加载 RAG 配置'
  } finally {
    ragLoading.value = false
  }
}

const changeRagMode = async (event) => {
  const mode = event.target.value
  ragModeChanging.value = true
  ragError.value = ''
  try {
    Object.assign(ragConfig, await API.setRagMode(mode))
    showToast(`RAG 模式已切换为 ${mode}`, 'success')
  } catch (error) {
    ragError.value = error.message || '切换 RAG 模式失败'
    event.target.value = ragConfig.mode
  } finally {
    ragModeChanging.value = false
  }
}

const viewDocument = async (filename) => {
  ragError.value = ''
  try {
    selectedDocument.value = await API.getRagDocument(filename)
  } catch (error) {
    ragError.value = error.message || '无法读取文档'
  }
}

const uploadDocument = async (event) => {
  const file = event.target.files?.[0]
  event.target.value = ''
  if (!file) return
  ragUploading.value = true
  ragError.value = ''
  try {
    await API.uploadRagDocument(file)
    await loadRagData()
    showToast('文档上传成功', 'success')
  } catch (error) {
    ragError.value = error.message || '文档上传失败'
  } finally {
    ragUploading.value = false
  }
}

const stopRagPolling = () => {
  if (ragPollTimer) {
    clearTimeout(ragPollTimer)
    ragPollTimer = null
  }
}

const pollRagRebuild = async (operationId) => {
  try {
    const status = await API.getRagRebuildStatus(operationId)
    Object.assign(ragRebuildStatus, status)
    if (['queued', 'running'].includes(status.status)) {
      ragPollTimer = setTimeout(() => pollRagRebuild(operationId), 1000)
    } else {
      ragRebuilding.value = false
      await loadRagData()
      if (status.status === 'completed') showToast('RAG 索引重建完成', 'success')
      else ragError.value = status.error || 'RAG 索引重建失败'
    }
  } catch (error) {
    ragRebuilding.value = false
    ragError.value = error.message || '无法获取重建状态'
  }
}

const rebuildIndex = async () => {
  stopRagPolling()
  ragRebuilding.value = true
  ragError.value = ''
  try {
    const operation = await API.rebuildRagIndex()
    Object.assign(ragRebuildStatus, operation)
    pollRagRebuild(operation.operation_id)
  } catch (error) {
    ragRebuilding.value = false
    ragError.value = error.message || '无法触发索引重建'
  }
}

const save = () => {
  API.setBaseUrl(settings.apiUrl)
  ws.setUrl(settings.wsUrl)

  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    apiUrl: settings.apiUrl,
    wsUrl: settings.wsUrl,
    timeout: settings.timeout
  }))

  showToast('设置已成功保存！', 'success')

  ws.disconnect()
  ws.connect()
}

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

onMounted(loadRagData)
onBeforeUnmount(stopRagPolling)
</script>

<style scoped>
.page-header {
  margin-bottom: 32px;
}

.page-header h2 {
  font-size: 24px;
  font-weight: 600;
  color: #000000;
  margin-bottom: 6px;
}

.page-subtitle {
  font-size: 14px;
  color: #888888;
  margin: 0;
}

.settings-container {
  max-width: 640px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.settings-card {
  background: #FAFAFA;
  border: 1px solid #EAEAEA;
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

.card-body--action {
  padding: 20px 24px;
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

.btn-save {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 28px;
  font-size: 14px;
  font-weight: 500;
  font-family: inherit;
  color: #FFFFFF;
  background: #000000;
  border: none;
  cursor: pointer;
  transition: background 0.15s ease, transform 0.15s ease;
}

.btn-save:hover {
  background: #10B981;
}

.btn-save:active {
  transform: scale(0.98);
}

.rag-card {
  max-width: 100%;
}

.rag-status-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 20px;
}

.rag-status-item {
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 10px;
  background: #FFFFFF;
  border: 1px solid #E4E4E7;
  font-size: 12px;
  color: #71717A;
}

.rag-status-item strong {
  color: #000000;
  font-size: 13px;
  word-break: break-word;
}

.rag-status-item--error {
  grid-column: 1 / -1;
}

.rag-status-item--error strong,
.rag-error {
  color: #DC2626;
}

.rag-error {
  margin-bottom: 14px;
  padding: 10px 12px;
  background: #FEF2F2;
  font-size: 13px;
}

.rag-actions,
.rag-upload {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 18px;
}

.rag-mode-select {
  flex: 0 0 130px;
}

.upload-label {
  cursor: pointer;
}

.rag-documents {
  border-top: 1px solid #E4E4E7;
  padding-top: 16px;
}

.rag-documents-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
  font-size: 13px;
}

.link-button {
  padding: 0;
  border: none;
  background: transparent;
  color: #059669;
  cursor: pointer;
  font: inherit;
}

.rag-document {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 10px;
  border: none;
  border-bottom: 1px solid #F4F4F5;
  background: #FFFFFF;
  color: #27272A;
  cursor: pointer;
  text-align: left;
  font: inherit;
}

.rag-document:hover {
  background: #F4F4F5;
}

.rag-document span {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rag-document small {
  color: #A1A1AA;
}

.rag-document-viewer {
  margin-top: 18px;
  padding: 12px;
  background: #FFFFFF;
  border: 1px solid #E4E4E7;
}

.rag-document-viewer pre {
  max-height: 280px;
  margin: 0;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font: inherit;
  font-size: 12px;
  line-height: 1.6;
  color: #52525B;
}

@media (max-width: 600px) {
  .rag-status-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .rag-actions,
  .rag-upload {
    align-items: stretch;
    flex-direction: column;
  }

  .rag-mode-select {
    flex: 1;
  }
}

@media (max-width: 768px) {
  .settings-container {
    max-width: 100%;
  }

  .card-header {
    padding: 16px 16px 0;
  }

  .card-body {
    padding: 16px;
  }

  .card-body--action {
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

  .timeout-field {
    flex: 1;
  }

  .timeout-field .settings-input {
    flex: 1;
    width: auto;
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

  .btn-save {
    width: 100%;
    justify-content: center;
  }
}

@media (min-width: 1200px) {
  .settings-container {
    max-width: 680px;
  }
}
</style>