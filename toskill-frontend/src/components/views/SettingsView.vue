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
import { reactive, ref } from 'vue'
import { Server, Globe, Radio, Clock, Save, Wifi, Loader } from 'lucide-vue-next'
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
  wsUrl: saved?.wsUrl || 'ws://localhost:8081/api/ai-chat/ws',
  timeout: saved?.timeout || 300
})

if (saved) {
  API.setBaseUrl(settings.apiUrl)
}

const connState = ref('idle')
const connMessage = ref('')

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