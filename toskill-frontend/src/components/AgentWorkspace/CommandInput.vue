<template>
  <div class="command-center" ref="containerRef" @click.stop>
    
    <transition name="pop-fade">
      <div v-if="showActions" class="action-popover">
        <div class="popover-list">
          
          <button class="action-item" @click="handleAction('info')">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <span class="text">信息收集</span>
          </button>
          
          <button class="action-item" @click="handleAction('vuln')">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
            <span class="text">漏洞扫描</span>
          </button>
          
          <button class="action-item" @click="handleAction('full')">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
            </svg>
            <span class="text">完整扫描</span>
          </button>

        </div>
      </div>
    </transition>

    <div class="input-wrapper" :class="{ 'is-focused': isFocused }">
      
      <button 
        class="action-toggle-btn" 
        :class="{ 'is-active': showActions }"
        @click="toggleActions"
        title="展开快捷指令"
      >
        <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <line x1="12" y1="5" x2="12" y2="19"></line>
          <line x1="5" y1="12" x2="19" y2="12"></line>
        </svg>
      </button>

      <input 
        type="text" 
        :value="modelValue"
        @input="$emit('update:modelValue', $event.target.value)"
        @keydown.enter.prevent="handleSend"
        @focus="isFocused = true"
        @blur="isFocused = false"
        placeholder="输入扫描目标或用自然语言与 Agent 对话..." 
        autocomplete="off"
        :disabled="disabled"
      >

      <button 
        @click="isActive ? $emit('stop') : handleSend()" 
        class="send-btn"
        :class="{ active: isActive }"
        :disabled="!isActive && (!modelValue.trim() || disabled)"
      >
        <svg v-if="isActive" viewBox="0 0 24 24" width="16" height="16" fill="currentColor" stroke="none">
          <rect x="6" y="6" width="12" height="12" rx="2"></rect>
        </svg>
        <svg v-else viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <line x1="12" y1="19" x2="12" y2="5"></line>
          <polyline points="5 12 12 5 19 12"></polyline>
        </svg>
      </button>
      
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const props = defineProps({
  modelValue: String,
  disabled: Boolean,
  isActive: Boolean
})

const emit = defineEmits(['update:modelValue', 'send', 'quick-action', 'stop'])

const showActions = ref(false)
const isFocused = ref(false)
const containerRef = ref(null)

// 切换菜单状态
const toggleActions = () => {
  showActions.value = !showActions.value
}

// 触发快捷指令并关闭菜单
const handleAction = (mode) => {
  emit('quick-action', mode)
  showActions.value = false
}

// 触发发送
const handleSend = () => {
  if (props.modelValue.trim() && !props.disabled) {
    emit('send')
    showActions.value = false
  }
}

// 点击组件外部自动关闭菜单
const handleClickOutside = (event) => {
  if (containerRef.value && !containerRef.value.contains(event.target)) {
    showActions.value = false
  }
}

onMounted(() => {
  document.addEventListener('click', handleClickOutside)
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})
</script>

<style scoped>
/* ==========================================
   TOSKill - 隐藏式折叠菜单输入舱
========================================== */
.command-center {
  position: relative;
  width: 100%;
  padding: 16px 20px 24px;
  background: #ffffff;
  z-index: 10;
  display: flex;
  flex-direction: column;
  align-items: center;
}

/* --- 1. 悬浮折叠菜单 (Popover) --- */
.action-popover {
  position: absolute;
  bottom: 100%;
  left: 100px;
  margin-bottom: 0px;
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(0, 0, 0, 0.08);
  border-radius: 2px; 
  padding: 6px; /* 去掉header后，内边距可以缩紧一点 */
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.08), 0 4px 12px rgba(0,0,0,0.04);
  width: 160px; /* 宽度也可以适当收窄 */
  z-index: 20;
  transform-origin: bottom left;
}

.popover-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.action-item {
  display: flex;
  align-items: center;
  gap: 12px;
  background: transparent;
  border: none;
  width: 100%;
  padding: 10px 12px;
  border-radius: 2px;
  cursor: pointer;
  transition: all 0.2s ease;
  color: #52525B; /* 默认文字颜色 */
  font-size: 14px;
  font-weight: 500;
  text-align: left;
}

.action-item:hover {
  background: rgba(16, 185, 129, 0.1);
  color: #10B981;
}

.action-item .icon { 
  width: 16px; 
  height: 16px;
  color: #A1A1AA; /* 极简极客灰 */
  transition: color 0.2s ease;
}

/* 悬停时的状态：背景微绿，文字和图标变成品牌色 */
.action-item:hover {
  background: rgba(16, 185, 129, 0.08);
  color: #10B981;
}

.action-item:hover .icon {
  color: #10B981; /* 悬停时图标亮起 */
}

/* Popover 动画 */
.pop-fade-enter-active,
.pop-fade-leave-active {
  transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.pop-fade-enter-from,
.pop-fade-leave-to {
  opacity: 0;
  transform: scale(0.9) translateY(10px);
}

/* --- 2. 核心输入框区 --- */
.input-wrapper {
  display: flex; 
  align-items: center; 
  background: #ffffff; 
  border: 1px solid #E4E4E7; 
  border-radius: 10px; /* 大圆角胶囊形 */
  padding: 2px 8px 2px 8px; 
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.04); 
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  width: 100%;
  max-width: 900px; /* 限制最大宽度，视觉更聚焦 */
}

.input-wrapper.is-focused { 
  border-color: #10B981; 
  box-shadow: 0 8px 24px rgba(16, 185, 129, 0.12); 
}

/* 左侧唤醒菜单按钮 */
.action-toggle-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: #F4F4F5;
  border: none;
  color: #52525B;
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  margin-right: 12px;
  flex-shrink: 0;
}

.action-toggle-btn:hover {
  background: #E4E4E7;
  color: #111;
}

.action-toggle-btn.is-active {
  background: #10B981;
  color: #fff;
}

.action-toggle-btn svg {
  transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.action-toggle-btn.is-active svg {
  transform: rotate(45deg); /* 点击展开时，加号变成叉号 */
}

.cli-prompt { 
  font-family: monospace; 
  font-weight: 900; 
  color: #10B981; 
  margin-right: 12px; 
  font-size: 16px; 
}

.input-wrapper input { 
  flex: 1; 
  border: none; 
  outline: none; 
  padding: 8px 0; 
  font-size: 15px; 
  background: transparent;
  color: #111;
}

.input-wrapper input::placeholder { color: #A1A1AA; }
.input-wrapper input:disabled { cursor: not-allowed; opacity: 0.6; }

/* --- 3. 发送按钮 (向上箭头) --- */
.send-btn { 
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  background-color: #18181B; 
  color: #ffffff; 
  border: none; 
  border-radius: 50%; 
  cursor: pointer; 
  transition: all 0.2s ease; 
  flex-shrink: 0;
  margin-left: 8px;
}

.send-btn:hover:not(:disabled) { 
  background-color: #10B981; 
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
  transform: translateY(-1px);
}

.send-btn:disabled { 
  background-color: #F4F4F5; 
  color: #A1A1AA; 
  cursor: not-allowed; 
}
.send-btn.active {
  background-color: #FEF2F2;
  color: #EF4444;
  border-color: #FECACA;
}
.send-btn.active:hover {
  background-color: #FEE2E2;
  border-color: #EF4444;
}
</style>