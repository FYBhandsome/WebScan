<template>
<header class="app-header">
<div class="brand" style="display: flex; align-items: center; gap: 14px;">
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink: 0;">
    <path d="M4 10V4H10" stroke="#000000" stroke-width="2.5" stroke-linecap="square"/>
    <path d="M20 14V20H14" stroke="#000000" stroke-width="2.5" stroke-linecap="square"/>
    <circle cx="12" cy="12" r="3" fill="#10B981" />
  </svg>
  
  <div class="brand-text" style="
    /* 你可以把 font-family 换成以下三种之一来看看效果：
       1. 'Montserrat', sans-serif  (经典重工业宽体，极度平稳且霸气，最推荐)
       2. 'Orbitron', sans-serif    (纯正赛博朋克风，机甲感十足)
       3. 'Space Grotesk', sans-serif (前沿极客风，很多 AI 公司在用)
    */
    font-family: 'Montserrat', sans-serif; 
    font-weight: 900; 
    font-size: 22px; 
    letter-spacing: 0.5px;
    display: inline-block;
  ">
    <span style="color: #000000;">TOSK</span><span style="color: #10B981;">i</span><span style="color: #000000;">ll</span>
  </div>
</div>

    <div v-if="showScanProgress && hasProgress" class="header-scan-progress">
      <div class="header-progress-copy">
        <span>{{ progressLabel }}</span>
        <span>{{ scanProgress.current || 0 }} / {{ scanProgress.total || 0 }}</span>
      </div>
      <div class="header-progress-track">
        <div class="header-progress-fill" :style="{ width: `${progressPercent}%` }"></div>
      </div>
    </div>
    <div v-else class="header-center-placeholder"></div>

    <div class="system-status">
      <div class="status-dot" :class="{ online: status === '已连接' }"></div>
      <span class="status-text">{{ status }}</span>
    </div>
  </header>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  status: {
    type: String,
    default: '未连接'
  },
  scanProgress: {
    type: Object,
    default: () => ({ current: 0, total: 0, activeTool: '' })
  },
  scanStatus: {
    type: String,
    default: 'idle'
  },
  showScanProgress: Boolean
})

const progressStatuses = new Set([
  'queued',
  'scanning',
  'running',
  'waiting',
  'waiting_user',
  'pausing_for_chat',
  'paused_for_chat',
  'replanning',
  'reporting',
  'completed',
  'error'
])
const hasProgress = computed(() => (
  props.scanProgress?.total > 0 && progressStatuses.has(props.scanStatus)
))
const progressPercent = computed(() => {
  if (!props.scanProgress?.total) return 0
  return Math.min(100, Math.round(((props.scanProgress.current || 0) / props.scanProgress.total) * 100))
})
const progressLabel = computed(() => {
  if (props.scanStatus === 'completed') return '扫描完成'
  if (props.scanStatus === 'error') return '扫描异常'
  if (props.scanStatus === 'waiting') return '等待用户确认'
  if (props.scanStatus === 'idle') return '扫描已停止'
  return props.scanProgress?.activeTool ? `正在执行：${props.scanProgress.activeTool}` : '扫描准备中'
})
</script>

<style scoped>
@import url('https://fonts.font.im/css2?family=Montserrat:wght@900&family=Orbitron:wght@900&family=Space+Grotesk:wght@700&display=swap');
/* 顶栏容器：去除阴影，仅保留 1px 极细底边 */
.app-header {
  display: grid;
  grid-template-columns: minmax(180px, 1fr) minmax(280px, 620px) minmax(180px, 1fr);
  align-items: center;
  height: 64px;
  padding: 0 40px;
  background-color: #ffffff;
  border-bottom: 1px solid #eaeaea; /* 极简的灵魂在此 */
  /* box-shadow: none !important; 确保没有任何阴影 */
}

.header-scan-progress {
  width: 100%;
  justify-self: center;
  font-family: var(--font-family);
}

.header-progress-copy {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 5px;
  color: #52525b;
  font-size: 12px;
}

.header-progress-track {
  height: 3px;
  overflow: hidden;
  border-radius: 2px;
  background: #e4e4e7;
}

.header-progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #10b981, #0ea5e9);
  transition: width .3s ease;
}

.header-center-placeholder { min-width: 0; }

/* 品牌标识区 */
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-icon {
  width: 22px;
  height: 22px;
  color: #000000;
  stroke-width: 2px;
}

/* 排版对比学：TOSKill 极粗，Scanner 极细 */
.brand-text {
  font-size: 18px;
  letter-spacing: -0.5px;
  color: #000000;
}

.fw-bold {
  font-weight: 800;
}

.fw-light {
  font-weight: 400;
  color: #666666; /* 副标题稍微降噪 */
  margin-left: 6px;
}

/* 直接替换你原来的 .system-status 相关样式 */
.system-status {
  display: flex;
  align-items: center;
  gap: 8px; /* 圆点和文字的间距 */
  justify-self: end;
  /* 彻底删除 background, border, padding, border-radius */
}

/* 极其精密的极小圆点 */
.status-dot {
  width: 6px; 
  height: 6px;
  border-radius: 50%;
  background-color: #a1a1aa;
  box-shadow: none;
}

.status-dot.online { background-color: #10B981; box-shadow: 0 0 8px rgba(16, 185, 129, .8); }

/* 降噪的专业排版 */
.status-text {
  padding-left: 5px;
  font-size: 15px; /* 缩小字号 */
  font-weight: 600;
  color: #666666; /* 不要用纯黑，用中灰色让步给绿点 */
  letter-spacing: 0.5px; /* 微微拉开字间距，高级感来源 */
}


/* .system-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border-radius: 20px;
  background-color: #f9f9f9; 
  border: 1px solid #eaeaea;
}

.status-text {
  font-size: 13px;
  font-weight: 500;
  color: #333333;
}


.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: #10B981; 
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4);
  animation: pulse-green 2s infinite;
} */

@keyframes pulse-green {
  0% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
  }
  70% {
    transform: scale(1);
    box-shadow: 0 0 0 6px rgba(16, 185, 129, 0);
  }
  100% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0);
  }
}

@media (max-width: 820px) {
  .app-header { grid-template-columns: auto minmax(150px, 1fr) auto; gap: 16px; padding: 0 18px; }
  .header-progress-copy { font-size: 11px; }
}
</style>
