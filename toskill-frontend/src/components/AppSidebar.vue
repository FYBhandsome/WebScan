<template>
  <aside class="app-sidebar">
    <div class="sidebar-header">
      <div class="logo-box"></div>
    </div>

    <nav class="sidebar-nav">
      <a 
        href="#" 
        class="nav-item" 
        :class="{ active: currentPage === 'console' }"
        @click.prevent="navigate('console')"
      >
        <Terminal class="nav-icon" />
        <span>控制台</span>
      </a>

      <a 
        href="#" 
        class="nav-item" 
        :class="{ active: currentPage === 'scan' }"
        @click.prevent="navigate('scan')"
      >
        <ScanSearch class="nav-icon" />
        <span>扫描</span>
      </a>

      <a 
        href="#" 
        class="nav-item" 
        :class="{ active: currentPage === 'tools' }"
        @click.prevent="navigate('tools')"
      >
        <Wrench class="nav-icon" />
        <span>工具</span>
      </a>

      <a 
        href="#" 
        class="nav-item" 
        :class="{ active: currentPage === 'reports' }"
        @click.prevent="navigate('reports')"
      >
        <FileText class="nav-icon" />
        <span>报告</span>
      </a>

      <a 
        href="#" 
        class="nav-item" 
        :class="{ active: currentPage === 'settings' }"
        @click.prevent="navigate('settings')"
      >
        <Settings class="nav-icon" />
        <span>设置</span>
      </a>
    </nav>
  </aside>
</template>

<script setup>
import { Terminal, ScanSearch, Wrench, FileText, Settings } from 'lucide-vue-next'

// 1. 接收来自大管家 App.vue 的当前页面状态
const props = defineProps({
  currentPage: {
    type: String,
    required: true,
    default: 'console'
  }
})

// 2. 声明我们要向外发送的事件 (通知 App.vue 切换页面)
const emit = defineEmits(['navigate'])

// 3. 点击按钮时，不再修改本地变量，而是直接向上级汇报
const navigate = (route) => {
  emit('navigate', route)
}
</script>

<style scoped>
.app-sidebar {
  width: 150px;
  background-color: #ffffff;
  border-right: 1px solid #eaeaea; /* 极细的分割线 */
  display: flex;
  flex-direction: column;
  padding: 32px 0;
}

.sidebar-nav {
  display: flex;
  flex-direction: column;
  gap: 8px; /* 菜单项之间的间距 */
  padding: 0 16px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  text-decoration: none;
  border-radius: 6px;
  position: relative;
  
  /* 默认未选中状态：降噪处理 */
  color: #888888;
  font-size: 14px;
  font-weight: 500;
  transition: all 0.2s ease;
}

.nav-icon {
  width: 18px;
  height: 18px;
  stroke-width: 2px;
  transition: stroke 0.2s ease;
}

/* 悬浮态：轻微变暗 */
.nav-item:hover {
  color: #333333;
  background-color: #f9f9f9;
}

/* === 核心：极简高级选中态 === */
.nav-item.active {
  color: #000000; /* 纯黑，最高对比度 */
  font-weight: 600;
  background-color: transparent; /* 去掉廉价的背景底色 */
}

/* 选中态的侧边细线指示器 */
.nav-item.active::before {
  content: '';
  position: absolute;
  left: -16px; /* 贴紧侧边栏最左侧 */
  top: 10%;
  height: 80%;
  width: 3px;
  background-color: #000000; /* 纯黑色线条 */
  border-radius: 0 4px 4px 0;
}
</style>