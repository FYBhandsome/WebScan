<template>
  <div class="history-rail">
    <div class="rail-track">
      <div 
        v-for="(node, index) in nodes" 
        :key="node.id || index"
        class="rail-item"
        :class="{ 'is-active': activeId === node.id }"
        @click="scrollToBlock(node.id)"
      >
        <span class="node-label">{{ getLabel(node) }}</span>
        
        <div class="node-dash"></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'

const props = defineProps({
  blocks: {
    type: Array,
    default: () => []
  }
})

const emit = defineEmits(['navigate'])

// 当前激活的区块 ID
const activeId = ref(null)

// 从工作区的 block 列表中提取关键里程碑
const nodes = computed(() => {
  const filtered = props.blocks.filter(b => 
    b.type === 'user_command' || 
    b.type === 'agent_action_request' || 
    (b.type === 'agent_text' && b.reportUrl)
  )
  
  if (filtered.length > 0 && !activeId.value) {
    activeId.value = filtered[filtered.length - 1].id
  }
  return filtered
})

watch(() => nodes.value.length, (newLen, oldLen) => {
  if (newLen > oldLen && nodes.value.length > 0) {
    activeId.value = nodes.value[nodes.value.length - 1].id
  }
})

const getLabel = (node) => {
  if (node.type === 'user_command') {
    return node.content.length > 8 ? node.content.slice(0, 8) + '...' : node.content
  }
  if (node.type === 'agent_action_request') return '操作确认'
  if (node.reportUrl) return '扫描报告'
  return '对话节点'
}

const scrollToBlock = (id) => {
  activeId.value = id
  emit('navigate', id)
}
</script>

<style scoped>
/* ==========================================
   DeepSeek Style 隐形导航交互 (Hover to Reveal)
========================================== */

/* 1. 外层容器 */
.history-rail {
  width: 48px; /* 默认宽度 */
  height: 100%; 
  display: flex;
  flex-direction: column;
  align-items: flex-end; /* 保证子元素靠右，给最右侧的滚动条留出位置 */
  background: transparent;
  flex-shrink: 0;
  transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  z-index: 20;
  
  /* 开启垂直滚动，隐藏水平滚动 */
  overflow-y: auto;
  overflow-x: hidden;
}

/* 2. 自定义 Webkit 滚动条：极简、半透明、靠最右 */
.history-rail::-webkit-scrollbar {
  width: 4px; /* 极细的滚动条 */
}
.history-rail::-webkit-scrollbar-track {
  background: transparent; /* 轨道完全透明 */
}
.history-rail::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.15); /* 极低透明度的灰色 */
  border-radius: 4px;
}
.history-rail:hover::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.35); /* 鼠标移入导航栏时，稍微加深一点以便看清 */
}

/* 当鼠标悬停整个导航区域时，宽度展开 */
.history-rail:hover {
  width: 140px; 
}

/* 3. 轨道容器 */
.rail-track {
  display: flex;
  flex-direction: column;
  gap: 18px; 
  width: 100%;
  
  /* 核心修改：使用 margin: auto 0 替代父级的 justify-content: center。
     效果：内容少时绝对居中，内容多时正常滚动到底部，不会裁切顶部内容 */
  margin: auto 0; 
  padding: 40px 0;
}

/* 4. 单个节点包裹层 */
.rail-item {
  display: flex;
  align-items: center;
  justify-content: flex-end; 
  cursor: pointer;
  position: relative;
  height: 24px;
  /* 右侧 padding：确保横线和滚动条之间有一点间距，不会贴在一起 */
  padding-right: 12px; 
}

/* 5. 左侧文字标签 */
.node-label {
  font-size: 13px;
  color: #888;
  white-space: nowrap;
  
  opacity: 0;
  transform: translateX(8px);
  pointer-events: none; 
  
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  margin-right: 12px; 
}

.history-rail:hover .node-label {
  opacity: 1;
  transform: translateX(0);
}

.rail-item:hover .node-label {
  color: #111;
}

/* 6. 右侧短横线 */
.node-dash {
  width: 10px;
  height: 3px;
  background-color: #D4D4D8;
  border-radius: 2px;
  flex-shrink: 0;
  transition: all 0.3s ease;
}

.rail-item:hover .node-dash {
  background-color: #A1A1AA;
}

/* 7. 激活状态 (TOSKill 品牌绿) */
.rail-item.is-active .node-dash {
  background-color: #10B981; 
  width: 14px; 
}

.rail-item.is-active .node-label {
  color: #10B981; 
  font-weight: 600;
}

/* 针对小屏幕设备默认隐藏该组件 */
@media (max-width: 1024px) {
  .history-rail { display: none; }
}
</style>