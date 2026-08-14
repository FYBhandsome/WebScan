<template>
  <div class="conv-sidebar">
    <!-- 收起按钮 -->
    <button class="collapse-btn" @click="$emit('collapse')" title="收起对话列表">
      <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="15 18 9 12 15 6"></polyline>
      </svg>
    </button>

    <!-- 新建对话按钮 -->
    <button class="new-conv-btn" @click="$emit('new-conversation')" title="新建对话">
      <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <line x1="12" y1="5" x2="12" y2="19"/>
        <line x1="5" y1="12" x2="19" y2="12"/>
      </svg>
      <span>新建对话</span>
    </button>

    <!-- 对话列表 -->
    <div class="conv-list">
      <div
        v-for="conv in conversations"
        :key="conv.id"
        class="conv-item"
        :class="{ 'is-active': conv.id === currentId }"
        @click="$emit('switch-conversation', conv.id)"
        @contextmenu.prevent="openContextMenu($event, conv)"
      >
        <span class="conv-status" :class="conv.status || 'idle'"></span>
        <span class="conv-title">{{ conv.title || '新对话' }}</span>
      </div>
    </div>

    <!-- 右键菜单 -->
    <Teleport to="body">
      <div
        v-if="contextMenu.show"
        class="context-menu"
        :style="{ left: contextMenu.x + 'px', top: contextMenu.y + 'px' }"
        @click.stop
      >
        <button class="menu-item" @click="startRename">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
          </svg>
          <span>重命名</span>
        </button>
        <button
          class="menu-item danger"
          @click="confirmDelete"
          :disabled="contextMenu.convId === currentId && scanActive"
        >
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
          </svg>
          <span>删除对话</span>
        </button>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const props = defineProps({
  conversations: Array,
  currentId: String,
  scanActive: Boolean
})

const emit = defineEmits(['new-conversation', 'switch-conversation',
                          'delete-conversation', 'rename-conversation', 'collapse'])

const contextMenu = ref({ show: false, x: 0, y: 0, convId: '' })

const openContextMenu = (e, conv) => {
  contextMenu.value = { show: true, x: e.clientX, y: e.clientY, convId: conv.id }
}

const startRename = () => {
  const conv = props.conversations.find(c => c.id === contextMenu.value.convId)
  if (!conv) return
  const newTitle = prompt('请输入新的会话名称', conv.title)
  if (newTitle && newTitle.trim()) {
    emit('rename-conversation', conv.id, newTitle.trim())
  }
  contextMenu.value.show = false
}

const confirmDelete = () => {
  const conv = props.conversations.find(c => c.id === contextMenu.value.convId)
  if (!conv) return
  if (confirm(`确定要删除对话"${conv.title}"吗？此操作不可撤销。`)) {
    emit('delete-conversation', conv.id)
  }
  contextMenu.value.show = false
}

const closeContextMenu = () => { contextMenu.value.show = false }
onMounted(() => document.addEventListener('click', closeContextMenu))
onUnmounted(() => document.removeEventListener('click', closeContextMenu))
</script>

<style scoped>
.conv-sidebar {
  width: 220px;
  height: 100%;
  background: #FAFAFA;
  border-right: 1px solid #EAEAEA;
  display: flex;
  flex-direction: column;
  position: relative;
  flex-shrink: 0;
}

.collapse-btn {
  position: absolute;
  top: 17px;
  right: 8px;
  width: 24px;
  height: 24px;
  border: none;
  background: transparent;
  color: #888;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
}
.collapse-btn:hover { background: #F4F4F5; color: #18181B; }

.new-conv-btn {
  margin: 12px;
  margin-right: 40px;
  padding: 8px 8px 8px 8px;
  display: flex;
  align-items: center;
  gap: 8px;
  background: #FFFFFF;
  border: 1px solid #E4E4E7;
  color: #18181B;
  font-size: 13px;
  cursor: pointer;
  border-radius: 6px;
}
.new-conv-btn:hover { border-color: #10B981; color: #10B981; }

.conv-list {
  flex: 1;
  overflow-y: auto;
  padding: 0 8px;
}

.conv-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  margin-bottom: 2px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  color: #52525B;
}
.conv-item:hover { background: #F4F4F5; }
.conv-item.is-active { background: #ECFDF5; color: #10B981; }

.conv-status {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.conv-status.idle { background: #D4D4D8; }
.conv-status.scanning { background: #10B981; animation: pulse 1.5s infinite; }
.conv-status.completed { background: #6366F1; }
.conv-status.failed { background: #EF4444; }
.conv-status.cancelled { background: #9CA3AF; }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.conv-title {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.context-menu {
  position: fixed;
  background: #FFFFFF;
  border: 1px solid #E4E4E7;
  border-radius: 6px;
  padding: 4px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.1);
  z-index: 1000;
  min-width: 140px;
}

.menu-item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px 12px;
  background: transparent;
  border: none;
  color: #18181B;
  font-size: 13px;
  cursor: pointer;
  border-radius: 4px;
  text-align: left;
}
.menu-item:hover { background: #F4F4F5; }
.menu-item.danger { color: #EF4444; }
.menu-item.danger:hover { background: #FEF2F2; }
.menu-item:disabled { opacity: 0.4; cursor: not-allowed; }
</style>
