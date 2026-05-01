<template>
  <div class="app-layout">
    <el-container class="layout-container">
      <el-header class="header">
        <div class="header-content">
          <div class="logo-section">
            <el-button
              v-if="isMobile"
              circle
              @click="toggleMobileMenu"
              class="mobile-menu-btn"
            >
              <AppIcon name="Menu" :size="18" />
            </el-button>
            <div class="logo">
              <AppIcon name="Lock" :size="24" color="#409EFF" />
              <span class="logo-text">WebScan AI</span>
            </div>
          </div>
          <div class="header-actions">
            <el-badge :value="notificationCount" :hidden="notificationCount === 0" class="notification-badge">
              <el-button circle @click="toggleNotifications">
                <AppIcon name="Bell" :size="18" />
              </el-button>
            </el-badge>
            <el-dropdown @command="handleUserCommand" trigger="click">
              <el-avatar :size="36" class="user-avatar">
                <AppIcon name="User" :size="20" />
              </el-avatar>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item @click="handleViewNotifications">
                    <el-icon><Bell /></el-icon>
                    我的通知
                  </el-dropdown-item>
                  <div class="user-info">
                    <div class="user-name">{{ userInfo?.username || '管理员' }}</div>
                    <div class="user-email">{{ userInfo?.email || 'admin@webscan.ai' }}</div>
                  </div>
                  <el-dropdown-item divided command="profile">
                    <el-icon><User /></el-icon>
                    个人资料
                  </el-dropdown-item>
                  <el-dropdown-item divided command="settings">
                    <el-icon><Setting /></el-icon>
                    系统设置
                  </el-dropdown-item>
                  <el-dropdown-item divided command="logout">
                    <el-icon><SwitchButton /></el-icon>
                    退出登录
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </div>
      </el-header>

      <el-container class="main-container">
        <el-aside
          :width="sidebarWidth"
          :collapse="sidebarCollapsed && !isMobile"
          class="sidebar"
        >
          <div class="sidebar-content">
            <el-menu
              :default-active="activeMenu"
              :collapse="sidebarCollapsed && !isMobile"
              :unique-opened="true"
              router
              class="sidebar-menu"
            >
              <el-menu-item
                v-for="item in menuItems"
                :key="item.name"
                :index="item.path"
                @click="closeMobileMenu"
              >
                <AppIcon :name="item.icon" :size="18" />
                <template #title>
                  {{ item.label }}
                </template>
              </el-menu-item>
            </el-menu>
            
          </div>
        </el-aside>

        <el-drawer
          v-model="isMobileMenuOpen"
          direction="ltr"
          :with-header="false"
          class="mobile-drawer"
          @close="closeMobileMenu"
        >
          <el-menu
            :default-active="activeMenu"
            router
            class="mobile-menu"
          >
            <el-menu-item
              v-for="item in menuItems"
              :key="item.name"
              :index="item.path"
              @click="closeMobileMenu"
            >
              <el-icon>
                <component :is="item.icon" />
              </el-icon>
              <template #title>
                {{ item.label }}
              </template>
            </el-menu-item>
          </el-menu>
        </el-drawer>

        <el-main class="main-content">
          <router-view v-slot="{ Component }">
            <transition name="page-fade" mode="out-in">
              <component :is="Component" />
            </transition>
          </router-view>
        </el-main>
      </el-container>
    </el-container>

    <el-popover
      v-model:visible="showNotifications"
      placement="bottom-end"
      :width="320"
      trigger="click"
    >
      <template #reference>
        <div></div>
      </template>
      <div class="notification-panel">
        <div class="notification-header">
          <h3>通知</h3>
        </div>
        <div class="notification-list">
          <div v-for="notification in notifications" :key="notification.id" class="notification-item" @click="handleNotificationClick(notification)">
            <div class="notification-content">
              <div class="notification-header">
                <div class="notification-title">{{ notification.title }}</div>
                <div class="notification-time">{{ notification.time || formatDate(notification.created_at) }}</div>
              </div>
              <div class="notification-message">{{ notification.message }}</div>
            </div>
            <div class="notification-actions">
              <button v-if="!notification.read" @click.stop="handleMarkNotificationAsRead(notification)" class="btn-icon" title="标记已读">
                ✓
              </button>
              <button @click.stop="handleDeleteNotification(notification)" class="btn-icon btn-danger" title="删除">
                🗑
              </button>
            </div>
          </div>
          <div v-if="notifications.length === 0" class="empty-notifications">
            <el-empty description="暂无通知" />
          </div>
          <div class="notification-footer">
            <button @click="handleViewNotifications" class="btn-view-all">
              查看全部通知 →
            </button>
            <button @click="handleMarkAllAsRead" class="btn-mark-all" :disabled="unreadCount === 0">
              全部标记已读
            </button>
          </div>
        </div>
      </div>
    </el-popover>

    <AIChatFloater />
  </div>
</template>

<script>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Bell, User, Setting, SwitchButton } from '@element-plus/icons-vue'
import AppIcon from '@/components/common/AppIcon.vue'
import AIChatFloater from '@/components/common/AIChatFloater.vue'
import { userApi, notificationsApi } from '@/utils/api'
import { formatDate } from '@/utils/date'

export default {
  name: 'AppLayout',
  components: {
    AppIcon,
    AIChatFloater,
    Bell,
    User,
    Setting,
    SwitchButton
  },
  setup() {
    const route = useRoute()
    const router = useRouter()
    const sidebarCollapsed = ref(false)
    const showNotifications = ref(false)
    const isMobileMenuOpen = ref(false)
    const isMobile = ref(false)

    const menuItems = ref([
      { name: 'Dashboard', path: '/', label: '仪表盘', icon: 'DataAnalysis' },
      { name: 'ScanTasks', path: '/scan-tasks', label: '扫描任务', icon: 'Search' },
      { name: 'POCScan', path: '/poc-scan', label: 'POC扫描', icon: 'Aim' },
      { name: 'AWVSScan', path: '/awvs-scan', label: 'AWVS扫描', icon: 'Lock' },
      { name: 'AgentScan', path: '/agent-scan', label: 'AI Agent', icon: 'Monitor' },
      { name: 'KnowledgeBase', path: '/knowledge-base', label: '漏洞知识库', icon: 'Reading' },
      { name: 'Reports', path: '/reports', label: '报告', icon: 'Document' },
      { name: 'Settings', path: '/settings', label: '设置', icon: 'Setting' }
    ])

    const notifications = ref([])
    const userInfo = ref(null)

    const activeMenu = computed(() => route.path)

    const notificationCount = computed(() => {
      return (notifications.value || []).filter(n => !n.read).length
    })

    const unreadCount = computed(() => {
      return (notifications.value || []).filter(n => !n.read).length
    })

    const sidebarWidth = computed(() => {
      if (isMobile.value) return '0px'
      return sidebarCollapsed.value ? '64px' : '240px'
    })

    const toggleSidebar = () => {
      sidebarCollapsed.value = !sidebarCollapsed.value
    }

    const toggleMobileMenu = () => {
      isMobileMenuOpen.value = !isMobileMenuOpen.value
    }

    const closeMobileMenu = () => {
      isMobileMenuOpen.value = false
    }

    const checkMobile = () => {
      isMobile.value = window.innerWidth <= 768
      if (isMobile.value) {
        sidebarCollapsed.value = false
      }
    }

    const handleUserCommand = (command) => {
      if (command === 'profile') {
        router.push('/profile')
      } else if (command === 'settings') {
        router.push('/settings')
      } else if (command === 'logout') {
        localStorage.removeItem('isAuthenticated')
        localStorage.removeItem('token')
        router.push('/')
      }
    }

    const handleViewNotifications = () => {
      router.push('/notifications')
    }

    const toggleNotifications = () => {
      showNotifications.value = !showNotifications.value
    }

    const handleNotificationClick = async (notification) => {
      if (!notification.read) {
        try {
          await notificationsApi.markAsRead(notification.id)
          notification.read = true
        } catch (error) {
          console.error('标记已读失败:', error)
        }
      }
      showNotifications.value = false
      router.push(`/notification/${notification.id}`)
    }

    const handleMarkNotificationAsRead = async (notification) => {
      try {
        const response = await notificationsApi.markAsRead(notification.id)
        if (response.code === 200) {
          notification.read = true
        }
      } catch (error) {
        console.error('标记已读失败:', error)
      }
    }

    const handleDeleteNotification = async (notification) => {
      if (confirm('确定要删除此通知吗？')) {
        try {
          const response = await notificationsApi.deleteNotification(notification.id)
          if (response.code === 200) {
            notifications.value = notifications.value.filter(n => n.id !== notification.id)
          }
        } catch (error) {
          console.error('删除通知失败:', error)
        }
      }
    }

    const handleMarkAllAsRead = async () => {
      try {
        const response = await notificationsApi.markAllAsRead()
        if (response.code === 200) {
          notifications.value.forEach(n => n.read = true)
        }
      } catch (error) {
        console.error('全部标记已读失败:', error)
      }
    }

    const loadUserInfo = async () => {
      try {
        const response = await userApi.getProfile()
        if (response.code === 200) {
          userInfo.value = response.data
        }
      } catch (error) {
        console.error('加载用户信息失败:', error)
      }
    }

    const loadNotifications = async () => {
      try {
        const response = await notificationsApi.getNotifications({ limit: 10 })
        if (response.code === 200) {
          notifications.value = response.data.notifications || []
        }
      } catch (error) {
        console.error('加载通知失败:', error)
      }
    }

    onMounted(() => {
      loadUserInfo()
      loadNotifications()
      checkMobile()
      window.addEventListener('resize', checkMobile)
    })

    onBeforeUnmount(() => {
      window.removeEventListener('resize', checkMobile)
    })

    return {
      sidebarCollapsed,
      showNotifications,
      isMobileMenuOpen,
      isMobile,
      menuItems,
      notifications,
      userInfo,
      activeMenu,
      notificationCount,
      unreadCount,
      sidebarWidth,
      toggleSidebar,
      toggleMobileMenu,
      closeMobileMenu,
      handleUserCommand,
      handleViewNotifications,
      toggleNotifications,
      handleNotificationClick,
      handleMarkNotificationAsRead,
      handleDeleteNotification,
      handleMarkAllAsRead,
      formatDate
    }
  }
}
</script>

<style scoped>
.app-layout {
  height: 100vh;
}

.layout-container {
  height: 100vh;
}

.header {
  background-color: var(--el-fill-color-blank);
  border-bottom: 1px solid var(--el-border-color-light);
  box-shadow: var(--el-box-shadow-lighter);
  padding: 0;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 60px;
  padding: 0 var(--spacing-md);
}

.logo-section {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.mobile-menu-btn {
  display: none;
}

.logo {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.logo-text {
  font-size: 20px;
  font-weight: bold;
  color: var(--el-color-primary);
}

.header-actions {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.notification-badge {
  margin-right: var(--spacing-md);
}

.user-avatar {
  cursor: pointer;
  background-color: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
}

.user-info {
  padding: var(--spacing-md);
}

.user-name {
  font-weight: bold;
  color: var(--el-text-color-primary);
  margin-bottom: var(--spacing-xs);
}

.user-email {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.main-container {
  height: calc(100vh - 60px);
}

.sidebar {
  background-color: var(--el-fill-color-blank);
  border-right: 1px solid var(--el-border-color-light);
  transition: width var(--transition-base);
  overflow-x: hidden;
  position: relative;
}

.sidebar-content {
  display: flex;
  flex-direction: column;
  height: 100%;
  position: relative;
}

.sidebar-menu {
  border-right: none;
  flex: 1;
  overflow-y: auto;
}

.sidebar-menu :deep(.el-menu-item) {
  height: 50px;
  line-height: 50px;
}

.sidebar-menu :deep(.el-menu-item.is-active) {
  background-color: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
  border-right: 3px solid var(--el-color-primary);
}

.main-content {
  background-color: var(--el-fill-color-light);
  padding: var(--spacing-lg);
  overflow-y: auto;
}

.notification-panel {
  max-height: 400px;
  overflow-y: auto;
}

.notification-header {
  padding: var(--spacing-md);
  border-bottom: 1px solid var(--el-border-color-light);
}

.notification-header h3 {
  margin: 0;
  font-size: 16px;
  color: var(--el-text-color-primary);
}

.notification-item {
  padding: var(--spacing-md);
  border-bottom: 1px solid var(--el-border-color-lighter);
  cursor: pointer;
  transition: all 0.3s;
  display: flex;
  gap: var(--spacing-md);
  align-items: center;
}

.notification-item:hover {
  background-color: var(--el-fill-color-light);
}

.notification-item:last-child {
  border-bottom: none;
}

.notification-content {
  flex: 1;
  min-width: 0;
}

.notification-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-xs);
}

.notification-title {
  font-weight: 600;
  color: var(--el-text-color-primary);
  font-size: 14px;
}

.notification-time {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.notification-message {
  color: var(--el-text-color-regular);
  font-size: 13px;
  line-height: 1.5;
}

.notification-actions {
  display: flex;
  gap: var(--spacing-xs);
  flex-shrink: 0;
}

.notification-item .btn-icon {
  width: 28px;
  height: 28px;
  border: none;
  border-radius: 4px;
  background-color: var(--el-fill-color-blank);
  color: var(--el-text-color-secondary);
  cursor: pointer;
  transition: all 0.3s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.notification-item .btn-icon:hover {
  background-color: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
}

.notification-item .btn-icon.btn-danger {
  background-color: var(--el-color-danger-light-9);
  color: var(--el-color-danger);
}

.notification-item .btn-icon.btn-danger:hover {
  background-color: var(--el-color-danger);
  color: #ffffff;
}

.empty-notifications {
  padding: var(--spacing-xl);
  text-align: center;
}

.notification-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  border-top: 1px solid var(--el-border-color-lighter);
  margin-top: var(--spacing-md);
}

.btn-view-all {
  padding: var(--spacing-xs) var(--spacing-md);
  background-color: var(--el-color-primary);
  color: #ffffff;
  border: none;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s;
}

.btn-view-all:hover {
  background-color: var(--el-color-primary-dark-2);
}

.btn-mark-all {
  padding: var(--spacing-xs) var(--spacing-md);
  background-color: var(--el-fill-color-blank);
  color: var(--el-text-color-primary);
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s;
}

.btn-mark-all:hover:not(:disabled) {
  background-color: var(--el-color-primary-light-9);
  border-color: var(--el-color-primary);
  color: var(--el-color-primary);
}

.btn-mark-all:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.notification-list {
  padding: var(--spacing-md);
}

.notification-item {
  padding: var(--spacing-md);
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.notification-item:last-child {
  border-bottom: none;
}

.notification-title {
  font-weight: bold;
  color: var(--el-text-color-primary);
  margin-bottom: var(--spacing-xs);
}

.notification-message {
  color: var(--el-text-color-regular);
  font-size: 13px;
  margin-bottom: var(--spacing-xs);
}

.notification-time {
  color: var(--el-text-color-secondary);
  font-size: 11px;
}

.mobile-drawer :deep(.el-drawer__body) {
  padding: 0;
}

.mobile-menu {
  border-right: none;
}

.page-fade-enter-active,
.page-fade-leave-active {
  transition: opacity var(--transition-base);
}

.page-fade-enter-from,
.page-fade-leave-to {
  opacity: 0;
}

@media (max-width: 768px) {
  .mobile-menu-btn {
    display: flex;
  }

  .logo-text {
    font-size: 16px;
  }

  .sidebar {
    width: 0 !important;
  }

  .main-content {
    padding: var(--spacing-md);
  }

  .notification-panel {
    width: calc(100vw - 32px);
    max-width: none;
  }
}

@media (max-width: 480px) {
  .header-content {
    padding: 0 var(--spacing-sm);
    height: 50px;
  }

  .logo-text {
    font-size: 14px;
  }

  .main-content {
    padding: var(--spacing-sm);
  }
}
</style>