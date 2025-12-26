import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import ScanTasks from '../views/ScanTasks.vue'
import POCScan from '../views/POCScan.vue'
import VulnerabilityResults from '../views/VulnerabilityResults.vue'
import VulnerabilityDetail from '../views/VulnerabilityDetail.vue'
import Reports from '../views/Reports.vue'
import Settings from '../views/Settings.vue'
import AWVSScan from '../views/AWVSScan.vue'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/scan-tasks',
    name: 'ScanTasks',
    component: ScanTasks
  },
  {
    path: '/poc-scan',
    name: 'POCScan',
    component: POCScan
  },
  {
    path: '/vulnerabilities/:taskId',
    name: 'VulnerabilityResults',
    component: VulnerabilityResults,
    props: true
  },
  {
    path: '/vulnerability/:id',
    name: 'VulnerabilityDetail',
    component: VulnerabilityDetail,
    props: true
  },
  {
    path: '/reports',
    name: 'Reports',
    component: Reports
  },
  {
    path: '/settings',
    name: 'Settings',
    component: Settings
  },
  {
    path: '/awvs-scan',
    name: 'AWVSScan',
    component: AWVSScan
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
