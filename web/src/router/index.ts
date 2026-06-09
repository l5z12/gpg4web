import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/keys' },
  { path: '/keys', name: 'keys', component: () => import('@/views/KeysView.vue') },
  { path: '/keys/:fingerprint', name: 'key', component: () => import('@/views/KeyDetailView.vue'), props: true },
  { path: '/notepad', name: 'notepad', component: () => import('@/views/NotepadView.vue') },
  { path: '/files', name: 'files', component: () => import('@/views/FilesView.vue') },
  { path: '/sign', name: 'sign', component: () => import('@/views/SignView.vue') },
  { path: '/settings', name: 'settings', component: () => import('@/views/SettingsView.vue') },
  { path: '/about', name: 'about', component: () => import('@/views/AboutView.vue') },
]

export const router = createRouter({
  // Hash history keeps the app hostable from any static path with no server
  // rewrites required.
  history: createWebHashHistory(),
  routes,
})
