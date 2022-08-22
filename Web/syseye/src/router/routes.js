
const routes = [
  {
    path: '/',
    component: () => import('layouts/MainLayout.vue'),
    children: [
      { path: '', component: () => import('pages/Index.vue') }
    ]
  },
  {
    path: '/page',
    component: () => import('layouts/MainLayout.vue'),
    children: [
      { path: 'dashboard', component: () => import('pages/Dashboard.vue') },
      { path: 'index', name: 'index', component: () => import('pages/Index.vue') }
    ]
  },
  // Always leave this as last one,
  // but you can also remove it
  {
    path: '/:catchAll(.*)*',
    component: () => import('pages/Error404.vue')
  }
]

export default routes
