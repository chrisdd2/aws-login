import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import IdpLogin from './components/IdpLogin.vue'
import Home from './components/Home.vue'
import LoginForm from './components/LoginForm.vue'

const routes: RouteRecordRaw[] = [
  { path: '/', component: Home },
  { path: '/login', component: LoginForm },
  { path: '/oauth2/idpresponse', component: IdpLogin },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router