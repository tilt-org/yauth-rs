import { createRouter, createWebHistory } from "vue-router";
import ConsentPage from "./pages/ConsentPage.vue";
import DashboardPage from "./pages/DashboardPage.vue";
import LoginPage from "./pages/LoginPage.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", redirect: "/login" },
    { path: "/login", component: LoginPage },
    { path: "/consent", component: ConsentPage },
    { path: "/dashboard", component: DashboardPage },
  ],
});
