<script setup lang="ts">
import { useAuth, useSession } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const { user, isAuthenticated, loading } = useSession();
const { logout } = useAuth();
const router = useRouter();

async function handleLogout() {
  await logout();
  router.push("/login");
}
</script>

<template>
  <div class="card">
    <p v-if="loading">Loading…</p>
    <template v-else-if="isAuthenticated">
      <h2>Signed in to Server A</h2>
      <p>
        <strong>{{ user?.email }}</strong>
      </p>
      <p class="muted">role: {{ user?.role }}</p>
      <p class="muted" style="margin-top: 12px">
        This is the IdP's own user dashboard. The /authorize endpoint is
        what Server B redirects users to during the federation flow.
      </p>
      <div style="margin-top: 16px">
        <button type="button" @click="handleLogout">Sign out</button>
      </div>
    </template>
    <template v-else>
      <p>Not signed in.</p>
      <p><RouterLink to="/login">Go to login</RouterLink></p>
    </template>
  </div>
</template>
