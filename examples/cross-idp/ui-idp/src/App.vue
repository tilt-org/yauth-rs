<script setup lang="ts">
import { RouterView } from "vue-router";
</script>

<template>
  <div>
    <h1>
      Server A <span class="badge">Identity Provider</span>
    </h1>
    <p class="muted">
      This is the IdP side of the cross-IdP demo. Server B (on
      <code>localhost:8081</code>) federates against this server via OIDC.
    </p>
    <RouterView />
  </div>
</template>
