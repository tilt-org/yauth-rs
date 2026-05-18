<script setup lang="ts">
import { LoginForm } from "@yackey-labs/yauth-ui-vue";
import { useRoute, useRouter } from "vue-router";

const router = useRouter();
const route = useRoute();

// When the browser is redirected here from /authorize on the IdP, the
// original authorize URL lands in `?return_to=`. After a successful
// login we either continue to the consent screen (if we have a pending
// authorize URL) or go to the IdP's dashboard.
function onSuccess() {
  const ret = route.query.return_to as string | undefined;
  if (ret) {
    router.push({ path: "/consent", query: { return_to: ret } });
  } else {
    router.push("/dashboard");
  }
}
</script>

<template>
  <div class="card">
    <h2>Sign in to Server A</h2>
    <LoginForm @success="onSuccess" />
    <p class="muted" style="margin-top: 12px">
      Demo users seeded by <code>scripts/seed.sh</code>:
      <br />
      <code>alice@example.com</code> / <code>alicepasswd1</code><br />
      <code>bob@example.com</code> / <code>bobpasswd123</code>
    </p>
  </div>
</template>
