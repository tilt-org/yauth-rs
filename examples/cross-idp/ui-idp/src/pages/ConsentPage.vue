<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";

// yauth's oauth2_server flow:
//   1. Server B redirects user-agent to GET /oauth/authorize?... on the IdP.
//   2. With `consent_ui_url` set, yauth 302s the browser HERE with the
//      original authorize params on the query string.
//   3. This page renders a consent prompt; on Allow we POST back to
//      /oauth/authorize with the same params + `approved: true`. yauth
//      validates the session cookie, issues an auth code, and 302s the
//      user-agent to Server B's redirect_uri.
//
// Spec: crates/yauth/src/plugins/oauth2_server.rs::AuthorizeConsentRequest

const route = useRoute();
const loading = ref(false);
const error = ref<string | null>(null);

const params = computed(() => route.query as Record<string, string>);
const clientId = computed(() => params.value.client_id ?? "");
const redirectUri = computed(() => params.value.redirect_uri ?? "");
const scope = computed(() => params.value.scope ?? "openid email profile");

onMounted(async () => {
  // If the user lands here without a session cookie, /oauth/authorize
  // will 401 on POST. Probe `/api/auth/session` upfront so we can send
  // them to /login with a return-to that lands back here.
  try {
    const resp = await fetch("/api/auth/session", { credentials: "include" });
    if (resp.status === 401) {
      const ret = `${route.fullPath}`;
      window.location.href = `/login?return_to=${encodeURIComponent(ret)}`;
    }
  } catch {
    /* let the user attempt approve; the IdP will surface the auth error */
  }
});

async function decide(approved: boolean) {
  loading.value = true;
  error.value = null;
  try {
    const body = {
      client_id: params.value.client_id,
      redirect_uri: params.value.redirect_uri,
      response_type: params.value.response_type ?? "code",
      code_challenge: params.value.code_challenge ?? "",
      code_challenge_method: params.value.code_challenge_method ?? "S256",
      scope: params.value.scope,
      state: params.value.state,
      approved,
    };
    // Vite proxies /oauth/authorize → http://idp:8080 in compose; the
    // browser POST hits this origin so the session cookie travels.
    const resp = await fetch("/oauth/authorize", {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      redirect: "manual",
    });
    // yauth replies with a 302 to the App's redirect_uri carrying
    // ?code=&state=. fetch in "manual" mode exposes that as `type:
    // 'opaqueredirect'`; we read the Location header via a fallback
    // POST when redirect: 'manual' eats it. Easiest: just open the
    // location ourselves if the response is opaque.
    if (resp.type === "opaqueredirect" || resp.status === 302 || resp.status === 303) {
      // Follow up: GET to learn the Location. But fetch already swallowed
      // it — fall back to re-POSTing as a real form submit so the browser
      // owns the navigation. (Safer than parsing headers across the proxy.)
      formPost("/oauth/authorize", body);
      return;
    }
    if (!resp.ok) {
      error.value = `consent POST failed (${resp.status})`;
      return;
    }
    // Some yauth builds return JSON `{ redirect_uri: "..." }` instead.
    const j = await resp.json().catch(() => null);
    if (j?.redirect_uri) {
      window.location.href = j.redirect_uri;
    } else {
      window.location.href = params.value.redirect_uri;
    }
  } catch (e: any) {
    error.value = e?.message ?? "consent failed";
  } finally {
    loading.value = false;
  }
}

function formPost(action: string, fields: Record<string, unknown>) {
  const f = document.createElement("form");
  f.method = "post";
  f.action = action;
  f.style.display = "none";
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined || v === null) continue;
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = k;
    input.value = String(v);
    f.appendChild(input);
  }
  document.body.appendChild(f);
  f.submit();
}
</script>

<template>
  <div class="card">
    <p v-if="error" style="color: #b54">{{ error }}</p>
    <h2>Authorize Server B?</h2>
    <p class="muted">
      <strong>client_id:</strong> <code>{{ clientId }}</code>
    </p>
    <p class="muted">
      <strong>redirect:</strong> <code>{{ redirectUri }}</code>
    </p>
    <p class="muted">requested scopes:</p>
    <ul style="margin: 8px 0 16px 20px; color: #444">
      <li v-for="s in scope.split(' ')" :key="s">
        <code>{{ s }}</code>
      </li>
    </ul>
    <div class="row">
      <button type="button" :disabled="loading" @click="decide(true)">
        {{ loading ? "..." : "Allow" }}
      </button>
      <button
        type="button"
        class="secondary"
        :disabled="loading"
        @click="decide(false)"
      >
        Deny
      </button>
    </div>
  </div>
</template>
