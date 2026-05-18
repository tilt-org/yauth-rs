import { useNavigate } from "@solidjs/router";
import { useYAuth } from "@yackey-labs/yauth-ui-solidjs";
import { Show, createResource } from "solid-js";

/** Best-effort JWT payload decoder. Demo-only; never trust unverified. */
function decodeJwt(token: string): unknown {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  try {
    return JSON.parse(atob(b64 + pad));
  } catch {
    return null;
  }
}

export function Dashboard() {
  const navigate = useNavigate();
  const { client, user, loading } = useYAuth();

  // Best-effort: try to mint a bearer JWT so we can show its claims.
  const [token] = createResource(async () => {
    try {
      // The yauth client may or may not expose .bearer; fall back to fetch.
      const resp = await fetch("/api/auth/bearer/token", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      if (!resp.ok) return null;
      const j = await resp.json();
      return j.access_token as string | undefined;
    } catch {
      return null;
    }
  });

  const handleLogout = async () => {
    await client.logout();
    navigate("/login");
  };

  return (
    <div>
      <h1>
        Server B <span class="badge">App</span>
      </h1>

      <Show when={!loading()} fallback={<p>Loading…</p>}>
        <Show
          when={user()}
          fallback={
            <div class="card">
              <p>Not signed in.</p>
              <a href="/login">Back to login</a>
            </div>
          }
        >
          {(u) => (
            <div class="card">
              <h2>Signed in (federated)</h2>
              <p>
                <strong>{u().email}</strong>
              </p>
              <p class="muted">
                role: <code>{u().role}</code> · verified:{" "}
                {u().email_verified ? "yes" : "no"}
              </p>

              <h2 style={{ "margin-top": "20px" }}>Bearer JWT (claims)</h2>
              <Show
                when={token()}
                fallback={
                  <p class="muted">
                    No bearer token available (either /api/auth/bearer/token
                    isn't enabled or it required a different grant).
                  </p>
                }
              >
                {(t) => (
                  <pre>{JSON.stringify(decodeJwt(t()), null, 2)}</pre>
                )}
              </Show>

              <div style={{ "margin-top": "16px" }}>
                <button type="button" onClick={handleLogout}>
                  Sign out
                </button>
              </div>
            </div>
          )}
        </Show>
      </Show>
    </div>
  );
}
