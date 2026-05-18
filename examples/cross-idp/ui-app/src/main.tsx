import { Route, Router } from "@solidjs/router";
import { YAuthProvider } from "@yackey-labs/yauth-ui-solidjs";
import { render } from "solid-js/web";
import { Dashboard } from "./Dashboard";
import { Login } from "./Login";

// The Vite dev server proxies `/api/*` to Server B (yauth as the App).
// All yauth-client calls hit `/api/auth/*` relative to this origin so
// the session cookie stays first-party.
function App() {
  return (
    <YAuthProvider baseUrl="/api/auth">
      <div id="root">
        <Router>
          <Route path="/" component={() => <Login />} />
          <Route path="/login" component={() => <Login />} />
          <Route path="/dashboard" component={() => <Dashboard />} />
        </Router>
      </div>
    </YAuthProvider>
  );
}

render(() => <App />, document.getElementById("app") as HTMLElement);
