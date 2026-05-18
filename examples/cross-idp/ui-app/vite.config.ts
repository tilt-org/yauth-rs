import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";

// Server B (the App) lives at http://localhost:8081 in compose. The
// `/api` proxy rewrites browser requests so cookies stay first-party.
const target = process.env.VITE_YAUTH_BASE ?? "http://localhost:8081";

export default defineConfig({
	plugins: [solidPlugin()],
	server: {
		port: 5174,
		host: "0.0.0.0",
		proxy: {
			"/api": {
				target,
				changeOrigin: true,
			},
		},
	},
});
