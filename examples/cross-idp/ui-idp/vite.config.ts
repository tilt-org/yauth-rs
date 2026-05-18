import vue from "@vitejs/plugin-vue";
import { defineConfig } from "vite";

// Server A (the IdP) lives at http://localhost:8080 in compose. /api is
// proxied so cookies stay first-party for the in-browser /authorize call.
const target = process.env.VITE_YAUTH_BASE ?? "http://localhost:8080";

export default defineConfig({
	plugins: [vue()],
	server: {
		port: 5173,
		host: "0.0.0.0",
		proxy: {
			"/api": {
				target,
				changeOrigin: true,
			},
			"/.well-known": {
				target,
				changeOrigin: true,
			},
			"/authorize": {
				target,
				changeOrigin: true,
			},
			"/token": {
				target,
				changeOrigin: true,
			},
		},
	},
});
