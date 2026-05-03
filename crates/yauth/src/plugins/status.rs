use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;

use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

pub struct StatusPlugin;

impl YAuthPlugin for StatusPlugin {
    fn name(&self) -> &'static str {
        "status"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(Router::new().route("/status", get(get_status)))
    }
}

/// Response for `GET /status`. Mirrors yauth-go's `StatusResponse`.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StatusResponse {
    pub plugins: Vec<String>,
    pub version: String,
}

async fn get_status(State(state): State<YAuthState>) -> Json<StatusResponse> {
    let plugins: Vec<String> = state.plugins.iter().map(|p| p.name().to_string()).collect();
    Json(StatusResponse {
        plugins,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
