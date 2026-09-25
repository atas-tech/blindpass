// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod admin;
pub(crate) mod admin_agents;
pub(crate) mod admin_approvals;
pub(crate) mod admin_operators;
pub(crate) mod admin_policy;
pub(crate) mod admin_session;
pub(crate) mod agent_rate_limit;
pub(crate) mod agents;
pub(crate) mod auth;
pub(crate) mod exchanges;
pub(crate) mod secrets;

pub(crate) use admin_session::forced_password_change_gate;

use crate::app::AppState;
use axum::{Router, routing::post};

pub(crate) fn test_seed_routes(test_mode: bool) -> Router<AppState> {
    if test_mode {
        Router::new().route("/api/v3/admin/test/seed", post(auth::test_seed))
    } else {
        Router::new()
    }
}

pub(crate) fn admin_routes() -> Router<AppState> {
    admin::routes()
        .merge(admin_session::routes())
        .merge(admin_approvals::routes())
        .merge(admin_operators::routes())
        .merge(admin_agents::routes())
        .merge(admin_policy::routes())
}
