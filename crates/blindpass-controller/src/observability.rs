// SPDX-License-Identifier: AGPL-3.0-only

use crate::config::LogFormat;
use tracing_subscriber::EnvFilter;

/// Start structured logging without installing a formatter that records full
/// request URIs, query strings, headers or request bodies.
pub fn init(format: LogFormat) -> Result<(), &'static str> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
            .map_err(|_| "tracing subscriber could not be initialized"),
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .try_init()
            .map_err(|_| "tracing subscriber could not be initialized"),
    }
}
