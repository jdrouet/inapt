use axum::{
    extract::{Path, State},
    response::Redirect,
};

use crate::adapter_http_server::{HealthCheck, ServerState};

pub async fn handler<AR, HC>(
    State(state): State<ServerState<AR, HC>>,
    Path((_, name, filename)): Path<(String, String, String)>,
) -> Result<Redirect, super::ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    let item = state
        .apt_repository
        .package(name.as_str(), filename.as_str())
        .await
        .map_err(|err| {
            tracing::error!(error = ?err, "something went wrong");
            super::ApiError::internal("ooops")
        })?;
    let item = item.ok_or_else(|| super::ApiError::not_found("package not found"))?;
    Ok(Redirect::permanent(&item.asset.url))
}
