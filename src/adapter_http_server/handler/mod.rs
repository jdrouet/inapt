use std::borrow::Cow;

use axum::response::IntoResponse;
use axum::routing::get;

use crate::adapter_http_server::ServerState;

mod by_hash;
mod inrelease;
mod packages;
mod pool_redirect;
mod release;
mod release_gpg;

pub fn build<AR>() -> axum::Router<ServerState<AR>>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
{
    axum::Router::new()
        .route("/dists/stable/Release", get(release::handler))
        .route("/dists/stable/InRelease", get(inrelease::handler))
        .route("/dists/stable/Release.gpg", get(release_gpg::handler))
        .route(
            "/dists/stable/main/binary-{arch}/Packages",
            get(packages::handler),
        )
        .route(
            "/dists/stable/main/binary-{arch}/Packages.gz",
            get(packages::gz_handler),
        )
        .route(
            "/dists/stable/main/binary-{arch}/by-hash/SHA256/{hash}",
            get(by_hash::handler),
        )
        .route("/pool/main/{p}/{pkg}/{file}", get(pool_redirect::handler))
}

#[derive(Debug)]
struct ApiError {
    status_code: axum::http::StatusCode,
    message: Cow<'static, str>,
}

impl ApiError {
    #[inline]
    fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status_code: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    #[inline]
    fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status_code: axum::http::StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status_code, self.message).into_response()
    }
}
