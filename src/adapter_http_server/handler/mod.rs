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
mod translation;

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
        // Translation files (i18n) - serve actual English descriptions
        // Use a single route with filename capture to avoid Axum's "one parameter per segment" limitation
        .route(
            "/dists/stable/main/i18n/{filename}",
            get(translation::handler::<AR>),
        )
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

#[cfg(test)]
mod tests {
    use crate::domain::prelude::MockAptRepositoryService;

    /// Test that the router can be built without panicking.
    /// This catches invalid route patterns (like having multiple parameters in one segment)
    /// at test time rather than at runtime.
    #[test]
    fn should_build_router_without_panicking() {
        // This will panic if any route pattern is invalid
        let _router = super::build::<MockAptRepositoryService>();
    }
}
