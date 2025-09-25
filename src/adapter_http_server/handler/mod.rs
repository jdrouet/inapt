use axum::routing::get;

use crate::adapter_http_server::ServerState;

mod inrelease;
mod packages;
mod pool_redirect;
mod release;

pub fn build<AR>() -> axum::Router<ServerState<AR>>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
{
    axum::Router::new()
        .route("/dists/stable/Release", get(release::handler))
        .route("/dists/stable/InRelease", get(inrelease::handler))
        .route(
            "/dists/stable/main/binary-{arch}/Packages",
            get(packages::handler),
        )
        .route(
            "/dists/stable/main/binary-{arch}/Packages.gz",
            get(packages::gz_handler),
        )
        .route("/pool/main/{p}/{pkg}/{file}", get(pool_redirect::handler))
}
