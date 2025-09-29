use axum::extract::{Path, State};

use crate::adapter_http_server::ServerState;

pub async fn handler<AR>(
    State(_state): State<ServerState<AR>>,
    Path(_arch): Path<String>,
) -> axum::http::StatusCode
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
{
    axum::http::StatusCode::NOT_IMPLEMENTED
}

// Example of output
//
// Package: foo
// Version: 1.0.0-1
// Architecture: amd64
// Maintainer: Alice <alice@example.com>
// Installed-Size: 1024
// Depends: bar (>= 2.0)
// Section: utils
// Priority: optional
// Description: Foo package
// Filename: pool/main/f/foo/foo_1.0.0-1_amd64.deb
// Size: 12345
// SHA256: 1111111111111111111111111111111111111111111111111111111111111111

// Package: bar
// Version: 2.0.0-1
// Architecture: amd64
// Maintainer: Bob <bob@example.com>
// Installed-Size: 2048
// Depends: libc6 (>= 2.28)
// Section: libs
// Priority: required
// Description: Bar package
// Filename: pool/main/b/bar/bar_2.0.0-1_amd64.deb
// Size: 23456
// SHA256: 2222222222222222222222222222222222222222222222222222222222222222

pub async fn gz_handler<AR>(
    State(_state): State<ServerState<AR>>,
    Path(_arch): Path<String>,
) -> axum::http::StatusCode
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
{
    axum::http::StatusCode::NOT_IMPLEMENTED
}

#[cfg(test)]
mod tests {
    use axum::{
        extract::{Path, State},
        http::StatusCode,
    };

    use crate::{adapter_http_server::ServerState, domain::prelude::MockAptRepositoryService};

    #[tokio::test]
    async fn should_list_packages() {
        let apt_repository = MockAptRepositoryService::new();
        let res = super::handler(
            State(ServerState { apt_repository }),
            Path(String::from("x86_64")),
        )
        .await;
        assert_eq!(res, StatusCode::NOT_IMPLEMENTED)
    }
}
