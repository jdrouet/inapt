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
