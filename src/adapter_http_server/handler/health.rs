use axum::extract::State;
use axum::http::StatusCode;

use crate::adapter_http_server::{HealthCheck, ServerState};

/// Health check handler for load balancers and Kubernetes probes.
///
/// Returns 200 OK if all dependencies (database, etc.) are healthy.
/// Returns 503 Service Unavailable if any dependency check fails.
pub async fn handler<AR, HC>(State(state): State<ServerState<AR, HC>>) -> StatusCode
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    match state.health_checker.health_check().await {
        Ok(()) => StatusCode::OK,
        Err(err) => {
            tracing::warn!(error = ?err, "health check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;
    use axum::http::StatusCode;

    use crate::adapter_http_server::{HealthCheck, ServerState};
    use crate::domain::prelude::MockAptRepositoryService;

    #[derive(Clone)]
    struct MockHealthyChecker;

    impl HealthCheck for MockHealthyChecker {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockUnhealthyChecker;

    impl HealthCheck for MockUnhealthyChecker {
        async fn health_check(&self) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("database connection failed"))
        }
    }

    #[tokio::test]
    async fn should_return_ok_when_healthy() {
        let apt_repository = MockAptRepositoryService::new();
        let state = ServerState {
            apt_repository,
            health_checker: MockHealthyChecker,
        };
        let result = super::handler(State(state)).await;
        assert_eq!(result, StatusCode::OK);
    }

    #[tokio::test]
    async fn should_return_service_unavailable_when_unhealthy() {
        let apt_repository = MockAptRepositoryService::new();
        let state = ServerState {
            apt_repository,
            health_checker: MockUnhealthyChecker,
        };
        let result = super::handler(State(state)).await;
        assert_eq!(result, StatusCode::SERVICE_UNAVAILABLE);
    }
}
