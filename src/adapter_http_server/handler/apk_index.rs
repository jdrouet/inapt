use axum::extract::{Path, State};
use axum::http::header;
use axum::response::IntoResponse;

use crate::adapter_http_server::{HealthCheck, ServerState};

/// Serves the signed `APKINDEX.tar.gz` for a given architecture.
///
/// Returns the index with `Content-Type: application/gzip`.
#[tracing::instrument(skip_all, err(Debug))]
pub async fn handler<AR, APK, HC>(
    State(state): State<ServerState<AR, APK, HC>>,
    Path(arch): Path<String>,
) -> Result<impl IntoResponse, super::ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    APK: crate::domain::prelude::ApkRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    let index = state.apk_repository.apk_index(&arch).await.map_err(|err| {
        tracing::error!(error = ?err, "unable to fetch APKINDEX");
        super::ApiError::internal("unable to fetch APKINDEX")
    })?;
    Ok(([(header::CONTENT_TYPE, "application/gzip")], index))
}

#[cfg(test)]
mod tests {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;

    use crate::adapter_http_server::{HealthCheck, ServerState};
    use crate::domain::prelude::{MockApkRepositoryService, MockAptRepositoryService};

    #[derive(Clone)]
    struct MockHealthCheck;

    impl HealthCheck for MockHealthCheck {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn should_return_apkindex_when_requested() {
        let apt_repository = MockAptRepositoryService::new();
        let mut apk_repository = MockApkRepositoryService::new();
        apk_repository
            .expect_apk_index()
            .withf(|arch| arch == "x86_64")
            .once()
            .return_once(|_| Box::pin(async { Ok(vec![0x1f, 0x8b, 0x08]) }));

        let response = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository,
                health_checker: MockHealthCheck,
            }),
            Path("x86_64".to_string()),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/gzip"
        );
    }

    #[tokio::test]
    async fn should_return_error_when_apkindex_fetch_fails() {
        let apt_repository = MockAptRepositoryService::new();
        let mut apk_repository = MockApkRepositoryService::new();
        apk_repository
            .expect_apk_index()
            .once()
            .return_once(|_| Box::pin(async { Err(anyhow::anyhow!("fetch error")) }));

        let result = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository,
                health_checker: MockHealthCheck,
            }),
            Path("x86_64".to_string()),
        )
        .await;

        assert!(result.is_err());
    }
}
