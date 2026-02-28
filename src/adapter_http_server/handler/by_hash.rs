use std::io::Write;

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::IntoResponse;
use flate2::write::GzEncoder;

use crate::adapter_http_server::handler::ApiError;
use crate::adapter_http_server::{HealthCheck, ServerState};

#[derive(serde::Deserialize)]
pub struct ByHashParams {
    arch: String,
    hash: String,
}

pub async fn handler<AR, APK, HC>(
    State(state): State<ServerState<AR, APK, HC>>,
    Path(params): Path<ByHashParams>,
) -> Result<impl IntoResponse, ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    APK: crate::domain::prelude::ApkRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    let Some(hash_match) = state
        .apt_repository
        .find_architecture_by_hash(&params.hash)
        .await
        .map_err(|err| {
            tracing::error!(error = ?err, "unable to find architecture by hash");
            ApiError::internal("unable to find architecture by hash")
        })?
    else {
        return Err(ApiError::not_found("hash not found"));
    };

    // Verify the architecture matches
    if hash_match.architecture != params.arch {
        return Err(ApiError::not_found("hash not found for this architecture"));
    }

    let packages_content = state
        .apt_repository
        .packages_file(&hash_match.architecture)
        .await
        .map_err(|err| {
            tracing::error!(error = ?err, "unable to fetch packages");
            ApiError::internal("unable to fetch packages")
        })?;

    if hash_match.compressed {
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(packages_content.as_bytes())
            .map_err(|err| {
                tracing::error!(error = ?err, "unable to compress response");
                ApiError::internal("unable to compress response")
            })?;
        let compressed = encoder.finish().map_err(|err| {
            tracing::error!(error = ?err, "unable to compress response");
            ApiError::internal("unable to compress response")
        })?;
        Ok(([(header::CONTENT_TYPE, "application/gzip")], compressed).into_response())
    } else {
        Ok((
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            packages_content,
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;

    use crate::adapter_http_server::{HealthCheck, ServerState};
    use crate::domain::prelude::{
        ArchitectureHashMatch, MockApkRepositoryService, MockAptRepositoryService,
    };

    use super::ByHashParams;

    #[derive(Clone)]
    struct MockHealthCheck;

    impl HealthCheck for MockHealthCheck {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn should_return_plain_packages_by_hash() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_find_architecture_by_hash()
            .withf(|hash| hash == "abc123")
            .once()
            .return_once(|_| {
                Box::pin(async {
                    Ok(Some(ArchitectureHashMatch {
                        architecture: "amd64".to_string(),
                        compressed: false,
                    }))
                })
            });
        apt_repository
            .expect_packages_file()
            .withf(|arch| arch == "amd64")
            .once()
            .return_once(|_| Box::pin(async { Ok("Package: test\n".to_string()) }));

        let res = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(ByHashParams {
                arch: "amd64".to_string(),
                hash: "abc123".to_string(),
            }),
        )
        .await
        .unwrap();

        let response = res.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn should_return_compressed_packages_by_hash() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_find_architecture_by_hash()
            .withf(|hash| hash == "def456")
            .once()
            .return_once(|_| {
                Box::pin(async {
                    Ok(Some(ArchitectureHashMatch {
                        architecture: "arm64".to_string(),
                        compressed: true,
                    }))
                })
            });
        apt_repository
            .expect_packages_file()
            .withf(|arch| arch == "arm64")
            .once()
            .return_once(|_| Box::pin(async { Ok("Package: test\n".to_string()) }));

        let res = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(ByHashParams {
                arch: "arm64".to_string(),
                hash: "def456".to_string(),
            }),
        )
        .await
        .unwrap();

        let response = res.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/gzip"
        );
    }

    #[tokio::test]
    async fn should_return_not_found_for_unknown_hash() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_find_architecture_by_hash()
            .once()
            .return_once(|_| Box::pin(async { Ok(None) }));

        let result = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(ByHashParams {
                arch: "amd64".to_string(),
                hash: "unknown".to_string(),
            }),
        )
        .await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.status_code, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn should_return_not_found_for_mismatched_architecture() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_find_architecture_by_hash()
            .once()
            .return_once(|_| {
                Box::pin(async {
                    Ok(Some(ArchitectureHashMatch {
                        architecture: "arm64".to_string(),
                        compressed: false,
                    }))
                })
            });

        let result = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(ByHashParams {
                arch: "amd64".to_string(),
                hash: "somehash".to_string(),
            }),
        )
        .await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.status_code, axum::http::StatusCode::NOT_FOUND);
    }
}
