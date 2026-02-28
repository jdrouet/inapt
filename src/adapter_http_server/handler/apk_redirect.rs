use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::adapter_http_server::{HealthCheck, ServerState};

/// Redirects to the GitHub asset URL for a given APK package.
///
/// Returns HTTP 302 (Found) pointing to the upstream download URL.
pub async fn handler<AR, APK, HC>(
    State(state): State<ServerState<AR, APK, HC>>,
    Path((arch, filename)): Path<(String, String)>,
) -> Result<Response, super::ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    APK: crate::domain::prelude::ApkRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    let item = state
        .apk_repository
        .apk_package(&arch, &filename)
        .await
        .map_err(|err| {
            tracing::error!(error = ?err, "something went wrong");
            super::ApiError::internal("unable to fetch APK package")
        })?;
    let item = item.ok_or_else(|| super::ApiError::not_found("package not found"))?;
    Ok((StatusCode::FOUND, [(header::LOCATION, item.asset.url)]).into_response())
}

#[cfg(test)]
mod tests {
    use axum::extract::{Path, State};

    use crate::adapter_http_server::{HealthCheck, ServerState};
    use crate::domain::entity::{ApkAsset, ApkMetadata, ApkPackage};
    use crate::domain::prelude::{MockApkRepositoryService, MockAptRepositoryService};

    #[derive(Clone)]
    struct MockHealthCheck;

    impl HealthCheck for MockHealthCheck {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn sample_apk_package() -> ApkPackage {
        ApkPackage {
            metadata: ApkMetadata {
                name: "busybox".to_string(),
                version: "1.37.0-r14".to_string(),
                architecture: "x86_64".to_string(),
                installed_size: 817257,
                description: "Size optimized toolbox".to_string(),
                url: "https://busybox.net/".to_string(),
                license: "GPL-2.0-only".to_string(),
                origin: None,
                maintainer: None,
                build_date: None,
                dependencies: Vec::new(),
                provides: Vec::new(),
                datahash: None,
            },
            asset: ApkAsset {
                repo_owner: "owner".to_string(),
                repo_name: "repo".to_string(),
                release_id: 1,
                asset_id: 42,
                filename: "busybox-1.37.0-r14.apk".to_string(),
                url: "https://github.com/owner/repo/releases/download/v1/busybox-1.37.0-r14.apk"
                    .to_string(),
                size: 123456,
                sha256: None,
            },
        }
    }

    #[tokio::test]
    async fn should_redirect_to_github_asset_url() {
        let apt_repository = MockAptRepositoryService::new();
        let mut apk_repository = MockApkRepositoryService::new();
        apk_repository
            .expect_apk_package()
            .withf(|arch, filename| arch == "x86_64" && filename == "busybox-1.37.0-r14.apk")
            .once()
            .return_once(|_, _| Box::pin(async { Ok(Some(sample_apk_package())) }));

        let response = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository,
                health_checker: MockHealthCheck,
            }),
            Path(("x86_64".to_string(), "busybox-1.37.0-r14.apk".to_string())),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FOUND);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://github.com/owner/repo/releases/download/v1/busybox-1.37.0-r14.apk"
        );
    }

    #[tokio::test]
    async fn should_return_not_found_when_package_missing() {
        let apt_repository = MockAptRepositoryService::new();
        let mut apk_repository = MockApkRepositoryService::new();
        apk_repository
            .expect_apk_package()
            .once()
            .return_once(|_, _| Box::pin(async { Ok(None) }));

        let result = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository,
                health_checker: MockHealthCheck,
            }),
            Path(("x86_64".to_string(), "nonexistent.apk".to_string())),
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn should_return_error_when_fetch_fails() {
        let apt_repository = MockAptRepositoryService::new();
        let mut apk_repository = MockApkRepositoryService::new();
        apk_repository
            .expect_apk_package()
            .once()
            .return_once(|_, _| Box::pin(async { Err(anyhow::anyhow!("fetch error")) }));

        let result = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository,
                health_checker: MockHealthCheck,
            }),
            Path(("x86_64".to_string(), "busybox.apk".to_string())),
        )
        .await;

        assert!(result.is_err());
    }
}
