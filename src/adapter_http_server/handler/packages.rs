use std::io::Write;

use axum::extract::{Path, State};
use flate2::write::GzEncoder;

use crate::adapter_http_server::{HealthCheck, ServerState};

pub async fn handler<AR, APK, HC>(
    State(state): State<ServerState<AR, APK, HC>>,
    Path(arch): Path<String>,
) -> Result<String, super::ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    APK: crate::domain::prelude::ApkRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    state
        .apt_repository
        .packages_file(arch.as_str())
        .await
        .map_err(|err| {
            tracing::error!(error = ?err, "unable to fetch packages");
            super::ApiError::internal("unable to fetch packages")
        })
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

pub async fn gz_handler<AR, APK, HC>(
    State(state): State<ServerState<AR, APK, HC>>,
    Path(arch): Path<String>,
) -> Result<Vec<u8>, super::ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    APK: crate::domain::prelude::ApkRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    let data = handler(State(state), Path(arch)).await?;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write(data.as_bytes()).map_err(|err| {
        tracing::error!(error = ?err, "unable to compress response");
        super::ApiError::internal("unable to compress response")
    })?;
    encoder.finish().map_err(|err| {
        tracing::error!(error = ?err, "unable to compress response");
        super::ApiError::internal("unable to compress response")
    })
}

#[cfg(test)]
mod tests {
    use axum::extract::{Path, State};

    use crate::{
        adapter_http_server::{HealthCheck, ServerState},
        domain::prelude::{MockApkRepositoryService, MockAptRepositoryService},
    };

    #[derive(Clone)]
    struct MockHealthCheck;

    impl HealthCheck for MockHealthCheck {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn should_list_packages_when_requested() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_packages_file()
            .once()
            .return_once(|arch| {
                assert_eq!(arch, "amd64");
                Box::pin(async { Ok(String::from("Package: test\nVersion: 1.0.0")) })
            });
        let res = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(String::from("amd64")),
        )
        .await
        .unwrap();
        assert_eq!(res, "Package: test\nVersion: 1.0.0");
    }

    #[tokio::test]
    async fn should_return_error_when_packages_fetch_fails() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_packages_file()
            .once()
            .return_once(|_| Box::pin(async { Err(anyhow::anyhow!("fetch error")) }));
        let res = super::handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(String::from("amd64")),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn should_return_compressed_packages_when_gz_requested() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_packages_file()
            .once()
            .return_once(|arch| {
                assert_eq!(arch, "amd64");
                Box::pin(async { Ok(String::from("Package: test\nVersion: 1.0.0")) })
            });
        let res = super::gz_handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(String::from("amd64")),
        )
        .await
        .unwrap();
        // Check that result is gzip compressed (starts with gzip magic bytes)
        assert!(res.len() > 2);
        assert_eq!(res[0], 0x1f);
        assert_eq!(res[1], 0x8b);
    }

    #[tokio::test]
    async fn should_return_error_when_gz_packages_fetch_fails() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_packages_file()
            .once()
            .return_once(|_| Box::pin(async { Err(anyhow::anyhow!("fetch error")) }));
        let res = super::gz_handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path(String::from("amd64")),
        )
        .await;
        assert!(res.is_err());
    }
}
