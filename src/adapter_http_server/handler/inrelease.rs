use axum::extract::State;

use crate::adapter_http_server::{HealthCheck, ServerState, handler::ApiError};

#[tracing::instrument(skip_all, err(Debug))]
pub async fn handler<AR, HC>(State(state): State<ServerState<AR, HC>>) -> Result<String, ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    match state.apt_repository.signed_release_metadata().await {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(ApiError::not_found("release not found")),
        Err(err) => Err(ApiError::internal(err.to_string())),
    }
}

// The `/dists/stable/InRelease` endpoint serves a **signed version of the Release file**. It is a single file that contains both the Release
// metadata and a GPG signature, allowing APT clients to verify the authenticity and integrity of the repository metadata in one request.
//
// ## Purpose
//
// - **Security**: The InRelease file provides cryptographic assurance that the repository metadata (Release file) has not been tampered with.
// - **Convenience**: It combines the Release file and its signature, so clients don’t need to fetch and verify a separate `Release.gpg` file.
//
// ## Format
//
// The InRelease file is a concatenation of:
// 1. The plain text Release file (as described previously).
// 2. A PGP (GPG) signature block, in ASCII-armored format, immediately following the Release content.
//
// ### Example Structure
//
// ```/dev/null/InRelease#L1-20
// Origin: MyRepo
// Label: MyRepo
// Suite: stable
// Version: 1.0
// Codename: stable
// Date: Tue, 04 Jun 2024 12:34:56 UTC
// Architectures: amd64
// Components: main
// Description: Minimal APT proxy for GitHub Releases
//
// MD5Sum:
//  1234567890abcdef1234567890abcdef 12345 main/binary-amd64/Packages
// SHA256:
//  abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef 12345 main/binary-amd64/Packages
//
// -----BEGIN PGP SIGNATURE-----
// Version: GnuPG v1
//
// [...signature data...]
// -----END PGP SIGNATURE-----
// ```
//
// - The signature is generated over the exact contents of the Release file (everything before the `-----BEGIN PGP SIGNATURE-----` line).
// - The signature is typically created using a detached, clear-signed method (`gpg --clearsign`).

#[cfg(test)]
mod tests {
    use crate::adapter_http_server::HealthCheck;
    use crate::domain::prelude::MockAptRepositoryService;

    #[derive(Clone)]
    struct MockHealthCheck;

    impl HealthCheck for MockHealthCheck {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn should_return_error_if_empty() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_signed_release_metadata()
            .once()
            .return_once(|| Box::pin(async move { Ok(None) }));
        let state = crate::adapter_http_server::ServerState {
            apt_repository,
            health_checker: MockHealthCheck,
        };
        let err = super::handler(axum::extract::State(state))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn should_return_payload() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_signed_release_metadata()
            .once()
            .return_once(|| {
                Box::pin(async move {
                    Ok(Some(String::from(
                        "foo -----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n",
                    )))
                })
            });
        let state = crate::adapter_http_server::ServerState {
            apt_repository,
            health_checker: MockHealthCheck,
        };
        let value = super::handler(axum::extract::State(state)).await.unwrap();
        assert_eq!(
            value,
            "foo -----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n"
        );
    }
}
