use axum::extract::State;

use crate::adapter_http_server::{HealthCheck, ServerState, handler::ApiError};

#[tracing::instrument(skip_all, err(Debug))]
pub async fn handler<AR, HC>(State(state): State<ServerState<AR, HC>>) -> Result<String, ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    match state.apt_repository.release_gpg_signature().await {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(ApiError::not_found("release not found")),
        Err(err) => Err(ApiError::internal(err.to_string())),
    }
}

// The /dists/stable/Release.gpg endpoint serves a detached GPG signature for the Release file.
// APT clients use this signature to verify the integrity and authenticity of the Release file by fetching it separately.
//
// ## Purpose
//
// - **Security**: Provides a cryptographic signature to confirm that the Release file has not been tampered with. It ensures that the metadata about packages (checksums, sizes, etc.) is trustworthy.
//
// ## Format
//
// The `Release.gpg` file is a standard PGP (GPG) detached signature in binary or ASCII-armored format. When using ASCII-armored format, it looks like this:
//
// ```/dev/null/Release.gpg#L1-6
// -----BEGIN PGP SIGNATURE-----
// Version: GnuPG v2
//
// [...signature data...]
// -----END PGP SIGNATURE-----
// ```
//
// ## Verification Process
//
// 1. **Fetch `Release`**: The APT client downloads the plain-text `Release` file.
// 2. **Fetch `Release.gpg`**: The client downloads the detached signature.
// 3. **Verify**: The client uses the repository's public key (which must be in its keyring) to verify that the signature in `Release.gpg` is valid for the `Release` file.
//
// If the verification is successful, APT trusts the checksums in the `Release` file and proceeds to download and verify the `Packages` files.

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
            .expect_release_gpg_signature()
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
            .expect_release_gpg_signature()
            .once()
            .return_once(|| {
                Box::pin(async move {
                    Ok(Some(String::from(
                        "-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n",
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
            "-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n"
        );
    }
}
