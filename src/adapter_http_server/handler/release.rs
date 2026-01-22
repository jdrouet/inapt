use axum::extract::State;

use crate::adapter_http_server::ServerState;
use crate::adapter_http_server::handler::ApiError;

#[tracing::instrument(skip_all, err(Debug))]
pub async fn handler<AR>(State(state): State<ServerState<AR>>) -> Result<String, ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
{
    let Some(meta) = state
        .apt_repository
        .release_metadata()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?
    else {
        return Err(ApiError::not_found("release not found"));
    };
    Ok(meta.serialize().to_string())
}

#[cfg(test)]
mod tests {
    use crate::domain::entity::ReleaseMetadata;
    use crate::domain::prelude::MockAptRepositoryService;

    // Example of returned data
    //
    // Origin: Debian
    // Label: Debian
    // Suite: stable
    // Version: 12.5
    // Codename: bookworm
    // Date: Tue, 04 Jun 2024 12:34:56 UTC
    // Architectures: amd64 arm64
    // Components: main contrib non-free
    // Description: Debian 12.5 Release
    //
    // MD5Sum:
    //  1234567890abcdef1234567890abcdef 12345 main/binary-amd64/Packages
    //  abcdef1234567890abcdef1234567890 23456 main/binary-amd64/Packages.gz
    //
    // SHA256:
    //  1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef 12345 main/binary-amd64/Packages
    //  abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 23456 main/binary-amd64/Packages.gz

    #[tokio::test]
    async fn should_return_error_if_empty() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_release_metadata()
            .once()
            .return_once(|| Box::pin(async move { Ok(None) }));
        let state = crate::adapter_http_server::ServerState { apt_repository };
        let err = super::handler(axum::extract::State(state))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn should_return_payload() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_release_metadata()
            .once()
            .return_once(|| {
                let value = ReleaseMetadata {
                    origin: "GitHub".into(),
                    label: "Debian".into(),
                    suite: "Stable".into(),
                    version: "1.2.3".into(),
                    codename: "Whatever".into(),
                    date: chrono::DateTime::from_timestamp(1286705410, 0).unwrap(),
                    architectures: Vec::default(),
                    components: vec!["main".into()],
                    description: "Mirror to GitHub".into(),
                    translation: Default::default(),
                };
                Box::pin(async move { Ok(Some(value)) })
            });
        let state = crate::adapter_http_server::ServerState { apt_repository };
        let value = super::handler(axum::extract::State(state)).await.unwrap();
        assert_eq!(
            value,
            "Origin: GitHub\nLabel: Debian\nSuite: Stable\nVersion: 1.2.3\nCodename: Whatever\nComponents: main\nDate: Sun, 10 Oct 2010 10:10:10 +0000\nAcquire-By-Hash: yes\nDescription: Mirror to GitHub\n"
        );
    }
}
