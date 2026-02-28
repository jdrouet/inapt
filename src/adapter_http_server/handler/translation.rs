//! Handler for Translation files (i18n).
//!
//! APT clients request Translation files for localized package descriptions.
//! We provide actual English descriptions in Translation-en, and return empty
//! content for other languages to avoid 404 errors.

use std::io::Write;

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use flate2::write::GzEncoder;

use crate::adapter_http_server::{HealthCheck, ServerState};

/// Empty gzip content for empty responses
const EMPTY_GZIP: &[u8] = &[
    0x1f, 0x8b, // magic number
    0x08, // compression method (deflate)
    0x00, // flags
    0x00, 0x00, 0x00, 0x00, // modification time
    0x00, // extra flags
    0xff, // OS (unknown)
    0x03, 0x00, // compressed data (empty deflate block)
    0x00, 0x00, 0x00, 0x00, // CRC32
    0x00, 0x00, 0x00, 0x00, // uncompressed size
];

/// Empty bzip2 content
const EMPTY_BZ2: &[u8] = &[
    0x42, 0x5a, // magic "BZ"
    0x68, // 'h' for bzip2
    0x39, // block size (900k)
    0x17, 0x72, 0x45, 0x38, 0x50, 0x90, // empty block
    0x00, 0x00, 0x00, 0x00, // padding
];

/// Empty xz content
const EMPTY_XZ: &[u8] = &[
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, // magic number
    0x00, 0x00, // stream flags
    0xff, 0x12, 0xd9, 0x41, // CRC32 of stream flags
    0x00, // block header (empty)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a, // stream footer
];

/// Compression format for translation files
#[derive(Debug, Clone, Copy, PartialEq)]
enum Compression {
    None,
    Gzip,
    Bzip2,
    Xz,
}

/// Parse a translation filename like "Translation-en" or "Translation-en.gz"
/// Returns (language, compression) or None if the filename is invalid.
fn parse_translation_filename(filename: &str) -> Option<(&str, Compression)> {
    let filename = filename.strip_prefix("Translation-")?;

    if let Some(lang) = filename.strip_suffix(".gz") {
        Some((lang, Compression::Gzip))
    } else if let Some(lang) = filename.strip_suffix(".bz2") {
        Some((lang, Compression::Bzip2))
    } else if let Some(lang) = filename.strip_suffix(".xz") {
        Some((lang, Compression::Xz))
    } else {
        Some((filename, Compression::None))
    }
}

/// Unified handler for all Translation files.
///
/// Parses the filename to determine language and compression format,
/// then returns the appropriate response.
#[tracing::instrument(skip_all)]
pub async fn handler<AR, APK, HC>(
    State(state): State<ServerState<AR, APK, HC>>,
    Path(filename): Path<String>,
) -> Result<Response, super::ApiError>
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
    APK: crate::domain::prelude::ApkRepositoryReader + Clone,
    HC: HealthCheck + Clone,
{
    let Some((lang, compression)) = parse_translation_filename(&filename) else {
        tracing::debug!(filename = %filename, "invalid translation filename");
        return Err(super::ApiError::not_found("Invalid translation filename"));
    };

    tracing::debug!(lang = %lang, compression = ?compression, "serving translation file");

    // Get content for English, empty for other languages
    let content = if lang == "en" {
        state
            .apt_repository
            .translation_file()
            .await
            .map_err(|err| {
                tracing::error!(error = ?err, "unable to fetch translation file");
                super::ApiError::internal("unable to fetch translation file")
            })?
    } else {
        String::new()
    };

    Ok(match compression {
        Compression::None => ([(header::CONTENT_TYPE, "text/plain")], content).into_response(),
        Compression::Gzip => {
            if content.is_empty() {
                return Ok(
                    ([(header::CONTENT_TYPE, "application/gzip")], EMPTY_GZIP).into_response()
                );
            }
            let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(content.as_bytes()).map_err(|err| {
                tracing::error!(error = ?err, "unable to compress translation file");
                super::ApiError::internal("unable to compress translation file")
            })?;
            let compressed = encoder.finish().map_err(|err| {
                tracing::error!(error = ?err, "unable to compress translation file");
                super::ApiError::internal("unable to compress translation file")
            })?;
            ([(header::CONTENT_TYPE, "application/gzip")], compressed).into_response()
        }
        Compression::Bzip2 => {
            // We don't support bzip2 compression for dynamic content
            // APT will fall back to .gz or plain
            ([(header::CONTENT_TYPE, "application/x-bzip2")], EMPTY_BZ2).into_response()
        }
        Compression::Xz => {
            // We don't support xz compression for dynamic content
            // APT will fall back to .gz or plain
            ([(header::CONTENT_TYPE, "application/x-xz")], EMPTY_XZ).into_response()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    use crate::{
        adapter_http_server::ServerState,
        domain::prelude::{MockApkRepositoryService, MockAptRepositoryService},
    };

    #[derive(Clone)]
    struct MockHealthCheck;

    impl HealthCheck for MockHealthCheck {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn should_parse_translation_filename() {
        assert_eq!(
            parse_translation_filename("Translation-en"),
            Some(("en", Compression::None))
        );
        assert_eq!(
            parse_translation_filename("Translation-en.gz"),
            Some(("en", Compression::Gzip))
        );
        assert_eq!(
            parse_translation_filename("Translation-fr.bz2"),
            Some(("fr", Compression::Bzip2))
        );
        assert_eq!(
            parse_translation_filename("Translation-de.xz"),
            Some(("de", Compression::Xz))
        );
        assert_eq!(parse_translation_filename("Invalid"), None);
        assert_eq!(parse_translation_filename("Packages"), None);
    }

    #[tokio::test]
    async fn should_return_plain_translation_when_en_requested() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_translation_file()
            .once()
            .return_once(|| Box::pin(async { Ok(String::from("Description: test")) }));

        let response = handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path("Translation-en".to_string()),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain"
        );
    }

    #[tokio::test]
    async fn should_return_empty_translation_when_other_lang_requested() {
        let apt_repository = MockAptRepositoryService::new();
        // No expectations - translation_file should not be called for non-English

        let response = handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path("Translation-fr".to_string()),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain"
        );
    }

    #[tokio::test]
    async fn should_return_compressed_translation_when_gz_requested() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_translation_file()
            .once()
            .return_once(|| Box::pin(async { Ok(String::from("Description: test")) }));

        let response = handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path("Translation-en.gz".to_string()),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/gzip"
        );
    }

    #[tokio::test]
    async fn should_return_empty_bz2_when_bz2_requested() {
        // bz2 returns empty content regardless of language, so use non-English
        let apt_repository = MockAptRepositoryService::new();

        let response = handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path("Translation-fr.bz2".to_string()),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/x-bzip2"
        );
    }

    #[tokio::test]
    async fn should_return_empty_xz_when_xz_requested() {
        // xz returns empty content regardless of language, so use non-English
        let apt_repository = MockAptRepositoryService::new();

        let response = handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path("Translation-de.xz".to_string()),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/x-xz"
        );
    }

    #[tokio::test]
    async fn should_return_not_found_when_invalid_filename() {
        let apt_repository = MockAptRepositoryService::new();

        let response = handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path("Invalid".to_string()),
        )
        .await;

        assert!(response.is_err());
    }

    #[tokio::test]
    async fn should_return_error_when_translation_fetch_fails() {
        let mut apt_repository = MockAptRepositoryService::new();
        apt_repository
            .expect_translation_file()
            .once()
            .return_once(|| Box::pin(async { Err(anyhow::anyhow!("fetch error")) }));

        let response = handler(
            State(ServerState {
                apt_repository,
                apk_repository: MockApkRepositoryService::new(),
                health_checker: MockHealthCheck,
            }),
            Path("Translation-en".to_string()),
        )
        .await;

        assert!(response.is_err());
    }
}
