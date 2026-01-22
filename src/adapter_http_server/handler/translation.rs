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

use crate::adapter_http_server::ServerState;

/// Handler for plain Translation files (e.g., Translation-en).
#[tracing::instrument(skip_all)]
pub async fn handler<AR>(State(state): State<ServerState<AR>>, Path(lang): Path<String>) -> Response
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
{
    tracing::debug!(lang = %lang, "serving translation file");

    // Only provide actual translations for English
    if lang == "en" {
        match state.apt_repository.translation_file().await {
            Ok(content) => {
                return ([(header::CONTENT_TYPE, "text/plain")], content).into_response();
            }
            Err(err) => {
                tracing::error!(error = ?err, "unable to fetch translation file");
            }
        }
    }

    // Return empty content for other languages or on error
    ([(header::CONTENT_TYPE, "text/plain")], "").into_response()
}

/// Handler for gzip-compressed Translation files (e.g., Translation-en.gz).
#[tracing::instrument(skip_all)]
pub async fn gz_handler<AR>(
    State(state): State<ServerState<AR>>,
    Path(lang): Path<String>,
) -> Response
where
    AR: crate::domain::prelude::AptRepositoryReader + Clone,
{
    tracing::debug!(lang = %lang, "serving gzip translation file");

    // Only provide actual translations for English
    if lang == "en" {
        match state.apt_repository.translation_file().await {
            Ok(content) => {
                let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
                if encoder.write_all(content.as_bytes()).is_ok()
                    && let Ok(compressed) = encoder.finish()
                {
                    return ([(header::CONTENT_TYPE, "application/gzip")], compressed)
                        .into_response();
                }
                tracing::error!("unable to compress translation file");
            }
            Err(err) => {
                tracing::error!(error = ?err, "unable to fetch translation file");
            }
        }
    }

    // Return empty gzip for other languages or on error
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
    ([(header::CONTENT_TYPE, "application/gzip")], EMPTY_GZIP).into_response()
}

/// Handler for bzip2-compressed Translation files (e.g., Translation-en.bz2).
///
/// Returns empty bzip2 content since we don't support bzip2 compression
/// for dynamic content. APT will fall back to .gz or plain.
#[tracing::instrument(skip_all)]
pub async fn bz2_handler(Path(lang): Path<String>) -> Response {
    tracing::debug!(lang = %lang, "serving empty bzip2 translation file");
    // Empty bzip2 file
    const EMPTY_BZ2: &[u8] = &[
        0x42, 0x5a, // magic "BZ"
        0x68, // 'h' for bzip2
        0x39, // block size (900k)
        0x17, 0x72, 0x45, 0x38, 0x50, 0x90, // empty block
        0x00, 0x00, 0x00, 0x00, // padding
    ];
    ([(header::CONTENT_TYPE, "application/x-bzip2")], EMPTY_BZ2).into_response()
}

/// Handler for xz-compressed Translation files (e.g., Translation-en.xz).
///
/// Returns empty xz content since we don't support xz compression
/// for dynamic content. APT will fall back to .gz or plain.
#[tracing::instrument(skip_all)]
pub async fn xz_handler(Path(lang): Path<String>) -> Response {
    tracing::debug!(lang = %lang, "serving empty xz translation file");
    // Empty xz file
    const EMPTY_XZ: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, // magic number
        0x00, 0x00, // stream flags
        0xff, 0x12, 0xd9, 0x41, // CRC32 of stream flags
        0x00, // block header (empty)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a, // stream footer
    ];
    ([(header::CONTENT_TYPE, "application/x-xz")], EMPTY_XZ).into_response()
}

#[cfg(test)]
mod tests {
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn test_bz2_translation() {
        let response = super::bz2_handler(Path("en".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/x-bzip2"
        );
    }

    #[tokio::test]
    async fn test_xz_translation() {
        let response = super::xz_handler(Path("en".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/x-xz"
        );
    }
}
