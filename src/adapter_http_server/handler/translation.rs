//! Handler for Translation files (i18n).
//!
//! APT clients request Translation files for localized package descriptions.
//! Since this repository doesn't provide translations, we return empty content
//! to avoid 404 errors in APT client logs.

use axum::extract::Path;
use axum::http::header;
use axum::response::{IntoResponse, Response};

/// Handler for plain Translation files (e.g., Translation-en).
///
/// Returns an empty response since we don't have translations.
#[tracing::instrument(skip_all)]
pub async fn handler(Path(lang): Path<String>) -> Response {
    tracing::debug!(lang = %lang, "serving empty translation file");
    ([(header::CONTENT_TYPE, "text/plain")], "").into_response()
}

/// Handler for gzip-compressed Translation files (e.g., Translation-en.gz).
///
/// Returns an empty gzip-compressed response.
#[tracing::instrument(skip_all)]
pub async fn gz_handler(Path(lang): Path<String>) -> Response {
    tracing::debug!(lang = %lang, "serving empty gzip translation file");
    // Empty gzip file (gzip header with no content)
    // This is a minimal valid gzip stream representing empty content
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
/// Returns an empty bzip2-compressed response.
#[tracing::instrument(skip_all)]
pub async fn bz2_handler(Path(lang): Path<String>) -> Response {
    tracing::debug!(lang = %lang, "serving empty bzip2 translation file");
    // Empty bzip2 file
    // This is a minimal valid bzip2 stream representing empty content
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
/// Returns an empty xz-compressed response.
#[tracing::instrument(skip_all)]
pub async fn xz_handler(Path(lang): Path<String>) -> Response {
    tracing::debug!(lang = %lang, "serving empty xz translation file");
    // Empty xz file created from compressing empty content
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
    async fn test_plain_translation() {
        let response = super::handler(Path("en".to_string())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain"
        );
    }

    #[tokio::test]
    async fn test_gz_translation() {
        let response = super::gz_handler(Path("en".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/gzip"
        );
    }

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
