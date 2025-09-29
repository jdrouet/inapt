pub async fn handler() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}

// The `/dists/stable/InRelease` endpoint serves a **signed version of the Release file**. It is a single file that contains both the Release metadata and a GPG signature, allowing APT clients to verify the authenticity and integrity of the repository metadata in one request.
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
