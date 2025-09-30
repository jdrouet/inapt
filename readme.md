# inapt

A minimal Debian/Ubuntu APT repository proxy written in Rust. It exposes a valid APT repo structure over HTTP but sources .deb packages directly from GitHub Release assets. Useful for distributing packages without hosting your own artifact storage.

> ⚠️ The following readme is a goal, it's not yet implemented...

## Features

- Exposes a Debian repository structure over HTTP:
  - `dists/<suite>/Release`
  - `dists/<suite>/<component>/binary-<arch>/Packages(.gz)`
  - `pool/main/.../*.deb`
- Dynamically builds Packages and Release from GitHub Release assets.
- 302 redirects `.deb` downloads to GitHub (leverages GitHub CDN).
- Supports multiple repositories (via `REPOS=owner1/repo1,owner2/repo2`).
- Caches results in memory (configurable TTL).
- Extracts control metadata from .deb to generate proper Packages entries.

⚠️ Signing (`InRelease/Release.gpg`) is not yet implemented.

## Quick Start

1. Clone & configure

```bash
git clone https://github.com/jdrouet/inapt.git
cd inapt
```

Edit .env to list the GitHub repos you want to expose, e.g.:

```
REPO_ORIGIN=My Origin
REPO_LABEL=Debian
REPO_SUITE=sable
REPO_VERSION=1.2.3
REPO_CODENAME=cucumber
REPO_DESCRIPTION=How you want to describe it
REPO_REPOSITORIES=myorg/myproject
```

2. Run

```
cargo run
```

The proxy listens on 0.0.0.0:3000 by default.

3. Configure APT client

For now, you must trust the repo (unsigned):

```
echo "deb [trusted=yes] http://localhost:3000 stable main" | sudo tee /etc/apt/sources.list.d/inapt.list
sudo apt update
```

Then you can install packages from your proxied repos:

```
sudo apt install mypackage
```

## Configuration

The server is configured through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `REPO_REPOSITORIES` | Comma-separated owner/repo list to scan for releases | |
| `REPO_SUITE` | Distribution codename (e.g., stable) | stable |
| `GITHUB_TOKEN` | Optional token (higher rate limit, private repos) | none |

## Roadmap

- [ ] Add GPG signing for Release → InRelease.
- [ ] ETag/If-None-Match against GitHub API for better efficiency.
- [ ] On-disk cache of package metadata to avoid re-downloading assets.
- [ ] Add by-hash support (by-hash/SHA256/...).
- [ ] Multiple suites/components support.
- [ ] Range proxy mode for private repositories (instead of redirect).

## License

This project is licensed under the **AGPL-3.0**.

For companies or organizations that wish to use this software in a commercial context **without the obligations of the AGPL**, a **commercial license** is available. Please contact us at **contact@jdrouet.fr** for details.

## Status

Draft/experimental. Tested with apt on Debian/Ubuntu for basic package installs. Needs signing and caching improvements for production use.
