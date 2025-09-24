# inapt

A minimal Debian/Ubuntu APT repository proxy written in Rust. It exposes a valid APT repo structure over HTTP but sources .deb packages directly from GitHub Release assets. Useful for distributing packages without hosting your own artifact storage.

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
git clone https://github.com/yourname/inapt.git
cd inapt
cp .env.example .env
```

Edit .env to list the GitHub repos you want to expose, e.g.:

```
REPOS=myorg/myproject
SUITE=stable
COMPONENT=main
ARCHS=amd64
```

2. Run

```
cargo run
```

The proxy listens on 0.0.0.0:8080 by default.

3. Configure APT client

For now, you must trust the repo (unsigned):

```
echo "deb [trusted=yes] http://localhost:8080 stable main" | sudo tee /etc/apt/sources.list.d/inapt.list
sudo apt update
```

Then you can install packages from your proxied repos:

```
sudo apt install mypackage
```

## Configuration

The server is configured through environment variables:

| Variable         | Description                                          | Default |
|------------------|------------------------------------------------------|---------|
| `REPOS`          | Comma-separated owner/repo list to scan for releases |         |
| `GITHUB_TOKEN`   | Optional token (higher rate limit, private repos)    | none    |
| `SUITE`          | Distribution codename (e.g., stable)                 | stable  |
| `COMPONENT`      | Component (e.g., main)                               | main    |
| `ARCHS`          | Comma-separated architectures (e.g., amd64,arm64)    | amd64   |
| `CACHE_TTL_SECS` | Cache duration for GitHub release queries            | 900     |

## Roadmap

- [ ] Add GPG signing for Release → InRelease.
- [ ] ETag/If-None-Match against GitHub API for better efficiency.
- [ ] On-disk cache of package metadata to avoid re-downloading assets.
- [ ] Add by-hash support (by-hash/SHA256/...).
- [ ] Multiple suites/components support.
- [ ] Range proxy mode for private repositories (instead of redirect).

## License

MIT — do what you want, attribution appreciated.

## Status

Draft/experimental. Tested with apt on Debian/Ubuntu for basic package installs. Needs signing and caching improvements for production use.
