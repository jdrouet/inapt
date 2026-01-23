# inapt

A minimal Debian/Ubuntu APT repository proxy written in Rust. It exposes a valid APT repository structure over HTTP while sourcing `.deb` packages directly from GitHub Release assets. Useful for distributing packages without hosting your own artifact storage.

## Features

- **Full APT Repository Structure**: Exposes standard Debian repository endpoints:
  - `dists/<suite>/Release` - Repository metadata
  - `dists/<suite>/InRelease` - Signed repository metadata
  - `dists/<suite>/Release.gpg` - Detached GPG signature
  - `dists/<suite>/<component>/binary-<arch>/Packages(.gz)` - Package indices
  - `dists/<suite>/<component>/binary-<arch>/by-hash/SHA256/<hash>` - By-hash index retrieval
  - `dists/<suite>/<component>/i18n/Translation-<lang>(.gz|.bz2|.xz)` - Package descriptions
  - `pool/main/.../*.deb` - Package downloads (302 redirects to GitHub)

- **GPG Signing**: Full support for signed releases with `InRelease` and `Release.gpg`

- **By-Hash Support**: Implements `Acquire-By-Hash` for atomic index updates

- **Translation Files**: Serves `Translation-en` files with package descriptions in multiple compression formats (gzip, bzip2, xz)

- **GitHub Integration**:
  - Dynamically builds Packages and Release metadata from GitHub Release assets
  - 302 redirects `.deb` downloads to GitHub (leverages GitHub CDN)
  - Supports multiple repositories
  - Optional authentication for private repositories and higher rate limits

- **Persistence**: SQLite backend for tracking scanned releases and caching package metadata

- **Incremental Synchronization**: Only processes new releases, skipping already-scanned ones

- **Observability**: Full OpenTelemetry support for tracing, metrics, and logs

## Quick Start

### 1. Generate GPG keys

```bash
cargo run --bin inapt-genkey > resources/private-key.pem
```

Extract the public key to share with users:

```bash
# The public key is printed first in the output
head -n 20 resources/private-key.pem > public-key.asc
```

### 2. Configure

Create a `config.toml` file:

```toml
[core]
origin = "My Repository"
label = "Debian"
suite = "stable"
version = "1.0.0"
codename = "cucumber"
description = "Packages from GitHub releases"
repositories = ["myorg/myproject", "myorg/another-project"]

[github]
# Optional: for private repos or higher rate limits
# token = "ghp_..."

[http_server]
address = "0.0.0.0"
port = 3000

[pgp_cipher]
private_key_path = "resources/private-key.pem"
# passphrase = "optional-passphrase"

[sqlite]
path = "inapt.db"

[worker]
interval = 3600  # Sync every hour (default: 43200 = 12 hours)
```

### 3. Run

```bash
cargo run
# Or with custom config path:
CONFIG_PATH=/path/to/config.toml cargo run
```

The proxy listens on `0.0.0.0:3000` by default.

### 4. Configure APT client

Add the repository and GPG key:

```bash
# Add the GPG key
curl -fsSL http://localhost:3000/public-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/inapt.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/inapt.gpg] http://localhost:3000 stable main" | \
  sudo tee /etc/apt/sources.list.d/inapt.list

# Update and install
sudo apt update
sudo apt install mypackage
```

For testing without signature verification (not recommended for production):

```bash
echo "deb [trusted=yes] http://localhost:3000 stable main" | \
  sudo tee /etc/apt/sources.list.d/inapt.list
```

## Configuration Reference

### Configuration File (TOML)

| Section | Key | Description | Default |
|---------|-----|-------------|---------|
| `core` | `origin` | Repository origin field | |
| `core` | `label` | Repository label | |
| `core` | `suite` | Distribution suite (e.g., stable) | |
| `core` | `version` | Repository version | |
| `core` | `codename` | Distribution codename | |
| `core` | `description` | Repository description | |
| `core` | `repositories` | List of GitHub repos (owner/repo) | |
| `github` | `base_url` | GitHub API URL | `https://api.github.com` |
| `github` | `token` | GitHub token (optional) | |
| `github` | `max_retry` | Max HTTP retries | `5` |
| `github` | `timeout` | Request timeout (seconds) | `60` |
| `http_server` | `address` | Bind address | `0.0.0.0` |
| `http_server` | `port` | Bind port | `3000` |
| `pgp_cipher` | `private_key_path` | Path to GPG private key | |
| `pgp_cipher` | `passphrase` | Key passphrase (optional) | |
| `sqlite` | `path` | SQLite database path | |
| `worker` | `interval` | Sync interval (seconds) | `43200` (12h) |

### Environment Variables (Tracing)

| Variable | Description | Default |
|----------|-------------|---------|
| `TRACING_MODE` | `console` or `otel` | `console` |
| `TRACING_LEVEL` | Log level filter | `info` |
| `TRACING_CONSOLE_COLOR` | Enable colored output | `true` |
| `TRACING_OTEL_ENDPOINT` | OTLP gRPC endpoint | `http://localhost:4317` |
| `TRACING_OTEL_INTERNAL_LEVEL` | Log level for OpenTelemetry internals | `error` |
| `ENV` | Deployment environment name | `local` |
| `HOST_NAME` | Override system hostname (useful in containers) | System hostname |
| `CONTAINER_ID` | Container ID for container environments | |

#### OpenTelemetry Resource Attributes

When `TRACING_MODE=otel`, the following [OpenTelemetry semantic convention](https://opentelemetry.io/docs/specs/semconv/resource/) resource attributes are automatically set:

| Attribute | Source |
|-----------|--------|
| `service.name` | Package name (`inapt`) |
| `service.version` | Package version |
| `deployment.environment.name` | `ENV` environment variable |
| `telemetry.sdk.name` | `opentelemetry` |
| `telemetry.sdk.language` | `rust` |
| `telemetry.sdk.version` | SDK version |
| `process.pid` | Current process ID |
| `process.executable.path` | Full path to executable |
| `process.executable.name` | Executable filename |
| `process.command_args` | Command line arguments |
| `os.type` | Operating system type |
| `host.name` | `HOST_NAME` env var or system hostname |
| `host.arch` | CPU architecture |
| `container.id` | `CONTAINER_ID` env var (if set) |

#### Example: Console Tracing (Development)

```bash
TRACING_MODE=console TRACING_LEVEL=debug cargo run
```

#### Example: OpenTelemetry with Jaeger

```bash
# Start Jaeger
docker run -d --name jaeger \
  -p 4317:4317 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest

# Run inapt with OTLP export
TRACING_MODE=otel \
TRACING_OTEL_ENDPOINT=http://localhost:4317 \
ENV=development \
cargo run

# View traces at http://localhost:16686
```

#### Example: Docker/Kubernetes with Container Attributes

```yaml
# docker-compose.yml
services:
  inapt:
    image: inapt:latest
    environment:
      - TRACING_MODE=otel
      - TRACING_OTEL_ENDPOINT=http://otel-collector:4317
      - ENV=production
      - CONTAINER_ID=${HOSTNAME}  # Docker sets HOSTNAME to container ID
      - HOST_NAME=apt.example.com  # Real hostname for identification
```

```yaml
# Kubernetes deployment
spec:
  containers:
    - name: inapt
      env:
        - name: TRACING_MODE
          value: "otel"
        - name: TRACING_OTEL_ENDPOINT
          value: "http://otel-collector.monitoring:4317"
        - name: ENV
          value: "production"
        - name: CONTAINER_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.uid
        - name: HOST_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
```

## Docker

### Using Docker Compose

```bash
docker-compose up
```

### Manual Docker Build

```bash
docker build -t inapt .
docker run -p 3000:3000 \
  -v ./config.toml:/etc/inapt/config.toml \
  -v ./inapt.db:/data/inapt.db \
  -v ./resources/private-key.pem:/etc/inapt/private-key.pem \
  inapt
```

## Architecture

inapt follows a hexagonal (ports & adapters) architecture:

```
                    ┌─────────────────────────────────────┐
                    │           Domain Layer              │
                    │  ┌─────────────────────────────┐   │
                    │  │   AptRepositoryService      │   │
                    │  │   - Synchronization         │   │
                    │  │   - Metadata generation     │   │
                    │  │   - Package indexing        │   │
                    │  └─────────────────────────────┘   │
                    └─────────────────────────────────────┘
                                    │
        ┌───────────────┬───────────┼───────────┬───────────────┐
        ▼               ▼           ▼           ▼               ▼
┌───────────────┐ ┌───────────┐ ┌────────┐ ┌─────────┐ ┌───────────────┐
│  HTTP Server  │ │  GitHub   │ │  DEB   │ │   PGP   │ │    SQLite     │
│    (Axum)     │ │   Client  │ │ Reader │ │ Signer  │ │   Storage     │
└───────────────┘ └───────────┘ └────────┘ └─────────┘ └───────────────┘
```

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run E2E tests (requires Docker)
cargo test --test e2e_apt_repository -- --ignored

# Format & lint
cargo fmt
cargo clippy

# Generate coverage report
cargo llvm-cov
```

## Roadmap

### High Priority

- [x] Health check endpoint (`/health`) for load balancers and Kubernetes probes
- [ ] Public key endpoint (`/public-key.asc`) to serve GPG key directly
- [ ] ETag/If-None-Match caching against GitHub API for reduced API calls

### Medium Priority

- [ ] Package version retention policy (keep only N latest versions per package)
- [ ] Multiple components support (organize packages beyond `main`)
- [ ] Range proxy mode for private repositories (stream through instead of redirect)
- [ ] Package filtering (include/exclude patterns for .deb files)

### Low Priority

- [ ] PostgreSQL backend option for larger deployments
- [ ] Web UI for repository browsing
- [ ] Webhook support for immediate sync on new GitHub releases

## License

This project is licensed under the **AGPL-3.0**.

For companies or organizations that wish to use this software in a commercial context **without the obligations of the AGPL**, a **commercial license** is available. Please contact us at **contact@jdrouet.fr** for details.
