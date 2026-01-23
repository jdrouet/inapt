# Contributing to inapt

Thank you for your interest in contributing to inapt! This document outlines contribution opportunities and guidelines for getting started.

## Getting Started

### Prerequisites

- Rust (latest stable)
- Docker (for E2E tests)
- SQLite

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/inapt.git
cd inapt

# Build the project
cargo build

# Run tests
cargo test

# Run with development config
cargo run
```

### Code Quality

Before submitting a PR, ensure your code passes all checks:

```bash
cargo fmt        # Format code
cargo clippy     # Lint
cargo test       # Run tests
cargo audit      # Security audit
```

## Contribution Opportunities

Below are areas where contributions would be valuable.

### Testing Improvements

#### 1. Enable E2E Tests in CI
**Effort: Low | Impact: Medium**

Currently E2E tests are feature-gated and not run in default CI.

**Requirements:**
- Enable Docker in CI environment
- Run E2E tests on every PR
- Add timeout handling for flaky tests

**Files to modify:**
- `.github/workflows/` - Update CI configuration

---

#### 2. Integration Tests
**Effort: Medium | Impact: Medium**

Add mid-level integration tests between unit and E2E tests.

**Requirements:**
- Test adapter interactions without external dependencies
- Mock GitHub API responses
- Test database migrations
- Test configuration parsing edge cases

---

#### 3. Error Scenario E2E Tests
**Effort: Medium | Impact: Low**

Expand E2E test coverage for failure modes.

**Scenarios to test:**
- GitHub API rate limiting
- Network timeouts
- Malformed `.deb` files
- Database corruption recovery
- Invalid GPG key handling

---

### Documentation Improvements

#### 1. Configuration Schema
**Effort: Low | Impact: Low**

Add JSON schema for configuration validation.

**Requirements:**
- Document all configuration options
- Provide editor autocomplete support
- Validate configuration at startup

---

#### 2. Database Migration Guide
**Effort: Low | Impact: Low**

Document how to handle database migrations when upgrading.

**Topics:**
- Backup procedures
- Manual migration steps
- Rollback instructions
- Schema version checking

---

## Code Style Guidelines

- Follow standard Rust conventions (`rustfmt`)
- Use `anyhow::Result` for error handling
- Add tracing instrumentation to new functions
- Write tests for new functionality
- Keep functions small and focused
- Document public APIs

### Testing Conventions

- Test function names should follow the pattern `fn should_do_this_when_that()`
  ```rust
  #[test]
  fn should_return_empty_list_when_no_packages_found() { ... }
  
  #[test]
  fn should_fail_when_database_connection_lost() { ... }
  ```

### Database Queries

- **Do not use `sqlx::query_*!` macros** - Use the non-macro variants instead (`sqlx::query`, `sqlx::query_as`, etc.)

### Error Handling

- Do not use single letters for error variables
- Use `err` or `error` instead of `e` for readability
  ```rust
  // Bad
  .map_err(|e| anyhow::anyhow!("Failed: {e}"))
  
  // Good
  .map_err(|err| anyhow::anyhow!("Failed: {err}"))
  ```

### Code Coverage

Generate code coverage reports with:
```bash
cargo llvm-cov
```

## Architecture Notes

inapt follows a hexagonal (ports & adapters) architecture:

- **Domain Layer** (`src/domain/`): Core business logic, independent of external systems
- **Adapters** (`src/adapter_*/`): Implementations for external systems (HTTP, GitHub, SQLite, etc.)
- **Traits** (`src/domain/prelude.rs`): Interfaces that adapters implement

When adding new features:
1. Define any new traits in the domain layer
2. Implement adapters for external integrations
3. Keep the domain layer free of framework dependencies

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run all checks (`cargo fmt && cargo clippy && cargo test`)
5. Commit with a descriptive message
6. Push to your fork
7. Open a Pull Request

### Commit Message Format

Use conventional commits:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions or fixes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

### Pull Request Title

Pull request titles **must** follow the conventional commits format:
- `feat: add health check endpoint`
- `fix: handle empty package list gracefully`
- `docs: update configuration reference`

This ensures consistent changelog generation and release notes.

## Questions?

Feel free to open an issue for discussion before starting work on larger features. This helps ensure your contribution aligns with the project direction and avoids duplicate effort.
