# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.8](https://github.com/jdrouet/inapt/compare/v0.1.7...v0.1.8) - 2025-10-05

### Fixed

- allow to follow multiple repositories

### Other

- ignore RUSTSEC-2024-0384 considering it's not relevent

## [0.1.7](https://github.com/jdrouet/inapt/compare/v0.1.6...v0.1.7) - 2025-10-05

### Added

- add environment to telemetry
- add github timeout
- add span name to http server
- update client traces

### Other

- remove service name
- update dockerfile to have revision parameter

## [0.1.6](https://github.com/jdrouet/inapt/compare/v0.1.5...v0.1.6) - 2025-10-05

### Added

- add peer.hostname to client tracing

### Other

- use generic span name

## [0.1.5](https://github.com/jdrouet/inapt/compare/v0.1.4...v0.1.5) - 2025-10-05

### Added

- update http server tracing
- update tracing for github client

## [0.1.4](https://github.com/jdrouet/inapt/compare/v0.1.3...v0.1.4) - 2025-10-04

### Added

- use inner client to download file

### Other

- ignore invalid packages

## [0.1.3](https://github.com/jdrouet/inapt/compare/v0.1.2...v0.1.3) - 2025-10-04

### Added

- configure for opentelemetry collector
- prepare for console logs

### Fixed

- remove log

### Other

- prevent building docker image for arm64
- use reqwest to query releases

## [0.1.2](https://github.com/jdrouet/inapt/compare/v0.1.1...v0.1.2) - 2025-10-03

### Added

- write on disk after each sync
- avoid fetching a known package

### Fixed

- please clippy

### Other

- restart inapt after install
- rename storage adapter

## [0.1.1](https://github.com/jdrouet/inapt/compare/v0.1.0...v0.1.1) - 2025-10-01

### Added

- load domain config from env variable
- implement pool redirection
- add Filename to package file

### Fixed

- make the deb build work

### Other

- *(deps)* Bump axum from 0.8.5 to 0.8.6 ([#7](https://github.com/jdrouet/inapt/pull/7))
- add release-package workflow to push deb file
- update deb building process
- *(deps)* Bump actions/checkout from 4 to 5 ([#4](https://github.com/jdrouet/inapt/pull/4))
- *(deps)* Bump octocrab from 0.45.0 to 0.46.0 ([#5](https://github.com/jdrouet/inapt/pull/5))
- *(deps)* Bump thiserror from 2.0.16 to 2.0.17 ([#6](https://github.com/jdrouet/inapt/pull/6))
- *(deps)* Bump axum from 0.8.4 to 0.8.5 ([#3](https://github.com/jdrouet/inapt/pull/3))
- add codecov token
- update readme
- update license section in readme
- add working example with octopus deploy
- update dockerfile to instal certificates
- configure dependabot
- release v0.1.0 ([#1](https://github.com/jdrouet/inapt/pull/1))

## [0.1.0](https://github.com/jdrouet/inapt/releases/tag/v0.1.0) - 2025-09-29

### Added

- implement release date
- implement release endpoint
- implement adapter basics
- prepare test example with http-server
- prepare http handlers
- install tracing
- prepare http server

### Fixed

- please clippy

### Other

- update readme
- add release-plz config
- update cargo.toml
- create workflow for debian package
- basic configuration
- cover more adapters
- cover AptRepositoryReader
- cover AptRepositoryWriter
- create dockerfile
- handle packages file
- download deb files in parallel
- allow no github token
- move serializer
- use hexa arch
- prepare project
