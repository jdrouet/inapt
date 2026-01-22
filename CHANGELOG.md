# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1](https://github.com/jdrouet/inapt/compare/v0.3.0...v0.3.1) - 2026-01-22

### Added

- serve actual package descriptions in Translation-en files ([#44](https://github.com/jdrouet/inapt/pull/44))
- serve empty translation files to avoid APT client 404 errors ([#42](https://github.com/jdrouet/inapt/pull/42))

### Other

- add multiarch Docker image build to release workflow ([#45](https://github.com/jdrouet/inapt/pull/45))
- update README with implemented features and roadmap

## [0.3.0](https://github.com/jdrouet/inapt/compare/v0.2.1...v0.3.0) - 2026-01-21

### Added

- add by-hash support for APT index retrieval ([#40](https://github.com/jdrouet/inapt/pull/40))
- SQLite storage for incremental GitHub release synchronization ([#34](https://github.com/jdrouet/inapt/pull/34))

### Fixed

- builder on the ci

### Other

- add end-to-end tests for APT repository ([#41](https://github.com/jdrouet/inapt/pull/41))
- *(deps)* Bump chrono from 0.4.42 to 0.4.43 ([#39](https://github.com/jdrouet/inapt/pull/39))
- *(deps)* Bump thiserror from 2.0.17 to 2.0.18 ([#38](https://github.com/jdrouet/inapt/pull/38))
- *(deps)* Bump flate2 from 1.1.5 to 1.1.8 ([#37](https://github.com/jdrouet/inapt/pull/37))
- *(deps)* Bump reqwest-tracing from 0.5.8 to 0.6.0 ([#36](https://github.com/jdrouet/inapt/pull/36))
- *(deps)* Bump tracing from 0.1.41 to 0.1.44 ([#31](https://github.com/jdrouet/inapt/pull/31))
- *(deps)* Bump serde_json from 1.0.145 to 1.0.146 ([#32](https://github.com/jdrouet/inapt/pull/32))
- *(deps)* Bump reqwest-retry from 0.7.0 to 0.8.0 ([#33](https://github.com/jdrouet/inapt/pull/33))

## [0.2.1](https://github.com/jdrouet/inapt/compare/v0.2.0...v0.2.1) - 2025-12-20

### Fixed

- use deployment.environment for environment key

### Other

- remove allow unused

## [0.2.0](https://github.com/jdrouet/inapt/compare/v0.1.8...v0.2.0) - 2025-12-20

### Added

- handle release.gpg endpoint ([#26](https://github.com/jdrouet/inapt/pull/26))
- automatically generate gpg private key
- create bin to generate keys
- implement inrelease endpoint

### Fixed

- inrelease signature

### Other

- ignore RUSTSEC-2023-0071
- *(deps)* Bump flate2 from 1.1.2 to 1.1.5 ([#19](https://github.com/jdrouet/inapt/pull/19))
- *(deps)* Bump sequoia-openpgp from 2.0.0 to 2.1.0 ([#20](https://github.com/jdrouet/inapt/pull/20))
- *(deps)* Bump axum from 0.8.6 to 0.8.7 ([#21](https://github.com/jdrouet/inapt/pull/21))
- *(deps)* Bump mockall from 0.13.1 to 0.14.0 ([#22](https://github.com/jdrouet/inapt/pull/22))
- *(deps)* Bump http from 1.3.1 to 1.4.0 ([#23](https://github.com/jdrouet/inapt/pull/23))
- *(deps)* Bump actions/checkout from 5 to 6 ([#24](https://github.com/jdrouet/inapt/pull/24))
- *(deps)* Bump actions/cache from 4 to 5 ([#25](https://github.com/jdrouet/inapt/pull/25))
- *(deps)* Bump reqwest from 0.12.23 to 0.12.24 ([#16](https://github.com/jdrouet/inapt/pull/16))
- *(deps)* Bump tokio from 1.47.1 to 1.48.0 ([#17](https://github.com/jdrouet/inapt/pull/17))
- move configuration to toml file

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
