# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v2.1.0 2026-02-12

### Changed
- Aligned Virgil crypto dependencies (SDK/Pythia/Ratchet) to use a consistent underlying Virgil Crypto baseline with Android 16 KB page-size compatibility in mind.
- Updated CI to run compilation + JVM unit tests only (removed emulator/connected Android test execution).

### Fixed
- Fixed Gradle 8 task validation issues caused by implicit dependencies between `generateVirgilInfo`, KAPT outputs, and Dokka tasks in `ethree-common`.

### Added
- Added `.ci/publish-central.sh` helper to build a Sonatype Central Portal bundle (repo layout + checksums + zip), upload it, and optionally poll until `PUBLISHED`.

### CI
- Improved publishing workflow robustness by verifying the version via Gradle project properties (instead of parsing build files) and simplifying Gradle invocations.
