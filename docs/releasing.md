# Releasing

This project follows semantic versioning.

## Versioning

- Patch release: bug fixes, documentation corrections, dependency updates that do not change behavior.
- Minor release: new backwards-compatible CLI flags, auth flows, or platform support.
- Major release: backwards-incompatible CLI/config behavior or removed supported features.

The first public release is `0.1.0`. While the major version is `0`, minor releases may still contain user-visible iteration, but incompatible behavior should still be called out in release notes.

## Release Checklist

1. Update `version` in `Cargo.toml`.
2. Run the local verification suite:

   ```sh
   CARGO_HOME=$PWD/.cargo-home cargo fmt --check
   CARGO_HOME=$PWD/.cargo-home cargo check --all-targets
   CARGO_HOME=$PWD/.cargo-home cargo clippy --all-targets -- -D warnings
   CARGO_HOME=$PWD/.cargo-home cargo test
   target/cargo-tools/bin/cargo-audit audit
   ```

3. Commit the version change.
4. Create and push an annotated tag matching the Cargo version:

   ```sh
   git tag -a v0.1.0 -m "Release v0.1.0"
   git push origin v0.1.0
   ```

5. The GitHub Actions release workflow builds release archives for:

   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `x86_64-unknown-linux-gnu`

6. Confirm the GitHub release contains all `.tar.gz` archives and `SHA256SUMS`.

## Installer

The one-line installer downloads the latest GitHub release asset for the current platform, verifies the checksum, and installs the binary into `${HOME}/.local/bin` unless `INSTALL_DIR` is set.

```sh
curl -fsSL https://raw.githubusercontent.com/tuannvm/okta-awscli-rs/feature/rust-okta-awscli/scripts/install.sh | sh
```

Install a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/tuannvm/okta-awscli-rs/feature/rust-okta-awscli/scripts/install.sh | OKTA_AWSCLI_RS_VERSION=0.1.0 sh
```
