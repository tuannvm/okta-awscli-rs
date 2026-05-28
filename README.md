# okta-awscli-rs

`okta-awscli-rs` signs in to Okta, retrieves an AWS SAML assertion, exchanges it for temporary AWS STS credentials, and optionally runs `aws` with those credentials.

It is a Rust reimplementation of the Python `okta-awscli` workflow with the same config file shape and CLI habits.

## What It Does

- Reuses `~/.okta-aws` profiles from the Python tool.
- Authenticates with Okta Classic Authn.
- Supports TOTP, Okta Verify push, app-level MFA, SMS/call app MFA, and U2F security keys.
- Discovers Okta AWS app links when `app-link` is not configured.
- Extracts the AWS SAML response and calls AWS STS `AssumeRoleWithSAML`.
- Writes temporary credentials to `~/.aws/credentials` or `AWS_SHARED_CREDENTIALS_FILE`.
- Runs `aws --profile <profile> ...` when AWS CLI arguments are provided.
- Supports browser-assisted FastPass/fingerprint authentication with an isolated Chrome/Chromium-family session.

## Install

```sh
cargo install --path .
```

For local development:

```sh
cargo build
```

The package binary is `okta-awscli-rs`. The CLI name in help output is `okta-awscli` for compatibility with the original tool.

## Quick Start

Create or update an Okta profile:

```sh
okta-awscli-rs --config
```

Authenticate and write temporary AWS credentials:

```sh
okta-awscli-rs --okta-profile default --profile my-aws-profile
```

Authenticate, refresh credentials if needed, and run the AWS CLI:

```sh
okta-awscli-rs --profile my-aws-profile sts get-caller-identity
okta-awscli-rs --profile my-aws-profile iam list-users
```

Use a TOTP code without waiting for an interactive prompt:

```sh
okta-awscli-rs --profile my-aws-profile --token 123456
```

## Decision Guide

| Need | Use |
| --- | --- |
| FastPass, Touch ID, or browser-registered fingerprint auth | `--browser` |
| Okta Verify push, TOTP, U2F, or app-level MFA | default flow |
| Experimental terminal WebAuthn | `--webauthn-keychain` with CLI-enrolled credentials only |

## Configuration

The config file is `~/.okta-aws`:

```ini
[default]
base-url = example.okta.com
username = user@example.com
factor = OKTA
profile = my-aws-profile
duration = 3600
```

Common optional fields:

- `password`: Okta password. Avoid storing this in plaintext when possible.
- `app-link`: Okta AWS app link. If omitted, the tool discovers AWS apps from Okta.
- `role`: AWS role ARN. If omitted, the tool prompts you to choose a role.
- `factor`: preferred MFA provider. Supported values include `OKTA`, `OKTA_PUSH`, `OKTA_TOTP`, `GOOGLE`, and `U2F`.

See [docs/configuration.md](docs/configuration.md) for the full config reference.

## Browser-Assisted FastPass

Use browser capture mode when FastPass or a platform fingerprint authenticator is required:

```sh
okta-awscli-rs --okta-profile default --profile my-aws-profile --browser
```

The CLI launches an isolated Chrome/Chromium-family browser session, opens the configured Okta AWS app link, lets you authenticate with FastPass, captures the AWS SAML POST, and then assumes the AWS role.

Use a longer wait when your sign-in flow needs more time:

```sh
okta-awscli-rs --okta-profile default --profile my-aws-profile --browser --browser-timeout 300
```

If automatic capture is not available, use manual paste mode:

```sh
okta-awscli-rs --okta-profile default --profile my-aws-profile --browser-paste
```

## Experimental WebAuthn Keychain

For Okta tenants that expose a Classic Authn `webauthn` factor, the CLI can try a macOS Keychain-backed virtual authenticator. This is niche and experimental; use `--browser` for normal FastPass, Touch ID, browser passkeys, or platform fingerprint authentication.

```sh
okta-awscli-rs --okta-profile default --profile my-aws-profile --webauthn-keychain
```

Enroll a compatible credential when Okta offers WebAuthn enrollment during Classic Authn:

```sh
okta-awscli-rs --okta-profile default --username user@example.com --webauthn-keychain-enroll
```

This is experimental. The enrollment helper generates a new ES256 credential, completes Okta's WebAuthn make-credential activation, and stores the encrypted private key as a generic macOS Keychain item under the Okta relying party. It does not import browser/iCloud passkeys, and many Okta orgs require factor enrollment from the browser Security Methods page instead of the Classic Authn API. Use `--browser` for normal FastPass.

## End-to-End Testing

Run the deterministic mock E2E tests:

```sh
CARGO_HOME=$PWD/.cargo-home cargo test --test e2e_mock
```

Run the full local verification suite:

```sh
CARGO_HOME=$PWD/.cargo-home cargo fmt --check
CARGO_HOME=$PWD/.cargo-home cargo check --all-targets
CARGO_HOME=$PWD/.cargo-home cargo clippy --all-targets -- -D warnings
CARGO_HOME=$PWD/.cargo-home cargo test
```

See [docs/testing.md](docs/testing.md) for test strategy and adding new flows.

## Documentation

- [docs/getting-started.md](docs/getting-started.md): first run and common commands.
- [docs/configuration.md](docs/configuration.md): `~/.okta-aws` and AWS credential file behavior.
- [docs/auth-flow.md](docs/auth-flow.md): Okta, SAML, MFA, and AWS STS flow.
- [docs/testing.md](docs/testing.md): unit, integration, and mock E2E tests.
- [docs/development.md](docs/development.md): crate layout and maintenance notes.
- [docs/troubleshooting.md](docs/troubleshooting.md): common failures and fixes.

## Status

This repository is a Rust port of the Python behavior. It uses direct Okta Authn HTTP calls because the current Rust `okta` crate targets Okta Management API use cases and does not cover this Classic Authn plus AWS SAML flow.
