# Testing

The project has three useful verification levels.

## Fast Checks

```sh
CARGO_HOME=$PWD/.cargo-home cargo fmt --check
CARGO_HOME=$PWD/.cargo-home cargo check --all-targets
```

## Full Local Suite

```sh
CARGO_HOME=$PWD/.cargo-home cargo clippy --all-targets -- -D warnings
CARGO_HOME=$PWD/.cargo-home cargo test
```

`CARGO_HOME=$PWD/.cargo-home` keeps dependency downloads in the workspace. This is useful in sandboxed environments where the default Cargo cache may not be writable.

## Mock End-To-End Tests

```sh
CARGO_HOME=$PWD/.cargo-home cargo test --test e2e_mock
```

The E2E tests use `wiremock` to simulate Okta:

- Primary Authn success.
- Tenant TOTP MFA.
- Session creation.
- AWS appLinks discovery.
- AWS SAML app page.

AWS STS is represented by a fake `StsProvider`, so tests do not require real AWS credentials.

## CLI Tests

```sh
CARGO_HOME=$PWD/.cargo-home cargo test --test cli
```

The CLI test verifies that `--help` parses and exits successfully. This catches Clap configuration regressions.

## Adding A New Okta Flow Test

1. Add a new async test in `tests/e2e_mock.rs`.
2. Start a `MockServer`.
3. Mock the Okta endpoints needed for the flow.
4. Write a temporary `.okta-aws` config with the mock base URL.
5. Construct `OktaAuth` and call `get_assertion`.
6. Assert the expected SAML assertion or MFA request body.

Prefer testing protocol behavior at the HTTP boundary. That keeps tests deterministic while still covering the real parser and control flow.

## Manual Smoke Test

With a real Okta profile:

```sh
okta-awscli-rs --okta-profile default --profile smoke-test sts get-caller-identity
```

Use `--verbose` or `--debug` when diagnosing Okta or AWS behavior:

```sh
okta-awscli-rs --debug --okta-profile default --profile smoke-test sts get-caller-identity
```
