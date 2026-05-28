# Development

## Crate Layout

| Path | Responsibility |
| --- | --- |
| `src/cli.rs` | Clap arguments, logging, top-level command orchestration. |
| `src/config.rs` | `~/.okta-aws` parsing, profile fallback, interactive config creation. |
| `src/okta.rs` | Okta Authn, sessions, appLinks, MFA, and SAML extraction. |
| `src/aws.rs` | SAML role parsing, AWS STS/IAM calls, credential file writes, AWS CLI passthrough. |
| `src/secrets.rs` | Password prompting and local macOS user verification for experimental WebAuthn Keychain. |
| `src/u2f.rs` | U2F security key authentication. |
| `tests/e2e_mock.rs` | Mock Okta-to-AWS flow tests. |
| `tests/cli.rs` | CLI parsing tests. |

## Dependency Choices

- `reqwest`: direct Okta Authn/session/appLinks calls.
- `aws-sdk-sts` and `aws-sdk-iam`: official AWS SDK clients.
- `scraper`: extracting `SAMLResponse` from the AWS app HTML.
- `quick-xml`: parsing SAML role attributes.
- `authenticator`: CTAP/U2F support.
- `clap`: CLI parsing.
- `wiremock`: deterministic E2E tests.

## Error Handling

The code uses `anyhow::Result` at application boundaries. User-facing failures should include the external system and the missing/invalid field when possible, for example:

```text
Okta session response did not include id
U2F challenge missing nonce
No AWS roles were found in the SAML assertion
```

## Compatibility Notes

The original Python tool exits for many errors. The Rust implementation returns errors through `anyhow`, letting the top-level runtime print the failure.

The config parser is intentionally small and targets the INI subset used by `~/.okta-aws` and AWS credentials files. Avoid broadening it unless a real config compatibility issue appears.

## Verification Before Changes Land

Run the common targets:

```sh
make lint
make build
make test
```

The targets use `CARGO_HOME=$PWD/.cargo-home` by default so dependency downloads stay inside the workspace. The underlying commands are:

```sh
CARGO_HOME=$PWD/.cargo-home cargo fmt --check
CARGO_HOME=$PWD/.cargo-home cargo check --all-targets
CARGO_HOME=$PWD/.cargo-home cargo clippy --all-targets -- -D warnings
CARGO_HOME=$PWD/.cargo-home cargo test
```

When changing CLI parsing, also run:

```sh
CARGO_HOME=$PWD/.cargo-home cargo run --quiet -- --help
```
