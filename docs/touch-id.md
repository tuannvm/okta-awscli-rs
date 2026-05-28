# macOS Touch ID

Touch ID support is designed to avoid putting an Okta password in plaintext `~/.okta-aws`.

## Store The Password

```sh
okta-awscli-rs --store-touch-id --username user@example.com
```

The tool obtains the password from `--password`, config, or an interactive password prompt, then stores it as a generic password in macOS Keychain.

The Keychain account name is:

```text
<okta-profile>:<username>
```

The Keychain service is:

```text
okta-awscli-rs
```

## Use Touch ID

```sh
okta-awscli-rs --touch-id --username user@example.com --profile prod-admin
```

Before reading the Keychain item, the tool runs a LocalAuthentication biometric check through `/usr/bin/swift`. If Touch ID is not available, not enrolled, or rejected, the command fails instead of reading the stored password.

## Browser FastPass

Okta FastPass is not the same feature as `--touch-id`.

- `--touch-id` verifies the local macOS user before this CLI reads an Okta password from Keychain.
- `--browser` opens an isolated browser session so Okta can use FastPass, Touch ID, or another browser-registered authenticator.

Use browser capture mode like this:

```sh
okta-awscli-rs --okta-profile default --profile prod-admin --browser
```

Built-in macOS Touch ID/passkeys for Okta require a browser-associated or signed-app flow. A plain terminal process cannot claim the web relying party identity directly, so this tool uses the browser for FastPass and captures only the AWS SAML response needed for STS.

## Experimental WebAuthn Keychain

`--webauthn-keychain` is a separate experimental path for Okta Classic Authn `webauthn` factors. It uses a macOS Keychain-backed virtual authenticator compatible with `ctap-keyring-device` credentials, then prompts for local user verification before signing the challenge.

Use it only when the Okta WebAuthn credential was enrolled through that compatible virtual authenticator model. Existing browser or iCloud Keychain passkeys are not exportable into this path; use `--browser` for those.

If Okta returns a non-32-byte credential id, the credential is not compatible with this experimental path.

### Enroll A Compatible Credential

When Okta offers WebAuthn enrollment through the Classic Authn API, this helper can generate the WebAuthn credential locally and activate it with Okta:

```sh
okta-awscli-rs --okta-profile default --username user@example.com --webauthn-keychain-enroll
```

The helper creates a P-256 ES256 signing key, builds a WebAuthn packed attestation response, sends the activation response to Okta, and stores the encrypted private key in macOS Keychain only after Okta accepts the enrollment. The Keychain service is `<okta-domain>-webauthn`; the account is the generated credential's user UUID in lowercase hex.

This does not enroll or import your existing browser/iCloud Keychain passkey. If Okta requires MFA before adding a new factor, or if your org only exposes Security Methods enrollment in the browser, use the browser enrollment UI or `--browser` for AWS SAML authentication.

## Limitations

The current implementation is an application-level Touch ID gate before this binary reads the Keychain item. The Keychain item itself is not created with a per-item biometric access-control policy.

Practical impact:

- `okta-awscli-rs --touch-id` requires Touch ID before it reads the password.
- `okta-awscli-rs --browser` uses the browser for Okta FastPass/fingerprint authentication and then writes AWS credentials.
- `okta-awscli-rs --webauthn-keychain` tries a Keychain-backed WebAuthn assertion for compatible CLI-enrolled credentials.
- `okta-awscli-rs --webauthn-keychain-enroll` creates one of those compatible credentials only when Okta exposes Classic Authn WebAuthn enrollment.
- Built-in macOS Touch ID/passkeys for Okta require a browser-associated flow, not a bare terminal process.
- Other processes with permission to read the same Keychain item are governed by normal Keychain access controls, not this tool's Touch ID check.

## Removing The Stored Password

```sh
security delete-generic-password -s okta-awscli-rs -a default:user@example.com
```

Replace `default:user@example.com` with `<okta-profile>:<username>`.

## Recommended Setup

Avoid this:

```ini
[default]
password = plaintext-password
```

Prefer:

```sh
okta-awscli-rs --store-touch-id --username user@example.com
okta-awscli-rs --touch-id --username user@example.com --profile prod-admin
```
