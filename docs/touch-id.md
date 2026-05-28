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

## Limitations

The current implementation is an application-level Touch ID gate before this binary reads the Keychain item. The Keychain item itself is not created with a per-item biometric access-control policy.

Practical impact:

- `okta-awscli-rs --touch-id` requires Touch ID before it reads the password.
- `okta-awscli-rs --browser` uses the browser for Okta FastPass/fingerprint authentication and then writes AWS credentials.
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
