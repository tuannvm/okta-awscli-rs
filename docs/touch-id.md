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

## Limitations

The current implementation is an application-level Touch ID gate before this binary reads the Keychain item. The Keychain item itself is not created with a per-item biometric access-control policy.

Practical impact:

- `okta-awscli-rs --touch-id` requires Touch ID before it reads the password.
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
