# Troubleshooting

## No Profile Found

Error:

```text
No profile found. Please define a default profile, or specify a named profile using --okta-profile
```

Fix:

```sh
okta-awscli-rs --config
```

Or create `~/.okta-aws` with at least:

```ini
[default]
base-url = example.okta.com
```

## App Link Missing

When `app-link` is missing, the tool discovers AWS apps from Okta. If no AWS apps are available, ask your Okta administrator to confirm the AWS app is assigned to your user.

You can also configure the app link explicitly:

```ini
[default]
app-link = https://example.okta.com/home/amazon_aws/...
```

## Invalid Or Expired AWS Credentials

Force a refresh:

```sh
okta-awscli-rs --profile prod-admin --force
```

Refresh role selection:

```sh
okta-awscli-rs --profile prod-admin --refresh-role
```

## Role Alias Lookup Fails

`--lookup` tries to call `iam:ListAccountAliases` for each role. If a role cannot perform alias lookup, the tool logs a warning and falls back to showing the raw role ARN.

If you need aliases everywhere, attach permission for:

```text
iam:ListAccountAliases
```

## Touch ID Is Not Available

Touch ID requires macOS, enrolled biometrics, and `/usr/bin/swift` so the tool can run LocalAuthentication.

Fallback options:

- Omit `--touch-id` and enter the password interactively.
- Pass `--password` for automation, understanding the shell-history risk.
- Store `password` in `~/.okta-aws` only if that is acceptable for your environment.

## U2F Device Not Detected

Check that the security key is connected and available to the OS. The tool waits for the U2F callback and times out if the device does not respond.

For Okta tenants that offer multiple factors, using `factor = OKTA` with Okta Verify push is often easier for terminal workflows.

## Cargo Cache Permission Errors

Use a repo-local Cargo cache:

```sh
CARGO_HOME=$PWD/.cargo-home cargo test
```
