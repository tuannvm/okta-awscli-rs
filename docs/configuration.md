# Configuration

`okta-awscli-rs` intentionally keeps the Python `okta-awscli` config format.

## Okta Config Path

The config file is:

```text
~/.okta-aws
```

Each INI section is an Okta profile:

```ini
[default]
base-url = example.okta.com
username = user@example.com
factor = OKTA
profile = prod-admin
duration = 3600
```

## Fields

| Field | Required | Description |
| --- | --- | --- |
| `base-url` | Yes | Okta org host, such as `example.okta.com`. Tests may use a full `http://` URL for mock servers. |
| `username` | No | Okta username. If omitted, the tool prompts. |
| `password` | No | Okta password. If omitted, the tool prompts or reads from Keychain with `--touch-id`. |
| `factor` | No | Preferred MFA provider. Supported values include `OKTA`, `OKTA_PUSH`, `OKTA_TOTP`, `GOOGLE`, and `U2F`. |
| `profile` | No | AWS profile to write credentials into. Overridden by `--profile`. |
| `app-link` | No | Direct Okta AWS app link. If omitted, the tool discovers AWS apps through Okta appLinks. |
| `role` | No | AWS role ARN to assume. If omitted or invalid for the assertion, the tool prompts. |
| `duration` | No | Requested STS duration in seconds. Defaults to `3600` when absent or invalid. |

## Default Fallbacks

Some values fall back to the `[default]` section when the selected profile does not define them:

- `base-url`
- `username`
- `password`
- `factor`
- `app-link`
- `duration`

Profile-specific `role` and `profile` are not inherited.

## AWS Credentials Path

By default, credentials are written to:

```text
~/.aws/credentials
```

If `AWS_SHARED_CREDENTIALS_FILE` is set, that file is used instead.

Written keys:

```ini
[prod-admin]
aws_access_key_id = ...
aws_secret_access_key = ...
aws_session_expiration = ...
aws_session_token = ...
```

When writing a non-`default` profile, the tool also copies that profile into `[default]`, matching the Python tool's behavior.

## Example Profiles

Multiple Okta tenants:

```ini
[default]
base-url = example.okta.com
username = user@example.com
profile = sandbox

[prod]
base-url = example.okta.com
username = user@example.com
profile = prod-admin
factor = OKTA
duration = 3600
```

Preselected role:

```ini
[prod]
base-url = example.okta.com
username = user@example.com
profile = prod-admin
role = arn:aws:iam::123456789012:role/Admin
```

Direct app link:

```ini
[prod]
base-url = example.okta.com
username = user@example.com
app-link = https://example.okta.com/home/amazon_aws/...
profile = prod-admin
```
