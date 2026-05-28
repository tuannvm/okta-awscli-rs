# Getting Started

This guide assumes you already have an Okta account with access to one or more AWS apps and the AWS CLI installed locally.

## Build The Binary

```sh
cargo build --release
```

The binary is available at:

```sh
./target/release/okta-awscli-rs
```

For development builds:

```sh
cargo build
./target/debug/okta-awscli-rs --help
```

## Create A Profile

Run the interactive config helper:

```sh
okta-awscli-rs --config
```

It writes `~/.okta-aws` and asks for:

- Okta profile name, such as `default` or `prod`.
- AWS profile name, such as `prod-admin`.
- Okta base URL, such as `example.okta.com`.
- Okta username.
- Optional AWS app link.
- Requested STS duration.

## First Login

Write credentials into an AWS profile:

```sh
okta-awscli-rs --okta-profile default --profile prod-admin
```

If your SAML assertion contains multiple AWS roles, select one from the prompt. The selected role is saved back into the Okta profile as `role`.

## Run AWS Commands

Any positional arguments after the options are passed to the AWS CLI:

```sh
okta-awscli-rs --profile prod-admin sts get-caller-identity
okta-awscli-rs --profile prod-admin s3 ls
```

The command run is equivalent to:

```sh
aws --profile prod-admin sts get-caller-identity
```

## Force A Refresh

The tool checks whether existing STS credentials are valid. Force a new Okta login and STS token:

```sh
okta-awscli-rs --profile prod-admin --force
```

Refresh role selection even when a role is saved:

```sh
okta-awscli-rs --profile prod-admin --refresh-role
```

## Browser-Assisted FastPass

If FastPass works in your browser but not through terminal MFA, use browser capture mode:

```sh
okta-awscli-rs --okta-profile default --profile prod-admin --force --browser
```

The profile must have an `app-link`. The CLI launches an isolated Chrome/Chromium-family browser session, opens that link, watches for the AWS SAML POST, captures `SAMLResponse`, and then assumes the AWS role normally.

Manual paste mode remains available when automatic capture is not possible:

```sh
okta-awscli-rs --okta-profile default --profile prod-admin --force --browser-paste
```

## Experimental WebAuthn Keychain

If your Okta tenant exposes a Classic Authn WebAuthn factor and the credential was enrolled through a `ctap-keyring-device` compatible virtual authenticator, try:

```sh
okta-awscli-rs --okta-profile default --profile prod-admin --force --webauthn-keychain
```

For normal browser or iCloud Keychain passkeys, use `--browser` instead.

## Use Multiple Okta Profiles

Select a profile explicitly:

```sh
okta-awscli-rs --okta-profile prod --profile prod-admin
```

Choose from configured profiles interactively:

```sh
okta-awscli-rs --switch
```

## Output Environment Exports

If no AWS profile is configured or passed, credentials are printed as shell exports instead of written to `~/.aws/credentials`:

```sh
okta-awscli-rs --okta-profile prod
```

Cache that output in `~/.okta-credentials.cache`:

```sh
okta-awscli-rs --okta-profile prod --cache
```
