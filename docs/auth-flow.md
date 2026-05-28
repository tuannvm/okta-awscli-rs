# Authentication Flow

The implementation follows the Python tool's Classic Okta Authn plus AWS SAML design.

`--browser-capture` is a separate browser-assisted path for environments where FastPass is only available in the browser. In that mode, the CLI launches an isolated Chrome/Chromium-family browser session, opens the configured Okta AWS app link, captures the AWS SAML POST through DevTools, and then resumes at AWS STS role exchange.

`--browser-paste` is the manual fallback. It opens the configured app link and accepts a pasted `SAMLResponse`.

## High-Level Flow

1. Read `~/.okta-aws`.
2. Collect username and password from flags, config, prompt, or Touch ID-assisted Keychain lookup.
3. POST primary credentials to Okta Authn:

   ```text
   POST https://<base-url>/api/v1/authn
   ```

4. Complete tenant-level MFA when Okta returns `MFA_REQUIRED`.
5. Create an Okta session:

   ```text
   POST https://<base-url>/api/v1/sessions
   ```

6. Use the `sid` session cookie to open the AWS app link.
7. If no app link is configured, discover AWS apps:

   ```text
   GET https://<base-url>/api/v1/users/me/appLinks
   ```

8. Extract the hidden `SAMLResponse` input from the AWS app page.
9. If the app page requires extra verification, complete app-level MFA and retry with the same `sid`.
10. Parse AWS role/principal ARN pairs from the SAML assertion.
11. Call AWS STS `AssumeRoleWithSAML`.
12. Write credentials or print shell exports.

## MFA Support

Tenant-level MFA:

- TOTP from Okta Verify or Google Authenticator.
- Okta Verify push, including challenge number display when Okta returns one.
- U2F security key challenge.

Application-level MFA:

- Push.
- SMS.
- Call.
- TOTP/passCode.

## U2F

U2F support uses the Mozilla `authenticator` crate with CTAP1 fallback enabled. It builds a U2F `clientData` payload from the Okta challenge, asks the user to touch the device, and sends the authenticator response back to Okta.

Okta FastPass is represented separately from U2F and TOTP. When `--okta-fastpass` is set, the CLI requires Okta to expose a `signed_nonce` or WebAuthn factor and will not silently fall back to a verification-code prompt. Completing the full FastPass device challenge requires Okta's IDX/browser challenge exchange, so Classic Authn-only tenants should use Okta Verify push instead.

## AWS Role Selection

AWS roles are extracted from this SAML attribute:

```text
https://aws.amazon.com/SAML/Attributes/Role
```

Values can appear in either order:

```text
role_arn,principal_arn
principal_arn,role_arn
```

The implementation normalizes them before role selection.

## AWS Partitions

The STS region is selected from the ARN partition:

- `arn:aws:...` uses standard STS config.
- `arn:aws-us-gov:...` uses `us-gov-west-1`.

IAM alias lookup follows the same partition distinction.

## Okta Library Choice

The current Rust `okta` crate is a generated Okta Management API client. This tool needs Classic Authn endpoints, Okta session creation, appLinks, and HTML SAML extraction, so the implementation uses `reqwest` directly with typed JSON parsing around the specific Okta APIs it needs.
