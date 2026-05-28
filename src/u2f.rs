use anyhow::{Context, Result, anyhow, bail};
use authenticator::authenticatorservice::{AuthenticatorService, SignArgs};
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor, Transport,
    UserVerificationRequirement,
};
use authenticator::statecallback::StateCallback;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct U2fChallenge {
    pub app_id: String,
    pub key_handle: String,
    pub challenge: String,
}

#[derive(Clone, Debug)]
pub struct WebAuthnChallenge {
    pub origin: String,
    pub relying_party_id: String,
    pub credential_id: String,
    pub challenge: String,
    pub user_verification: String,
}

pub fn authenticate(challenge: &U2fChallenge) -> Result<serde_json::Value> {
    let client_data = json!({
        "typ": "navigator.id.getAssertion",
        "challenge": challenge.challenge,
        "origin": challenge.app_id,
    })
    .to_string();
    let client_data_hash: [u8; 32] = Sha256::digest(client_data.as_bytes()).into();
    let key_handle = decode_b64(&challenge.key_handle)?;

    let args = SignArgs {
        client_data_hash,
        origin: challenge.app_id.clone(),
        relying_party_id: challenge.app_id.clone(),
        allow_list: vec![PublicKeyCredentialDescriptor {
            id: key_handle.clone(),
            transports: vec![Transport::USB, Transport::NFC, Transport::BLE],
        }],
        user_verification_req: UserVerificationRequirement::Discouraged,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: true,
    };

    let mut service = AuthenticatorService::new().map_err(|err| anyhow!("{err}"))?;
    service.add_detected_transports();
    let (status_tx, _status_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let callback = StateCallback::new(Box::new(move |result| {
        let _ = result_tx.send(result);
    }));
    println!("Please touch your U2F device...");
    service
        .sign(60_000, args, status_tx, callback)
        .map_err(|err| anyhow!("{err}"))?;
    let result = result_rx
        .recv_timeout(Duration::from_secs(65))
        .context("timed out waiting for U2F device")?
        .map_err(|err| anyhow!("{err}"))?;
    let auth_data = result.assertion.auth_data.to_vec();
    if auth_data.len() < 37 {
        bail!("U2F authenticator returned malformed auth data");
    }
    let mut signature_data = auth_data[32..37].to_vec();
    signature_data.extend_from_slice(&result.assertion.signature);
    Ok(json!({
        "clientData": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
        "signatureData": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_data),
        "keyHandle": challenge.key_handle,
    }))
}

pub fn authenticate_webauthn(challenge: &WebAuthnChallenge) -> Result<serde_json::Value> {
    #[cfg(target_os = "macos")]
    match authenticate_webauthn_macos(challenge) {
        Ok(value) => return Ok(value),
        Err(err) => {
            if std::env::var_os("OKTA_AWSCLI_ALLOW_EXTERNAL_FIDO_FALLBACK").is_none() {
                return Err(err.context(
                    "macOS platform WebAuthn failed; set OKTA_AWSCLI_ALLOW_EXTERNAL_FIDO_FALLBACK=1 to try an external FIDO authenticator",
                ));
            }
            log::debug!("macOS platform WebAuthn failed: {err:#}");
        }
    }

    let client_data = json!({
        "type": "webauthn.get",
        "challenge": challenge.challenge,
        "origin": challenge.origin,
        "crossOrigin": false,
    })
    .to_string();
    let client_data_hash: [u8; 32] = Sha256::digest(client_data.as_bytes()).into();
    let credential_id = decode_b64(&challenge.credential_id)?;
    let user_verification_req = match challenge.user_verification.to_ascii_lowercase().as_str() {
        "required" => UserVerificationRequirement::Required,
        "discouraged" => UserVerificationRequirement::Discouraged,
        _ => UserVerificationRequirement::Preferred,
    };

    let args = SignArgs {
        client_data_hash,
        origin: challenge.origin.clone(),
        relying_party_id: challenge.relying_party_id.clone(),
        allow_list: vec![PublicKeyCredentialDescriptor {
            id: credential_id,
            transports: vec![
                Transport::USB,
                Transport::NFC,
                Transport::BLE,
                Transport::Internal,
            ],
        }],
        user_verification_req,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let mut service = AuthenticatorService::new().map_err(|err| anyhow!("{err}"))?;
    service.add_detected_transports();
    let (status_tx, _status_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let callback = StateCallback::new(Box::new(move |result| {
        let _ = result_tx.send(result);
    }));
    println!("Please approve the WebAuthn security key or platform authenticator prompt...");
    service
        .sign(60_000, args, status_tx, callback)
        .map_err(|err| anyhow!("{err}"))?;
    let result = result_rx
        .recv_timeout(Duration::from_secs(65))
        .context("timed out waiting for WebAuthn authenticator")?
        .map_err(|err| anyhow!("{err}"))?;
    Ok(json!({
        "clientData": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
        "authenticatorData": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result.assertion.auth_data.to_vec()),
        "signatureData": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result.assertion.signature),
        "credentialId": challenge.credential_id,
    }))
}

#[cfg(target_os = "macos")]
fn authenticate_webauthn_macos(challenge: &WebAuthnChallenge) -> Result<serde_json::Value> {
    let script = r#"
import AppKit
import AuthenticationServices
import Foundation

func decodeBase64Url(_ input: String) -> Data? {
    var value = input.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    let padding = (4 - value.count % 4) % 4
    if padding > 0 {
        value += String(repeating: "=", count: padding)
    }
    return Data(base64Encoded: value)
}

func encodeBase64Url(_ data: Data) -> String {
    return data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

final class AuthorizationDelegate: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    let window: NSWindow
    var output: String?
    var completed = false

    init(window: NSWindow) {
        self.window = window
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return window
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            output = "{\"error\":\"unexpected credential type\"}"
            completed = true
            return
        }
        let payload: [String: String] = [
            "clientData": encodeBase64Url(assertion.rawClientDataJSON),
            "authenticatorData": encodeBase64Url(assertion.rawAuthenticatorData),
            "signatureData": encodeBase64Url(assertion.signature),
            "credentialId": encodeBase64Url(assertion.credentialID)
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: []),
           let json = String(data: data, encoding: .utf8) {
            output = json
        } else {
            output = "{\"error\":\"failed to serialize assertion\"}"
        }
        completed = true
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        let payload = ["error": error.localizedDescription]
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: []),
           let json = String(data: data, encoding: .utf8) {
            output = json
        } else {
            output = "{\"error\":\"authorization failed\"}"
        }
        completed = true
    }
}

if CommandLine.arguments.count != 6 {
    fputs("{\"error\":\"usage: rp_id origin challenge credential_id user_verification\"}\n", stderr)
    exit(2)
}

let rpId = CommandLine.arguments[1]
let challengeB64 = CommandLine.arguments[3]
let credentialB64 = CommandLine.arguments[4]
let userVerification = CommandLine.arguments[5]

guard let challenge = decodeBase64Url(challengeB64), let credentialID = decodeBase64Url(credentialB64) else {
    fputs("{\"error\":\"invalid base64url challenge or credential\"}\n", stderr)
    exit(2)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1, height: 1), styleMask: [], backing: .buffered, defer: false)
let delegate = AuthorizationDelegate(window: window)
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
let request = provider.createCredentialAssertionRequest(challenge: challenge)
request.allowedCredentials = [ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialID)]
switch userVerification.lowercased() {
case "required":
    request.userVerificationPreference = .required
case "discouraged":
    request.userVerificationPreference = .discouraged
default:
    request.userVerificationPreference = .preferred
}

let controller = ASAuthorizationController(authorizationRequests: [request])
controller.delegate = delegate
controller.presentationContextProvider = delegate
controller.performRequests()

let deadline = Date().addingTimeInterval(65)
while !delegate.completed && Date() < deadline {
    RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
}

if !delegate.completed {
    fputs("{\"error\":\"timed out waiting for macOS WebAuthn prompt\"}\n", stderr)
    exit(1)
}

if let output = delegate.output {
    print(output)
    if output.contains("\"error\"") {
        exit(1)
    }
    exit(0)
}
fputs("{\"error\":\"no assertion returned\"}\n", stderr)
exit(1)
"#;

    let mut child = Command::new("/usr/bin/swift")
        .arg("-")
        .arg(&challenge.relying_party_id)
        .arg(&challenge.origin)
        .arg(&challenge.challenge)
        .arg(&challenge.credential_id)
        .arg(&challenge.user_verification)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting macOS WebAuthn helper")?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("macOS WebAuthn helper stdin unavailable"))?
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "macOS WebAuthn helper failed: {}{}",
            stderr.trim(),
            stdout.trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("decoding macOS WebAuthn output")?;
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).context("parsing macOS WebAuthn output")?;
    if let Some(error) = value["error"].as_str() {
        bail!("macOS WebAuthn helper failed: {error}");
    }
    Ok(value)
}

fn decode_b64(input: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .with_context(|| "decoding U2F key handle")
}
