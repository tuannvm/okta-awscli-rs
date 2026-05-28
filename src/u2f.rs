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
use std::sync::mpsc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct U2fChallenge {
    pub app_id: String,
    pub key_handle: String,
    pub challenge: String,
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

fn decode_b64(input: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .with_context(|| "decoding U2F key handle")
}
