use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const CTAP_KEYRING_ES256_ALG: i16 = -7;

#[derive(Clone)]
pub struct WebAuthnChallenge {
    pub origin: String,
    pub relying_party_id: String,
    pub credential_id: String,
    pub challenge: String,
    pub user_verification: String,
}

pub fn authenticate(challenge: &WebAuthnChallenge) -> Result<serde_json::Value> {
    if !cfg!(target_os = "macos") {
        bail!("--webauthn-keychain is only supported on macOS");
    }

    let client_data_json = json!({
        "type": "webauthn.get",
        "challenge": challenge.challenge,
        "origin": challenge.origin,
        "crossOrigin": false,
    })
    .to_string();
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();
    let credential_id = Zeroizing::new(decode_base64url(&challenge.credential_id)?);
    if credential_id.len() != 32 {
        bail!(
            "This Okta WebAuthn credential is not compatible with --webauthn-keychain. The experimental Keychain authenticator can only use ctap-keyring-device-style 32-byte credential ids; Okta returned a {}-byte credential id. Use --browser for existing browser, iCloud Keychain, or FastPass credentials.",
            credential_id.len()
        );
    }

    let mut user_uuid = [0_u8; 16];
    user_uuid.copy_from_slice(&credential_id[..16]);
    let mut key_password = [0_u8; 16];
    key_password.copy_from_slice(&credential_id[16..]);

    let encoded_key = keychain_get(&challenge.relying_party_id, &hex_lower(&user_uuid))?
        .ok_or_else(|| {
            anyhow!(
                "No compatible macOS Keychain WebAuthn credential was found for relying party {}. Use --browser for existing browser, iCloud Keychain, or FastPass credentials.",
                challenge.relying_party_id
            )
        })?;
    let decoded_key = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded_key.as_bytes())
            .context("decoding Keychain WebAuthn credential")?,
    );
    if decoded_key.len() < 3 {
        bail!("Keychain WebAuthn credential is malformed");
    }

    let alg = i16::from_be_bytes([decoded_key[0], decoded_key[1]]);
    if alg != CTAP_KEYRING_ES256_ALG {
        bail!("Unsupported Keychain WebAuthn COSE algorithm {alg}; only ES256 is supported");
    }

    let signing_key = SigningKey::from_pkcs8_encrypted_der(&decoded_key[2..], key_password)
        .context("decrypting Keychain WebAuthn private key")?;

    verify_local_user(challenge)?;

    let authenticator_data = authenticator_data(&challenge.relying_party_id);
    let signature: Signature =
        signing_key.sign(&[authenticator_data.as_slice(), &client_data_hash].concat());
    let signature_der = signature.to_der();

    key_password.zeroize();
    user_uuid.zeroize();

    Ok(json!({
        "authenticatorData": base64::engine::general_purpose::STANDARD.encode(&authenticator_data),
        "clientData": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data_json.as_bytes()),
        "signatureData": base64::engine::general_purpose::STANDARD.encode(signature_der.as_bytes()),
    }))
}

fn verify_local_user(challenge: &WebAuthnChallenge) -> Result<()> {
    let reason = format!(
        "Verify WebAuthn identity for {}",
        challenge.relying_party_id
    );
    let allow_password = !challenge
        .user_verification
        .eq_ignore_ascii_case("discouraged");
    crate::secrets::verify_local_user(&reason, allow_password)
}

fn authenticator_data(rp_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(0x05);
    let counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or_default();
    out.extend_from_slice(&counter.to_be_bytes());
    out
}

#[cfg(target_os = "macos")]
fn keychain_get(rp_id: &str, username: &str) -> Result<Option<String>> {
    use security_framework::os::macos::keychain::SecKeychain;

    let service = format!("{rp_id}-webauthn");
    let keychain = SecKeychain::default().context("opening default macOS Keychain")?;
    match keychain.find_generic_password(&service, username) {
        Ok((password, _)) => {
            let value = String::from_utf8(password.as_ref().to_vec())
                .context("decoding WebAuthn Keychain item as UTF-8")?;
            Ok(Some(value))
        }
        Err(err) if err.code() == crate::secrets::ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        Err(err) => Err(anyhow!("macOS Keychain WebAuthn lookup failed: {err}")),
    }
}

#[cfg(not(target_os = "macos"))]
fn keychain_get(_rp_id: &str, _username: &str) -> Result<Option<String>> {
    bail!("--webauthn-keychain is only supported on macOS")
}

fn decode_base64url(input: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .context("decoding WebAuthn credential id")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
