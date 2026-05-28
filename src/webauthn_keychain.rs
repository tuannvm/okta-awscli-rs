use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CTAP_KEYRING_ES256_ALG: i16 = -7;
const CTAP_KEYRING_AAGUID: &[u8; 16] = b"pasten-ctap-1337";

#[derive(Clone)]
pub struct WebAuthnChallenge {
    pub origin: String,
    pub relying_party_id: String,
    pub credential_id: String,
    pub challenge: String,
    pub user_verification: String,
}

pub struct WebAuthnCreationOptions {
    pub origin: String,
    pub relying_party_id: String,
    pub user_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub challenge: String,
}

pub struct PendingCredential {
    relying_party_id: String,
    account: String,
    encoded_key: Zeroizing<String>,
}

pub struct CreatedCredential {
    pub response: serde_json::Value,
    pub pending: PendingCredential,
    pub credential_id: String,
}

pub fn create_credential(options: &WebAuthnCreationOptions) -> Result<CreatedCredential> {
    if !cfg!(target_os = "macos") {
        bail!("--webauthn-keychain-enroll is only supported on macOS");
    }

    let mut rng = OsRng;
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = encoded_point
        .x()
        .ok_or_else(|| anyhow!("generated P-256 key did not expose an x coordinate"))?;
    let y = encoded_point
        .y()
        .ok_or_else(|| anyhow!("generated P-256 key did not expose a y coordinate"))?;

    let mut key_password = [0_u8; 16];
    rng.fill_bytes(&mut key_password);
    let user_uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, options.user_id.as_bytes());
    let mut credential_id = Vec::with_capacity(32);
    credential_id.extend_from_slice(user_uuid.as_bytes());
    credential_id.extend_from_slice(&key_password);

    let encrypted_key = signing_key
        .to_pkcs8_encrypted_der(&mut rng, key_password)
        .context("encrypting generated WebAuthn private key")?;
    let mut key_record = Vec::with_capacity(2 + encrypted_key.as_bytes().len());
    key_record.extend_from_slice(&CTAP_KEYRING_ES256_ALG.to_be_bytes());
    key_record.extend_from_slice(encrypted_key.as_bytes());

    let client_data_json = json!({
        "type": "webauthn.create",
        "challenge": options.challenge,
        "origin": options.origin,
        "crossOrigin": false,
    })
    .to_string();
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();
    let authenticator_data =
        attestation_authenticator_data(&options.relying_party_id, &credential_id, x, y);
    let signature: Signature =
        signing_key.sign(&[authenticator_data.as_slice(), &client_data_hash].concat());
    let attestation_object =
        packed_attestation_object(&authenticator_data, signature.to_der().as_bytes());

    let credential_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_id);
    let pending = PendingCredential {
        relying_party_id: options.relying_party_id.clone(),
        account: hex_lower(user_uuid.as_bytes()),
        encoded_key: Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&key_record)),
    };

    key_password.zeroize();
    key_record.zeroize();
    credential_id.zeroize();

    Ok(CreatedCredential {
        response: json!({
            "credentialId": credential_id_b64,
            "clientData": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data_json.as_bytes()),
            "attestation": base64::engine::general_purpose::STANDARD.encode(&attestation_object),
            "attestationObject": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&attestation_object),
            "type": "public-key",
        }),
        pending,
        credential_id: credential_id_b64,
    })
}

pub fn store_credential(pending: PendingCredential) -> Result<()> {
    keychain_set(
        &pending.relying_party_id,
        &pending.account,
        pending.encoded_key.as_str(),
    )
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

fn attestation_authenticator_data(
    rp_id: &str,
    credential_id: &[u8],
    x: &[u8],
    y: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + 16 + 2 + credential_id.len() + 77);
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(0x45);
    let counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or_default();
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(CTAP_KEYRING_AAGUID);
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(credential_id);
    cbor_map(&mut out, 5);
    cbor_int(&mut out, 1);
    cbor_int(&mut out, 2);
    cbor_int(&mut out, 3);
    cbor_int(&mut out, CTAP_KEYRING_ES256_ALG as i64);
    cbor_int(&mut out, -1);
    cbor_int(&mut out, 1);
    cbor_int(&mut out, -2);
    cbor_bytes(&mut out, x);
    cbor_int(&mut out, -3);
    cbor_bytes(&mut out, y);
    out
}

fn packed_attestation_object(authenticator_data: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_map(&mut out, 3);
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "packed");
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, authenticator_data);
    cbor_text(&mut out, "attStmt");
    cbor_map(&mut out, 2);
    cbor_text(&mut out, "alg");
    cbor_int(&mut out, CTAP_KEYRING_ES256_ALG as i64);
    cbor_text(&mut out, "sig");
    cbor_bytes(&mut out, signature);
    out
}

fn cbor_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        cbor_type_len(out, 0, value as u64);
    } else {
        cbor_type_len(out, 1, (-1 - value) as u64);
    }
}

fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    cbor_type_len(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

fn cbor_text(out: &mut Vec<u8>, value: &str) {
    cbor_type_len(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn cbor_map(out: &mut Vec<u8>, len: u64) {
    cbor_type_len(out, 5, len);
}

fn cbor_type_len(out: &mut Vec<u8>, major: u8, len: u64) {
    let prefix = major << 5;
    match len {
        0..=23 => out.push(prefix | len as u8),
        24..=0xff => out.extend_from_slice(&[prefix | 24, len as u8]),
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
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

#[cfg(target_os = "macos")]
fn keychain_set(rp_id: &str, username: &str, encoded_key: &str) -> Result<()> {
    use security_framework::os::macos::keychain::SecKeychain;

    let service = format!("{rp_id}-webauthn");
    let keychain = SecKeychain::default().context("opening default macOS Keychain")?;
    keychain
        .set_generic_password(&service, username, encoded_key.as_bytes())
        .map_err(|err| anyhow!("macOS Keychain WebAuthn update failed: {err}"))
}

#[cfg(not(target_os = "macos"))]
fn keychain_set(_rp_id: &str, _username: &str, _encoded_key: &str) -> Result<()> {
    bail!("--webauthn-keychain-enroll is only supported on macOS")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_encodes_negative_es256_alg() {
        let mut out = Vec::new();
        cbor_int(&mut out, -7);
        assert_eq!(out, vec![0x26]);
    }

    #[test]
    fn ctap_keyring_credential_id_is_user_uuid_plus_password() {
        let user_uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, b"jane@example.com");
        let mut credential_id = Vec::new();
        credential_id.extend_from_slice(user_uuid.as_bytes());
        credential_id.extend_from_slice(&[7_u8; 16]);
        assert_eq!(credential_id.len(), 32);
        assert_eq!(&credential_id[..16], user_uuid.as_bytes());
    }
}
