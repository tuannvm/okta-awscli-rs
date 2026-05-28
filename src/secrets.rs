use anyhow::{Context, Result, anyhow, bail};
const SERVICE: &str = "okta-awscli-rs";
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub fn password(
    config_password: Option<String>,
    okta_profile: &str,
    username: &str,
    touch_id: bool,
    store_touch_id: bool,
) -> Result<String> {
    if touch_id && let Some(secret) = macos_keychain_get(okta_profile, username)? {
        return Ok(secret);
    }
    if let Some(password) = config_password {
        if store_touch_id {
            macos_keychain_set(okta_profile, username, &password)?;
        }
        return Ok(password);
    }
    let password = rpassword::prompt_password("Enter password: ")?;
    if store_touch_id {
        macos_keychain_set(okta_profile, username, &password)?;
    }
    Ok(password)
}

pub fn macos_keychain_get(okta_profile: &str, username: &str) -> Result<Option<String>> {
    if !cfg!(target_os = "macos") {
        bail!("Touch ID password unlock is only supported on macOS");
    }
    require_local_auth(okta_profile)?;
    macos_keychain_get_impl(okta_profile, username)
}

#[cfg(target_os = "macos")]
fn macos_keychain_get_impl(okta_profile: &str, username: &str) -> Result<Option<String>> {
    use security_framework::os::macos::keychain::SecKeychain;

    let account = account(okta_profile, username);
    let keychain = SecKeychain::default().context("opening default macOS Keychain")?;
    match keychain.find_generic_password(SERVICE, &account) {
        Ok((password, _)) => {
            let value = String::from_utf8(password.as_ref().to_vec())
                .context("decoding macOS Keychain password as UTF-8")?;
            Ok(Some(value))
        }
        Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        Err(err) => Err(anyhow!("macOS Keychain lookup failed: {err}")),
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_keychain_get_impl(_okta_profile: &str, _username: &str) -> Result<Option<String>> {
    bail!("Touch ID password unlock is only supported on macOS")
}

pub fn macos_keychain_set(okta_profile: &str, username: &str, password: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("Touch ID password storage is only supported on macOS");
    }
    macos_keychain_set_impl(okta_profile, username, password)?;
    println!("Stored Okta password in macOS Keychain. Use --touch-id to unlock it on future runs.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_keychain_set_impl(okta_profile: &str, username: &str, password: &str) -> Result<()> {
    use security_framework::os::macos::keychain::SecKeychain;

    let account = account(okta_profile, username);
    let keychain = SecKeychain::default().context("opening default macOS Keychain")?;
    keychain
        .set_generic_password(SERVICE, &account, password.as_bytes())
        .map_err(|err| anyhow!("macOS Keychain update failed: {err}"))
}

#[cfg(not(target_os = "macos"))]
fn macos_keychain_set_impl(_okta_profile: &str, _username: &str, _password: &str) -> Result<()> {
    bail!("Touch ID password storage is only supported on macOS")
}

fn require_local_auth(okta_profile: &str) -> Result<()> {
    let script = format!(
        r#"import Foundation
import LocalAuthentication

let context = LAContext()
var error: NSError?
guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {{
    FileHandle.standardError.write(Data("Touch ID is not available or not enrolled\n".utf8))
    exit(2)
}}

let semaphore = DispatchSemaphore(value: 0)
var success = false
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock Okta password for profile {okta_profile}") {{ ok, _ in
    success = ok
    semaphore.signal()
}}
_ = semaphore.wait(timeout: .now() + 60)
exit(success ? 0 : 1)
"#,
    );
    let status = std::process::Command::new("/usr/bin/swift")
        .arg("-e")
        .arg(script)
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => bail!("Touch ID authentication failed"),
        Err(err) => bail!("could not invoke Touch ID authentication: {err}"),
    }
}

fn account(okta_profile: &str, username: &str) -> String {
    format!("{okta_profile}:{username}")
}
