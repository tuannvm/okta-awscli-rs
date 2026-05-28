use anyhow::{Context, Result, anyhow, bail};
const SERVICE: &str = "okta-awscli-rs";

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
    let account = account(okta_profile, username);
    let output = std::process::Command::new("/usr/bin/security")
        .args(["find-generic-password", "-w", "-s", SERVICE, "-a", &account])
        .output()
        .context("running security find-generic-password")?;
    if output.status.success() {
        Ok(Some(
            String::from_utf8(output.stdout)?
                .trim_end_matches('\n')
                .to_string(),
        ))
    } else if output.status.code() == Some(44) {
        Ok(None)
    } else {
        Err(anyhow!(
            "{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn macos_keychain_set(okta_profile: &str, username: &str, password: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("Touch ID password storage is only supported on macOS");
    }
    let account = account(okta_profile, username);
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            SERVICE,
            "-a",
            &account,
            "-l",
            &format!("Okta AWS CLI password for {account}"),
            "-w",
            password,
        ])
        .output()
        .context("running security add-generic-password")?;
    if output.status.success() {
        println!(
            "Stored Okta password in macOS Keychain. Use --touch-id to unlock it on future runs."
        );
        Ok(())
    } else {
        Err(anyhow!(
            "{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
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
