use anyhow::{Result, bail};
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub fn password(config_password: Option<String>, _username: &str) -> Result<String> {
    if let Some(password) = config_password {
        return Ok(password);
    }
    rpassword::prompt_password("Enter password: ").map_err(Into::into)
}

pub fn verify_local_user(reason: &str, allow_password: bool) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("Local user verification is only supported on macOS");
    }
    let reason = serde_json::to_string(reason)?;
    let policy = if allow_password {
        "LAPolicy.deviceOwnerAuthentication"
    } else {
        "LAPolicy.deviceOwnerAuthenticationWithBiometrics"
    };
    let script = format!(
        r#"import Foundation
import LocalAuthentication

let context = LAContext()
var error: NSError?
let policy = {policy}
guard context.canEvaluatePolicy(policy, error: &error) else {{
    FileHandle.standardError.write(Data("Local user verification is not available\n".utf8))
    exit(2)
}}

let semaphore = DispatchSemaphore(value: 0)
var success = false
context.evaluatePolicy(policy, localizedReason: {reason}) {{ ok, _ in
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
        Ok(_) => bail!("Local user verification failed"),
        Err(err) => bail!("could not invoke local user verification: {err}"),
    }
}
