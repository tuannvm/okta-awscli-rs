use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::aws::{AwsAuth, AwsSdkProvider, StsProvider};
use crate::config::{OktaConfig, configure_interactive};
use crate::okta::OktaAuth;

#[derive(Debug, Parser)]
#[command(name = "okta-awscli", bin_name = "okta-awscli", version = crate::VERSION)]
pub struct Args {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short = 'd', long)]
    debug: bool,
    #[arg(short = 'f', long)]
    force: bool,
    #[arg(short = 'o', long, default_value = "default")]
    okta_profile: String,
    #[arg(short = 'p', long)]
    profile: Option<String>,
    #[arg(short = 'c', long)]
    cache: bool,
    #[arg(short = 'r', long)]
    refresh_role: bool,
    #[arg(short = 't', long)]
    token: Option<String>,
    #[arg(short = 'l', long)]
    lookup: bool,
    #[arg(short = 'U', long = "username")]
    okta_username: Option<String>,
    #[arg(short = 'P', long = "password")]
    okta_password: Option<String>,
    #[arg(long)]
    config: bool,
    #[arg(short = 's', long = "switch")]
    switch_profile: bool,
    #[arg(
        long,
        help = "Unlock the Okta password from macOS Keychain after Touch ID verification"
    )]
    touch_id: bool,
    #[arg(
        long,
        help = "Store the Okta password in macOS Keychain for future --touch-id runs"
    )]
    store_touch_id: bool,
    #[arg(
        long,
        help = "Require Okta FastPass / signed-nonce MFA when Okta exposes it"
    )]
    okta_fastpass: bool,
    #[arg(
        long,
        help = "Open the configured Okta AWS app in a browser and prompt for a pasted SAMLResponse"
    )]
    browser_paste: bool,
    #[arg(
        long,
        help = "Launch an isolated Chrome session, authenticate in the browser, and capture SAMLResponse automatically"
    )]
    browser_capture: bool,
    #[arg(num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
    awscli_args: Vec<String>,
}

pub async fn run() -> Result<()> {
    let args = Args::parse();
    init_logging(args.debug, args.verbose);
    let config_path = OktaConfig::default_path()?;
    if args.config {
        configure_interactive(&config_path)?;
        return Ok(());
    }
    let mut config = OktaConfig::load(config_path)?;
    let okta_profile = if args.switch_profile {
        choose_okta_profile(&config)?
    } else {
        args.okta_profile.clone()
    };
    if args.browser_paste && args.browser_capture {
        bail!("Use only one of --browser-paste or --browser-capture");
    }
    let browser_mode = args.browser_paste || args.browser_capture;
    let username = if browser_mode {
        None
    } else {
        Some(
            args.okta_username
                .clone()
                .map(Ok)
                .unwrap_or_else(|| config.username_for(&okta_profile))?,
        )
    };
    let password = if let Some(username) = &username {
        Some(crate::secrets::password(
            args.okta_password
                .clone()
                .or(config.password_for(&okta_profile)?),
            &okta_profile,
            username,
            args.touch_id,
            args.store_touch_id,
        )?)
    } else {
        None
    };
    if args.touch_id && !args.okta_fastpass && !browser_mode {
        eprintln!(
            "Note: --touch-id only unlocks the local Keychain password. Use --okta-fastpass to require an Okta FastPass factor."
        );
    }

    let aws_auth = AwsAuth::new(
        args.profile.clone(),
        okta_profile.clone(),
        args.lookup,
        config.role_for(&okta_profile),
        config.aws_profile_for(&okta_profile),
    )?;
    let provider = AwsSdkProvider;
    if args.force || !aws_auth.check_sts_token(&provider).await? {
        if args.force && aws_auth.profile.is_some() {
            log::info!("Force option selected, getting new credentials anyway.");
        }
        let request = CredentialRequest {
            okta_profile: &okta_profile,
            username,
            password,
            token: args.token.clone(),
            cache: args.cache,
            refresh_role: args.refresh_role,
            okta_fastpass: args.okta_fastpass,
            browser_paste: args.browser_paste,
            browser_capture: args.browser_capture,
        };
        get_credentials(&mut config, &aws_auth, &provider, request).await?;
    }
    if !args.awscli_args.is_empty() {
        let code = aws_auth.execute_aws_args(&args.awscli_args)?;
        if code != 0 {
            std::process::exit(code);
        }
    }
    Ok(())
}

struct CredentialRequest<'a> {
    okta_profile: &'a str,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    cache: bool,
    refresh_role: bool,
    okta_fastpass: bool,
    browser_paste: bool,
    browser_capture: bool,
}

async fn get_credentials<P: StsProvider + Sync>(
    config: &mut OktaConfig,
    aws_auth: &AwsAuth,
    provider: &P,
    request: CredentialRequest<'_>,
) -> Result<()> {
    let assertion = if request.browser_capture {
        browser_capture_assertion(config, request.okta_profile).await?
    } else if request.browser_paste {
        browser_paste_assertion(config, request.okta_profile)?
    } else {
        let mut okta = OktaAuth::new(
            config,
            request.okta_profile,
            request
                .username
                .ok_or_else(|| anyhow!("username missing for Okta authentication"))?,
            request
                .password
                .ok_or_else(|| anyhow!("password missing for Okta authentication"))?,
            request.token,
            request.okta_fastpass,
        )?;
        okta.get_assertion(config).await?.1
    };
    let role = aws_auth
        .choose_aws_role(&assertion, request.refresh_role, provider)
        .await?;
    config.write_role_to_profile(request.okta_profile, &role.role_arn)?;
    let duration = config.duration_for(request.okta_profile).unwrap_or(3600);
    let sts_token = provider
        .assume_role_with_saml(&role, &assertion, duration)
        .await?;
    log::info!("Session token expires on: {}", sts_token.expiration);
    if aws_auth.profile.is_none() {
        let exports = console_output(
            &sts_token.access_key_id,
            &sts_token.secret_access_key,
            &sts_token.session_token,
        );
        if request.cache {
            let cache_path = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("could not locate home directory"))?
                .join(".okta-credentials.cache");
            std::fs::write(cache_path, &exports)?;
        }
        println!("{exports}");
    } else {
        aws_auth.write_sts_token(&sts_token)?;
    }
    Ok(())
}

async fn browser_capture_assertion(config: &OktaConfig, okta_profile: &str) -> Result<String> {
    let app_link = config.app_link_for(okta_profile)?.ok_or_else(|| {
        anyhow!(
            "--browser-capture requires app-link in ~/.okta-aws. Run the normal flow once to discover it, or set app-link manually."
        )
    })?;
    let chrome = chrome_path()?;
    let profile_dir = browser_capture_profile_dir()?;
    fs::create_dir_all(&profile_dir)?;
    let mut child = Command::new(&chrome)
        .arg("--remote-debugging-port=0")
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--new-window")
        .arg("about:blank")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting Chrome at {}", chrome.display()))?;
    let result = capture_saml_with_chrome(&profile_dir, &app_link).await;
    shutdown_browser(&mut child);
    let _ = fs::remove_dir_all(&profile_dir);
    result
}

fn chrome_path() -> Result<PathBuf> {
    let candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }
    for name in [
        "google-chrome",
        "chromium",
        "chromium-browser",
        "brave-browser",
    ] {
        if let Ok(output) = Command::new("which").arg(name).output()
            && output.status.success()
        {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }
    bail!("--browser-capture requires Chrome, Chromium, Brave, or Edge")
}

fn browser_capture_profile_dir() -> Result<PathBuf> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    Ok(std::env::temp_dir().join(format!(
        "okta-awscli-rs-chrome-{}-{now}",
        std::process::id()
    )))
}

async fn capture_saml_with_chrome(profile_dir: &Path, app_link: &str) -> Result<String> {
    let port = wait_for_devtools_port(profile_dir).await?;
    let client = reqwest::Client::new();
    let page_ws = wait_for_page_websocket(&client, port).await?;
    let (mut socket, _) =
        tungstenite::connect(&page_ws).context("connecting to Chrome DevTools")?;
    cdp_send(&mut socket, 1, "Page.enable", serde_json::json!({}))?;
    cdp_send(
        &mut socket,
        2,
        "Network.enable",
        serde_json::json!({ "maxPostDataSize": 10485760 }),
    )?;
    cdp_send(
        &mut socket,
        3,
        "Page.navigate",
        serde_json::json!({ "url": app_link }),
    )?;
    eprintln!("Opened isolated Chrome session. Complete FastPass in that browser window.");
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    while std::time::Instant::now() < deadline {
        let msg = socket.read().context("reading Chrome DevTools event")?;
        let tungstenite::Message::Text(text) = msg else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_str(&text)?;
        if value["method"].as_str() != Some("Network.requestWillBeSent") {
            continue;
        }
        let request = &value["params"]["request"];
        let url = request["url"].as_str().unwrap_or_default();
        let method = request["method"].as_str().unwrap_or_default();
        if method == "POST"
            && (url.contains("signin.aws.amazon.com/saml") || url.contains("amazon.com/saml"))
            && let Some(post_data) = request["postData"].as_str()
            && let Ok(assertion) = parse_pasted_saml_response(post_data)
        {
            eprintln!("Captured SAMLResponse from browser.");
            return Ok(assertion);
        }
    }
    bail!("timed out waiting for browser SAMLResponse")
}

async fn wait_for_devtools_port(profile_dir: &Path) -> Result<u16> {
    let active_port = profile_dir.join("DevToolsActivePort");
    for _ in 0..100 {
        if let Ok(contents) = fs::read_to_string(&active_port)
            && let Some(line) = contents.lines().next()
            && let Ok(port) = line.parse::<u16>()
        {
            return Ok(port);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("Chrome did not expose a DevTools port")
}

async fn wait_for_page_websocket(client: &reqwest::Client, port: u16) -> Result<String> {
    let list_url = format!("http://127.0.0.1:{port}/json/list");
    for _ in 0..100 {
        if let Ok(resp) = client.get(&list_url).send().await
            && let Ok(pages) = resp.json::<Vec<serde_json::Value>>().await
        {
            for page in pages {
                if page["type"].as_str() == Some("page")
                    && let Some(ws) = page["webSocketDebuggerUrl"].as_str()
                {
                    return Ok(ws.to_string());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("Chrome did not expose a debuggable page")
}

fn cdp_send(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    id: u64,
    method: &str,
    params: serde_json::Value,
) -> Result<()> {
    socket.send(tungstenite::Message::Text(
        serde_json::json!({ "id": id, "method": method, "params": params })
            .to_string()
            .into(),
    ))?;
    Ok(())
}

fn shutdown_browser(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn browser_paste_assertion(config: &OktaConfig, okta_profile: &str) -> Result<String> {
    let app_link = config.app_link_for(okta_profile)?.ok_or_else(|| {
        anyhow!(
            "--browser-paste requires app-link in ~/.okta-aws. Run the normal flow once to discover it, or set app-link manually."
        )
    })?;
    open_browser(&app_link)?;
    eprintln!("Opened Okta AWS app link in your browser.");
    eprintln!(
        "Authenticate with FastPass, capture the SAMLResponse, paste it below, and press Enter."
    );
    let pasted: String = dialoguer::Input::new()
        .with_prompt("SAMLResponse")
        .interact_text()?;
    parse_pasted_saml_response(&pasted)
}

fn open_browser(url: &str) -> Result<()> {
    let status = if cfg!(target_os = "macos") {
        Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "start", "", url]).status()
    } else {
        Command::new("xdg-open").arg(url).status()
    }
    .context("opening browser")?;
    if status.success() {
        Ok(())
    } else {
        bail!("failed to open browser for Okta app link")
    }
}

fn parse_pasted_saml_response(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("SAMLResponse cannot be empty");
    }
    if let Some(assertion) = crate::okta::simple_assertion(trimmed) {
        return Ok(assertion);
    }
    if trimmed.contains("SAMLResponse=") {
        let query = trimmed.split_once('?').map(|(_, q)| q).unwrap_or(trimmed);
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if key == "SAMLResponse" {
                return Ok(value.into_owned());
            }
        }
    }
    Ok(trimmed.to_string())
}

pub fn console_output(access_key_id: &str, secret_access_key: &str, session_token: &str) -> String {
    format!(
        "export AWS_ACCESS_KEY_ID={access_key_id}\nexport AWS_SECRET_ACCESS_KEY={secret_access_key}\nexport AWS_SESSION_TOKEN={session_token}"
    )
}

fn choose_okta_profile(config: &OktaConfig) -> Result<String> {
    let profiles = config.profiles();
    if profiles.is_empty() {
        bail!("No Okta profiles are configured");
    }
    if profiles.len() == 1 {
        return Ok(profiles[0].clone());
    }
    println!("Available Okta profiles:");
    for (index, profile) in profiles.iter().enumerate() {
        println!("{}: {}", index + 1, profile);
    }
    let selection: usize = dialoguer::Input::new()
        .with_prompt("Please select Okta profile")
        .interact_text()?;
    if selection == 0 || selection > profiles.len() {
        bail!("Invalid Okta profile selection");
    }
    Ok(profiles[selection - 1].clone())
}

fn init_logging(debug: bool, verbose: bool) {
    let default = if debug {
        "debug"
    } else if verbose {
        "info"
    } else {
        "warn"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default))
        .format_timestamp(None)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_exports_match_python_contract() {
        assert_eq!(
            console_output("ak", "sk", "tok"),
            "export AWS_ACCESS_KEY_ID=ak\nexport AWS_SECRET_ACCESS_KEY=sk\nexport AWS_SESSION_TOKEN=tok"
        );
    }

    #[test]
    fn parses_raw_pasted_saml_response() {
        assert_eq!(
            parse_pasted_saml_response(" abc123 ").unwrap(),
            "abc123".to_string()
        );
    }

    #[test]
    fn parses_html_pasted_saml_response() {
        assert_eq!(
            parse_pasted_saml_response(r#"<input name="SAMLResponse" value="abc123">"#).unwrap(),
            "abc123".to_string()
        );
    }

    #[test]
    fn parses_form_encoded_pasted_saml_response() {
        assert_eq!(
            parse_pasted_saml_response("RelayState=x&SAMLResponse=abc%2B123%3D").unwrap(),
            "abc+123=".to_string()
        );
    }
}
