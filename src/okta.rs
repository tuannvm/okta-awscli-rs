use anyhow::{Result, anyhow, bail};
use base64::Engine;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::{Value, json};
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::OktaConfig;

#[derive(Clone, Debug)]
pub struct OktaAuth {
    client: Client,
    base_url: String,
    auth_url: String,
    okta_profile: String,
    factor: Option<String>,
    app_link: Option<String>,
    username: String,
    password: String,
    token: Option<String>,
    require_fastpass: bool,
}

#[derive(Debug, Deserialize)]
struct AuthnResponse {
    status: Option<String>,
    #[serde(rename = "stateToken")]
    state_token: Option<String>,
    #[serde(rename = "sessionToken")]
    session_token: Option<String>,
    #[serde(rename = "_embedded")]
    embedded: Option<Embedded>,
    #[serde(rename = "errorSummary")]
    error_summary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Embedded {
    factors: Option<Vec<Value>>,
}

#[derive(Clone, Debug, Deserialize)]
struct AppLink {
    #[serde(rename = "appName")]
    app_name: String,
    label: String,
    #[serde(rename = "linkUrl")]
    link_url: String,
    #[serde(rename = "sortOrder")]
    sort_order: i64,
}

impl OktaAuth {
    pub fn new(
        config: &OktaConfig,
        okta_profile: &str,
        username: String,
        password: String,
        token: Option<String>,
        require_fastpass: bool,
    ) -> Result<Self> {
        let configured_base = config.base_url_for(okta_profile)?;
        let base_url =
            if configured_base.starts_with("http://") || configured_base.starts_with("https://") {
                configured_base
            } else {
                format!("https://{configured_base}")
            };
        Ok(Self {
            client: Client::builder()
                .cookie_store(true)
                .user_agent(format!("okta-awscli-rs/{}", crate::VERSION))
                .build()?,
            auth_url: format!("{base_url}/api/v1/authn"),
            base_url,
            okta_profile: okta_profile.to_string(),
            factor: config.factor_for(okta_profile),
            app_link: config.app_link_for(okta_profile)?,
            username,
            password,
            token,
            require_fastpass,
        })
    }

    pub async fn get_assertion(
        &mut self,
        config: &mut OktaConfig,
    ) -> Result<(Option<String>, String)> {
        let session_token = self.primary_auth().await?;
        let session_id = self.get_session(&session_token).await?;
        let (app_name, app_link) = if let Some(link) = &self.app_link {
            (None, link.clone())
        } else {
            let selected = self.get_apps(&session_id).await?;
            config.write_applink_to_profile(&self.okta_profile, &selected.1)?;
            self.app_link = Some(selected.1.clone());
            (Some(selected.0), selected.1)
        };
        let sid_cookie = format!("sid={session_id}");
        let html = self
            .client
            .get(&app_link)
            .header("Cookie", sid_cookie)
            .send()
            .await?
            .text()
            .await?;
        Ok((app_name, self.get_saml_assertion(&html, &session_id).await?))
    }

    async fn primary_auth(&self) -> Result<String> {
        let resp = self
            .client
            .post(&self.auth_url)
            .json(&json!({
                "username": self.username,
                "password": self.password,
            }))
            .send()
            .await?;
        let status = resp.status();
        let body: AuthnResponse = resp.json().await?;
        match body.status.as_deref() {
            Some("SUCCESS") => body
                .session_token
                .ok_or_else(|| anyhow!("Okta SUCCESS response did not include sessionToken")),
            Some("MFA_REQUIRED") => {
                let factors = body.embedded.and_then(|e| e.factors).unwrap_or_default();
                let state_token = body.state_token.ok_or_else(|| {
                    anyhow!("Okta MFA_REQUIRED response did not include stateToken")
                })?;
                verify_base_mfa(
                    &self.client,
                    &state_token,
                    &factors,
                    self.factor.as_deref(),
                    self.token.as_deref(),
                    self.require_fastpass,
                )
                .await
            }
            Some("MFA_ENROLL") => {
                bail!("MFA not enrolled. Please enroll an MFA factor in the Okta Web UI first.")
            }
            Some("LOCKED_OUT") => bail!("Account is locked. Please contact your administrator."),
            Some(other) => bail!("Unsupported Okta authentication status: {other}"),
            None if !status.is_success() => bail!(
                "{}",
                body.error_summary
                    .unwrap_or_else(|| format!("Okta authentication failed with {status}"))
            ),
            None => bail!("Okta authentication failed: missing status"),
        }
    }

    async fn get_session(&self, session_token: &str) -> Result<String> {
        let value: Value = self
            .client
            .post(format!("{}/api/v1/sessions", self.base_url))
            .json(&json!({ "sessionToken": session_token }))
            .send()
            .await?
            .json()
            .await?;
        value["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("Okta session response did not include id"))
    }

    async fn get_apps(&self, session_id: &str) -> Result<(String, String)> {
        let sid = format!("sid={session_id}");
        let mut apps: Vec<AppLink> = self
            .client
            .get(format!("{}/api/v1/users/me/appLinks", self.base_url))
            .header("Cookie", sid)
            .send()
            .await?
            .json()
            .await?;
        apps.retain(|app| app.app_name == "amazon_aws");
        if apps.is_empty() {
            bail!("No AWS apps are available for your user.");
        }
        apps.sort_by_key(|app| app.sort_order);
        let selected = if apps.len() == 1 {
            0
        } else {
            println!("Available apps:");
            for (index, app) in apps.iter().enumerate() {
                println!("{}: {}", index + 1, app.label);
            }
            prompt_index("Please select AWS app", apps.len())?
        };
        Ok((
            apps[selected].label.clone(),
            apps[selected].link_url.clone(),
        ))
    }

    async fn get_saml_assertion(&self, html: &str, session_id: &str) -> Result<String> {
        if let Some(assertion) = simple_assertion(html) {
            return Ok(assertion);
        }
        self.get_mfa_assertion(html, session_id)
            .await?
            .ok_or_else(|| anyhow!("SAML assertion not valid"))
    }

    async fn get_mfa_assertion(&self, html: &str, session_id: &str) -> Result<Option<String>> {
        let document = Html::parse_document(html);
        let title_selector = Selector::parse("title").unwrap();
        let title = document
            .select(&title_selector)
            .next()
            .map(|node| node.text().collect::<String>())
            .unwrap_or_default();
        if !title.ends_with(" - Extra Verification") {
            return Ok(None);
        }
        let re = Regex::new(r#"var stateToken = '(.*)';"#)?;
        let state_token = re
            .captures(html)
            .and_then(|caps| caps.get(1))
            .map(|m| html_escape::decode_html_entities(m.as_str()).to_string())
            .ok_or_else(|| anyhow!("Extra Verification page did not include a stateToken"))?;
        let _ = stepup_auth(
            &self.client,
            &self.auth_url,
            &state_token,
            self.factor.as_deref(),
            self.token.as_deref(),
        )
        .await?;
        let app_link = self
            .app_link
            .as_ref()
            .ok_or_else(|| anyhow!("app-link required for app MFA assertion retry"))?;
        let retry = self
            .client
            .get(app_link)
            .header("Cookie", format!("sid={session_id}"))
            .send()
            .await?
            .text()
            .await?;
        Ok(simple_assertion(&retry))
    }
}

pub fn simple_assertion(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse(r#"input[name="SAMLResponse"]"#).ok()?;
    document
        .select(&selector)
        .next()
        .and_then(|node| node.value().attr("value"))
        .map(str::to_string)
}

async fn verify_base_mfa(
    client: &Client,
    state_token: &str,
    factors: &[Value],
    preferred_provider: Option<&str>,
    totp_token: Option<&str>,
    require_fastpass: bool,
) -> Result<String> {
    let mut supported: Vec<&Value> = factors
        .iter()
        .filter(|factor| {
            matches!(
                factor["factorType"].as_str(),
                Some("token:software:totp")
                    | Some("push")
                    | Some("u2f")
                    | Some("signed_nonce")
                    | Some("webauthn")
            )
        })
        .collect();
    supported.sort_by_key(|factor| {
        (
            factor["provider"].as_str().unwrap_or_default().to_string(),
            factor["factorType"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    });
    if supported.is_empty() {
        bail!("MFA required, but no supported factors enrolled.");
    }
    let preferred_provider = if require_fastpass {
        Some("OKTA_FASTPASS")
    } else {
        preferred_provider
    };
    let selected = choose_factor(
        &supported,
        preferred_provider,
        "Registered MFA factors:",
        build_base_factor_name,
    )?;
    if require_fastpass && !is_fastpass_factor(selected) {
        bail!(
            "Okta FastPass was requested, but Okta did not expose a FastPass factor in this authentication response. Available factors: {}",
            supported
                .iter()
                .map(|factor| build_base_factor_name(factor))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    verify_factor(client, state_token, selected, totp_token).await
}

async fn stepup_auth(
    client: &Client,
    auth_url: &str,
    state_token: &str,
    preferred_provider: Option<&str>,
    totp_token: Option<&str>,
) -> Result<Value> {
    let mut flow = client
        .post(auth_url)
        .json(&json!({ "stateToken": state_token }))
        .send()
        .await?
        .json::<Value>()
        .await?;
    let mut current_state = state_token.to_string();
    while flow["status"].as_str() != Some("SUCCESS") {
        match flow["status"].as_str() {
            Some("MFA_REQUIRED") => {
                let factors = flow["_embedded"]["factors"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let refs: Vec<&Value> = factors.iter().collect();
                let factor = choose_factor(
                    &refs,
                    preferred_provider,
                    "Multi-factor Authentication required for application.\nPick a factor:",
                    build_app_factor_name,
                )?;
                flow =
                    send_or_verify_app_factor(client, &current_state, factor, totp_token).await?;
            }
            Some("MFA_CHALLENGE") if flow["factorResult"].as_str() == Some("WAITING") => {
                sleep(Duration::from_secs(1)).await;
                let next = flow["_links"]["next"]["href"]
                    .as_str()
                    .ok_or_else(|| anyhow!("MFA challenge missing next link"))?;
                flow = client
                    .post(next)
                    .json(&json!({ "stateToken": current_state }))
                    .send()
                    .await?
                    .json()
                    .await?;
            }
            Some("MFA_CHALLENGE") => {
                let next = flow["_links"]["next"]["href"]
                    .as_str()
                    .ok_or_else(|| anyhow!("MFA challenge missing next link"))?;
                let pass_code = pass_code(totp_token)?;
                flow = client
                    .post(next)
                    .json(&json!({ "stateToken": current_state, "passCode": pass_code }))
                    .send()
                    .await?
                    .json()
                    .await?;
            }
            Some("UNAUTHENTICATED") => {
                bail!("You are not authenticated -- please try to log in again")
            }
            Some("LOCKED_OUT") => {
                bail!("Your Okta access has been locked out due to failed login attempts.")
            }
            Some("MFA_ENROLL") => bail!("You must enroll in MFA before using this tool."),
            Some(status) => bail!("Unknown login status: {status}"),
            None => bail!("Okta step-up response did not include status"),
        }
        if let Some(next_state) = flow["stateToken"].as_str() {
            current_state = next_state.to_string();
        }
    }
    Ok(flow)
}

async fn send_or_verify_app_factor(
    client: &Client,
    state_token: &str,
    factor: &Value,
    totp_token: Option<&str>,
) -> Result<Value> {
    let verify = factor["_links"]["verify"]["href"]
        .as_str()
        .ok_or_else(|| anyhow!("factor missing verify link"))?;
    if is_fastpass_factor(factor) {
        let flow: Value = client
            .post(verify)
            .json(&json!({ "stateToken": state_token }))
            .send()
            .await?
            .json()
            .await?;
        launch_fastpass_challenge(client, &flow).await?;
        return Ok(flow);
    }
    match factor["factorType"].as_str() {
        Some("sms") | Some("call") | Some("push") => Ok(client
            .post(verify)
            .json(&json!({ "stateToken": state_token }))
            .send()
            .await?
            .json()
            .await?),
        Some("token:software:totp") | Some("token") => {
            let pass_code = pass_code(totp_token)?;
            Ok(client
                .post(verify)
                .json(&json!({ "stateToken": state_token, "passCode": pass_code }))
                .send()
                .await?
                .json()
                .await?)
        }
        other => bail!("Unsupported app MFA factor: {:?}", other),
    }
}

async fn verify_factor(
    client: &Client,
    state_token: &str,
    factor: &Value,
    totp_token: Option<&str>,
) -> Result<String> {
    let verify = factor["_links"]["verify"]["href"]
        .as_str()
        .ok_or_else(|| anyhow!("factor missing verify link"))?;
    let mut req = json!({ "stateToken": state_token });
    if factor["factorType"].as_str() == Some("token:software:totp") {
        req["passCode"] = Value::String(pass_code(totp_token)?);
    }
    let mut resp: Value = client.post(verify).json(&req).send().await?.json().await?;
    let mut fastpass_launched = false;
    loop {
        match resp["status"].as_str() {
            Some("SUCCESS") => {
                return resp["sessionToken"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("MFA success response missing sessionToken"));
            }
            Some("MFA_CHALLENGE") if factor["factorType"].as_str() != Some("u2f") => {
                if is_fastpass_factor(factor) && !fastpass_launched {
                    fastpass_launched = launch_fastpass_challenge(client, &resp).await?;
                }
                if is_fastpass_factor(factor) {
                    println!("Waiting for Okta FastPass verification...");
                } else {
                    println!("Waiting for push verification...");
                }
                match resp["factorResult"].as_str() {
                    Some("TIMEOUT") => bail!("Verification timed out"),
                    Some("REJECTED") => bail!("Verification was rejected"),
                    _ => {}
                }
                if let Some(correct) =
                    resp["_embedded"]["factor"]["_embedded"]["challenge"]["correctAnswer"].as_str()
                {
                    println!("On your phone, tap {correct} in the Okta Verify app");
                }
                let next = resp["_links"]["next"]["href"]
                    .as_str()
                    .ok_or_else(|| anyhow!("MFA challenge missing next link"))?
                    .to_string();
                sleep(Duration::from_millis(500)).await;
                resp = client.post(next).json(&req).send().await?.json().await?;
            }
            Some("MFA_CHALLENGE") => {
                let challenge = crate::u2f::U2fChallenge {
                    app_id: resp["_embedded"]["factor"]["profile"]["appId"]
                        .as_str()
                        .ok_or_else(|| anyhow!("U2F challenge missing appId"))?
                        .to_string(),
                    key_handle: resp["_embedded"]["factor"]["profile"]["credentialId"]
                        .as_str()
                        .ok_or_else(|| anyhow!("U2F challenge missing credentialId"))?
                        .to_string(),
                    challenge: resp["_embedded"]["factor"]["_embedded"]["challenge"]["nonce"]
                        .as_str()
                        .ok_or_else(|| anyhow!("U2F challenge missing nonce"))?
                        .to_string(),
                };
                let auth_response = crate::u2f::authenticate(&challenge)?;
                let next = resp["_links"]["next"]["href"]
                    .as_str()
                    .ok_or_else(|| anyhow!("U2F challenge missing next link"))?;
                let mut u2f_req = req.clone();
                if let Some(map) = u2f_req.as_object_mut()
                    && let Some(auth_map) = auth_response.as_object()
                {
                    for (key, value) in auth_map {
                        map.insert(key.clone(), value.clone());
                    }
                }
                resp = client
                    .post(next)
                    .json(&u2f_req)
                    .send()
                    .await?
                    .json()
                    .await?;
            }
            Some("PASSWORD_EXPIRED") => bail!("Your Okta password is expired"),
            Some("MFA_REQUIRED") if is_fastpass_factor(factor) => {
                fastpass_launched = launch_fastpass_challenge(client, &resp).await?;
                let next = resp["_links"]["next"]["href"]
                    .as_str()
                    .ok_or_else(|| anyhow!("FastPass challenge missing next link"))?
                    .to_string();
                sleep(Duration::from_millis(500)).await;
                resp = client.post(next).json(&req).send().await?.json().await?;
            }
            other => bail!("MFA verification failed with status {:?}", other),
        }
    }
}

fn choose_factor<'a>(
    factors: &[&'a Value],
    preferred_provider: Option<&str>,
    heading: &str,
    name_fn: fn(&Value) -> String,
) -> Result<&'a Value> {
    if let Some(preference) = preferred_provider {
        let selected = factors
            .iter()
            .copied()
            .filter(|factor| factor_matches_preference(factor, preference))
            .min_by_key(|factor| factor_rank(factor))
            .ok_or_else(|| {
                if is_fastpass_preference(preference) {
                    anyhow!(
                        "Okta FastPass was requested, but Okta did not expose signed_nonce or WebAuthn factors in this Classic Authn response. Available factors: {}",
                        factors
                            .iter()
                            .map(|factor| build_base_factor_name(factor))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                } else {
                    anyhow!("Unable to locate selected factor preference {preference}")
                }
            })?;
        return Ok(selected);
    }
    if let Some(push) = single_push_factor(factors) {
        return Ok(push);
    }
    if factors.len() == 1 {
        return Ok(factors[0]);
    }
    println!("{heading}");
    for (index, factor) in factors.iter().enumerate() {
        println!("{}: {}", index + 1, name_fn(factor));
    }
    Ok(factors[prompt_index("Please select the MFA factor", factors.len())?])
}

fn build_base_factor_name(factor: &Value) -> String {
    match (factor["provider"].as_str(), factor["factorType"].as_str()) {
        (Some("GOOGLE"), _) => with_profile(factor, "Google Authenticator"),
        (Some("OKTA"), Some("push")) => with_profile(factor, "Okta Verify - Push"),
        (Some("OKTA"), Some("token:software:totp")) => with_profile(factor, "Okta Verify - TOTP"),
        (Some("OKTA"), Some("signed_nonce")) => with_profile(factor, "Okta FastPass"),
        (_, Some("webauthn")) => with_profile(factor, "WebAuthn platform authenticator"),
        (Some("OKTA"), Some(factor_type)) => {
            with_profile(factor, &format!("Okta Verify - {factor_type}"))
        }
        (Some("FIDO"), _) => with_profile(factor, "U2F security key"),
        (Some(provider), _) => format!("Unsupported factor type: {provider}"),
        _ => "Unknown MFA factor".to_string(),
    }
}

fn factor_matches_preference(factor: &Value, preference: &str) -> bool {
    let preference = preference.to_ascii_uppercase().replace('-', "_");
    let provider = factor["provider"].as_str().unwrap_or_default();
    let factor_type = factor["factorType"].as_str().unwrap_or_default();
    match preference.as_str() {
        "FASTPASS" | "OKTA_FASTPASS" | "SIGNED_NONCE" => is_fastpass_factor(factor),
        "PUSH" | "OKTA_PUSH" => provider == "OKTA" && factor_type == "push",
        "TOTP" | "OKTA_TOTP" => provider == "OKTA" && factor_type == "token:software:totp",
        "GOOGLE" | "GOOGLE_TOTP" => provider == "GOOGLE",
        "U2F" | "FIDO" => factor_type == "u2f" || provider == "FIDO",
        _ => provider == preference,
    }
}

fn is_fastpass_preference(preference: &str) -> bool {
    matches!(
        preference.to_ascii_uppercase().replace('-', "_").as_str(),
        "FASTPASS" | "OKTA_FASTPASS" | "SIGNED_NONCE"
    )
}

fn is_fastpass_factor(factor: &Value) -> bool {
    let provider = factor["provider"].as_str().unwrap_or_default();
    matches!(
        factor["factorType"].as_str(),
        Some("signed_nonce") | Some("webauthn")
    ) && (provider.is_empty() || provider == "OKTA" || provider == "FIDO")
}

fn single_push_factor<'a>(factors: &[&'a Value]) -> Option<&'a Value> {
    let mut push_factors = factors
        .iter()
        .copied()
        .filter(|factor| factor["factorType"].as_str() == Some("push"));
    let push = push_factors.next()?;
    if push_factors.next().is_none() {
        Some(push)
    } else {
        None
    }
}

fn factor_rank(factor: &Value) -> u8 {
    match factor["factorType"].as_str() {
        Some("signed_nonce") | Some("webauthn") => 0,
        Some("push") => 0,
        Some("u2f") => 1,
        Some("token:software:totp") => 2,
        _ => 3,
    }
}

fn with_profile(factor: &Value, label: &str) -> String {
    let profile = &factor["profile"];
    for key in ["name", "deviceType", "credentialId", "phoneNumber"] {
        if let Some(value) = profile[key].as_str()
            && !value.is_empty()
        {
            return format!("{label} ({value})");
        }
    }
    label.to_string()
}

fn build_app_factor_name(factor: &Value) -> String {
    match factor["factorType"].as_str() {
        Some("push") => format!(
            "Okta Verify App: {}: {}",
            factor["profile"]["deviceType"]
                .as_str()
                .unwrap_or("unknown"),
            factor["profile"]["name"].as_str().unwrap_or("unknown")
        ),
        Some("sms") | Some("call") => format!(
            "{}: {}",
            factor["factorType"].as_str().unwrap(),
            factor["profile"]["phoneNumber"]
                .as_str()
                .unwrap_or("unknown")
        ),
        Some("token:software:totp") => format!(
            "token:software:totp( {} ) : {}",
            factor["provider"].as_str().unwrap_or("unknown"),
            factor["profile"]["credentialId"]
                .as_str()
                .unwrap_or("unknown")
        ),
        Some("token") => format!(
            "token: {}",
            factor["profile"]["credentialId"]
                .as_str()
                .unwrap_or("unknown")
        ),
        Some("signed_nonce") => with_profile(factor, "Okta FastPass"),
        Some("webauthn") => with_profile(factor, "WebAuthn platform authenticator"),
        Some(other) => format!("Unknown MFA type: {other}"),
        None => "Unknown MFA type".to_string(),
    }
}

async fn launch_fastpass_challenge(client: &Client, response: &Value) -> Result<bool> {
    let challenge = find_device_challenge(response).ok_or_else(|| {
        anyhow!(
            "Okta FastPass was selected, but Okta did not return a launchable device challenge. Run again with --debug and file the redacted MFA_CHALLENGE shape."
        )
    })?;
    let method = challenge["challengeMethod"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_uppercase();
    match method.as_str() {
        "LOOPBACK" => launch_loopback_challenge(client, challenge).await?,
        "CUSTOM_URI" | "UNIVERSAL_LINK" | "APP_LINK" | "CHROME_DTC" => {
            let href = challenge["href"]
                .as_str()
                .ok_or_else(|| anyhow!("FastPass {method} challenge did not include href"))?;
            open_url(href)?;
        }
        "" => {
            if let Some(href) = challenge["href"].as_str() {
                open_url(href)?;
            } else {
                bail!("FastPass challenge did not include challengeMethod or href");
            }
        }
        other => bail!("Unsupported FastPass challenge method: {other}"),
    }
    Ok(true)
}

fn find_device_challenge(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(map) => {
            let has_method = map.contains_key("challengeMethod");
            let has_launch = map.contains_key("href") || map.contains_key("challengeRequest");
            if has_method && has_launch {
                return Some(value);
            }
            for child in map.values() {
                if let Some(found) = find_device_challenge(child) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(find_device_challenge),
        _ => None,
    }
}

async fn launch_loopback_challenge(client: &Client, challenge: &Value) -> Result<()> {
    let challenge_request = challenge["challengeRequest"]
        .as_str()
        .ok_or_else(|| anyhow!("FastPass loopback challenge did not include challengeRequest"))?;
    let ports = challenge["ports"]
        .as_array()
        .ok_or_else(|| anyhow!("FastPass loopback challenge did not include ports"))?;
    let mut bases = Vec::new();
    if let Some(https_domain) = challenge["httpsDomain"].as_str() {
        bases.push(https_domain);
    }
    if let Some(domain) = challenge["domain"].as_str() {
        bases.push(domain);
    }
    if bases.is_empty() {
        bail!("FastPass loopback challenge did not include a domain");
    }

    for base in bases {
        for port in ports {
            let Some(port) = port.as_u64() else {
                continue;
            };
            let probe = format!("{base}:{port}/probe");
            if client
                .get(&probe)
                .timeout(Duration::from_millis(750))
                .send()
                .await
                .is_err()
            {
                continue;
            }
            let challenge_url = format!("{base}:{port}/challenge");
            let result = client
                .post(&challenge_url)
                .timeout(Duration::from_secs(300))
                .json(&json!({ "challengeRequest": challenge_request }))
                .send()
                .await;
            match result {
                Ok(resp) if resp.status().is_success() => {
                    println!("Opened Okta FastPass challenge through local Okta Verify.");
                    return Ok(());
                }
                Ok(resp) if resp.status().as_u16() == 503 => continue,
                Ok(resp) => bail!(
                    "Okta Verify rejected the FastPass challenge with {}",
                    resp.status()
                ),
                Err(_) => continue,
            }
        }
    }
    bail!("Unable to contact local Okta Verify for the FastPass loopback challenge")
}

fn open_url(href: &str) -> Result<()> {
    println!("Opening Okta Verify for FastPass...");
    let status = Command::new("open").arg(href).status()?;
    if status.success() {
        Ok(())
    } else {
        bail!("failed to open Okta Verify challenge URL")
    }
}

fn pass_code(totp_token: Option<&str>) -> Result<String> {
    Ok(match totp_token {
        Some(token) => token.to_string(),
        None => dialoguer::Input::new()
            .with_prompt("Enter MFA verification code")
            .interact_text()?,
    })
}

fn prompt_index(prompt: &str, len: usize) -> Result<usize> {
    let selection: usize = dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()?;
    if selection == 0 || selection > len {
        bail!("Invalid selection");
    }
    Ok(selection - 1)
}

pub fn decode_roles_from_assertion(assertion: &str) -> Result<Vec<(String, String)>> {
    let xml = base64::engine::general_purpose::STANDARD.decode(assertion)?;
    crate::aws::extract_available_roles_from_xml(&xml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_saml_response_input() {
        let html = r#"<html><input name="SAMLResponse" value="abc123"></html>"#;
        assert_eq!(simple_assertion(html).as_deref(), Some("abc123"));
    }

    #[test]
    fn okta_preference_picks_push_before_totp() {
        let totp = json!({
            "provider": "OKTA",
            "factorType": "token:software:totp",
            "profile": { "credentialId": "user@example.com" }
        });
        let push = json!({
            "provider": "OKTA",
            "factorType": "push",
            "profile": { "name": "iPhone" }
        });
        let factors = vec![&totp, &push];
        let selected = choose_factor(
            &factors,
            Some("OKTA"),
            "Registered MFA factors:",
            build_base_factor_name,
        )
        .unwrap();
        assert_eq!(selected["factorType"].as_str(), Some("push"));
    }

    #[test]
    fn factor_name_includes_type_and_profile() {
        let factor = json!({
            "provider": "OKTA",
            "factorType": "token:software:totp",
            "profile": { "credentialId": "user@example.com" }
        });
        assert_eq!(
            build_base_factor_name(&factor),
            "Okta Verify - TOTP (user@example.com)"
        );
    }

    #[test]
    fn fastpass_preference_picks_signed_nonce() {
        let push = json!({
            "provider": "OKTA",
            "factorType": "push",
            "profile": { "name": "phone" }
        });
        let fastpass = json!({
            "provider": "OKTA",
            "factorType": "signed_nonce",
            "profile": { "name": "MacBook" }
        });
        let factors = vec![&push, &fastpass];
        let selected = choose_factor(
            &factors,
            Some("OKTA_FASTPASS"),
            "Registered MFA factors:",
            build_base_factor_name,
        )
        .unwrap();
        assert_eq!(selected["factorType"].as_str(), Some("signed_nonce"));
        assert_eq!(build_base_factor_name(selected), "Okta FastPass (MacBook)");
    }

    #[test]
    fn fastpass_preference_reports_available_classic_factors() {
        let totp = json!({
            "provider": "OKTA",
            "factorType": "token:software:totp",
            "profile": { "credentialId": "user@example.com" }
        });
        let factors = vec![&totp];
        let err = choose_factor(
            &factors,
            Some("OKTA_FASTPASS"),
            "Registered MFA factors:",
            build_base_factor_name,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Okta FastPass was requested"));
        assert!(err.to_string().contains("Okta Verify - TOTP"));
    }

    #[test]
    fn finds_nested_device_challenge() {
        let response = json!({
            "status": "MFA_CHALLENGE",
            "_embedded": {
                "factor": {
                    "_embedded": {
                        "challenge": {
                            "challengeMethod": "APP_LINK",
                            "href": "okta-verify://challenge"
                        }
                    }
                }
            }
        });
        let challenge = find_device_challenge(&response).unwrap();
        assert_eq!(challenge["challengeMethod"].as_str(), Some("APP_LINK"));
    }
}
