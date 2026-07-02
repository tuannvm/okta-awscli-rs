use anyhow::{Result, anyhow, bail};
use base64::Engine;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::sleep;
use zeroize::Zeroize;

use crate::config::OktaConfig;

#[derive(Clone)]
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
    webauthn_keychain: bool,
}

impl Drop for OktaAuth {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(token) = &mut self.token {
            token.zeroize();
        }
    }
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
        webauthn_keychain: bool,
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
            webauthn_keychain,
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

    pub async fn enroll_webauthn_keychain(&self) -> Result<()> {
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
        let mut flow: Value = resp.json().await?;
        flow = self.continue_to_enrollment(flow, status).await?;
        self.enroll_webauthn_from_flow(&flow).await
    }

    async fn continue_to_enrollment(
        &self,
        flow: Value,
        http_status: reqwest::StatusCode,
    ) -> Result<Value> {
        match flow["status"].as_str() {
            Some("MFA_ENROLL") => Ok(flow),
            Some("MFA_REQUIRED") => {
                let factors = flow["_embedded"]["factors"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let state_token = flow["stateToken"].as_str().ok_or_else(|| {
                    anyhow!("Okta MFA_REQUIRED response did not include stateToken")
                })?;
                let after_mfa = verify_base_mfa_response(
                    &self.client,
                    state_token,
                    &factors,
                    self.factor.as_deref(),
                    self.token.as_deref(),
                    false,
                    &self.base_url,
                )
                .await?;
                match after_mfa["status"].as_str() {
                    Some("MFA_ENROLL") => Ok(after_mfa),
                    Some("SUCCESS") => bail!(
                        "Okta accepted MFA but did not offer WebAuthn enrollment through Classic Authn. Use the Okta Security Methods page for enrollment, or use --browser for FastPass-backed AWS SAML."
                    ),
                    Some(other) => bail!("Unsupported post-MFA enrollment status: {other}"),
                    None => bail!("Okta post-MFA response did not include status"),
                }
            }
            Some("SUCCESS") => bail!(
                "Okta signed in without offering factor enrollment. Use the Okta Security Methods page to add another WebAuthn authenticator, or ask an administrator to require/allow WebAuthn enrollment."
            ),
            Some(other) => bail!("Unsupported Okta enrollment status: {other}"),
            None if !http_status.is_success() => bail!(
                "{}",
                flow["errorSummary"]
                    .as_str()
                    .unwrap_or("Okta authentication failed")
            ),
            None => bail!("Okta authentication failed: missing status"),
        }
    }

    async fn enroll_webauthn_from_flow(&self, flow: &Value) -> Result<()> {
        let state_token = flow["stateToken"]
            .as_str()
            .ok_or_else(|| anyhow!("Okta MFA_ENROLL response did not include stateToken"))?;
        let factor = flow["_embedded"]["factors"]
            .as_array()
            .and_then(|factors| {
                factors
                    .iter()
                    .find(|factor| factor["factorType"].as_str() == Some("webauthn"))
            })
            .ok_or_else(|| anyhow!("Okta did not offer a WebAuthn enrollment factor"))?;
        let enroll = factor["_links"]["enroll"]["href"]
            .as_str()
            .ok_or_else(|| anyhow!("WebAuthn enrollment factor missing enroll link"))?;

        let activation: Value = self
            .client
            .post(enroll)
            .json(&json!({ "stateToken": state_token }))
            .send()
            .await?
            .json()
            .await?;
        let creation = webauthn_creation_options(&activation, &self.base_url, &self.username)?;
        let created = crate::webauthn_keychain::create_credential(&creation)?;
        let next = activation["_links"]["next"]["href"]
            .as_str()
            .or_else(|| activation["_links"]["activate"]["href"].as_str())
            .ok_or_else(|| anyhow!("WebAuthn enrollment activation missing next link"))?;
        let activation_state = activation["stateToken"].as_str().unwrap_or(state_token);
        let mut req = json!({ "stateToken": activation_state });
        if let Some(map) = req.as_object_mut()
            && let Some(response_map) = created.response.as_object()
        {
            for (key, value) in response_map {
                map.insert(key.clone(), value.clone());
            }
        }
        let completed: Value = self
            .client
            .post(next)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;
        match completed["status"].as_str() {
            Some("SUCCESS") | Some("MFA_ENROLL") | Some("MFA_REQUIRED") => {
                crate::webauthn_keychain::store_credential(created.pending)?;
                println!(
                    "Stored WebAuthn Keychain credential for relying party {}. Credential id: {}",
                    creation.relying_party_id, created.credential_id
                );
                Ok(())
            }
            Some(other) => bail!("Okta WebAuthn enrollment failed with status {other}"),
            None => bail!(
                "{}",
                completed["errorSummary"]
                    .as_str()
                    .unwrap_or("Okta WebAuthn enrollment failed")
            ),
        }
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
                    self.webauthn_keychain,
                    &self.base_url,
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
    webauthn_keychain: bool,
    origin: &str,
) -> Result<String> {
    let mut supported: Vec<&Value> = factors
        .iter()
        .filter(|factor| {
            matches!(
                factor["factorType"].as_str(),
                Some("token:software:totp") | Some("push") | Some("u2f")
            ) || (webauthn_keychain && factor["factorType"].as_str() == Some("webauthn"))
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
    let selected = choose_factor(
        &supported,
        preferred_provider,
        "Registered MFA factors:",
        build_base_factor_name,
    )?;
    let response = verify_factor_response(
        client,
        state_token,
        selected,
        totp_token,
        webauthn_keychain,
        origin,
    )
    .await?;
    response["sessionToken"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("MFA success response missing sessionToken"))
}

async fn verify_base_mfa_response(
    client: &Client,
    state_token: &str,
    factors: &[Value],
    preferred_provider: Option<&str>,
    totp_token: Option<&str>,
    webauthn_keychain: bool,
    origin: &str,
) -> Result<Value> {
    let mut supported: Vec<&Value> = factors
        .iter()
        .filter(|factor| {
            matches!(
                factor["factorType"].as_str(),
                Some("token:software:totp") | Some("push") | Some("u2f")
            ) || (webauthn_keychain && factor["factorType"].as_str() == Some("webauthn"))
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
    let selected = choose_factor(
        &supported,
        preferred_provider,
        "Registered MFA factors:",
        build_base_factor_name,
    )?;
    verify_factor_response(
        client,
        state_token,
        selected,
        totp_token,
        webauthn_keychain,
        origin,
    )
    .await
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

async fn verify_factor_response(
    client: &Client,
    state_token: &str,
    factor: &Value,
    totp_token: Option<&str>,
    webauthn_keychain: bool,
    origin: &str,
) -> Result<Value> {
    let verify = factor["_links"]["verify"]["href"]
        .as_str()
        .ok_or_else(|| anyhow!("factor missing verify link"))?;
    let mut req = json!({ "stateToken": state_token });
    if factor["factorType"].as_str() == Some("token:software:totp") {
        req["passCode"] = Value::String(pass_code(totp_token)?);
    }
    let mut resp: Value = client.post(verify).json(&req).send().await?.json().await?;
    loop {
        match resp["status"].as_str() {
            Some("SUCCESS") | Some("MFA_ENROLL") => return Ok(resp),
            Some("MFA_CHALLENGE") if factor["factorType"].as_str() != Some("u2f") => {
                if factor["factorType"].as_str() == Some("webauthn") {
                    if !webauthn_keychain {
                        bail!(
                            "Okta returned a WebAuthn factor. Re-run with --webauthn-keychain to try the experimental macOS Keychain-backed authenticator, or use --browser for browser FastPass."
                        );
                    }
                    let auth_response = crate::webauthn_keychain::authenticate(
                        &webauthn_challenge(&resp, origin)?,
                    )?;
                    let next = resp["_links"]["next"]["href"]
                        .as_str()
                        .ok_or_else(|| anyhow!("WebAuthn challenge missing next link"))?;
                    let mut webauthn_req = req.clone();
                    if let Some(map) = webauthn_req.as_object_mut()
                        && let Some(auth_map) = auth_response.as_object()
                    {
                        for (key, value) in auth_map {
                            map.insert(key.clone(), value.clone());
                        }
                    }
                    resp = client
                        .post(next)
                        .json(&webauthn_req)
                        .send()
                        .await?
                        .json()
                        .await?;
                    continue;
                }
                println!("Waiting for push verification...");
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
            .ok_or_else(|| anyhow!("Unable to locate selected factor preference {preference}"))?;
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
        (Some("GOOGLE"), _) => with_factor_details(factor, "Google Authenticator"),
        (Some("OKTA"), Some("push")) => with_factor_details(factor, "Okta Verify - Push"),
        (Some("OKTA"), Some("token:software:totp")) => {
            with_factor_details(factor, "Okta Verify - TOTP")
        }
        (_, Some("webauthn")) => with_factor_details(factor, "WebAuthn platform authenticator"),
        (Some("OKTA"), Some(factor_type)) => {
            with_factor_details(factor, &format!("Okta Verify - {factor_type}"))
        }
        (Some("FIDO"), _) => with_factor_details(factor, "U2F security key"),
        (Some(provider), _) => format!("Unsupported factor type: {provider}"),
        _ => "Unknown MFA factor".to_string(),
    }
}

fn factor_matches_preference(factor: &Value, preference: &str) -> bool {
    let preference = preference.to_ascii_uppercase().replace('-', "_");
    let provider = factor["provider"].as_str().unwrap_or_default();
    let factor_type = factor["factorType"].as_str().unwrap_or_default();
    match preference.as_str() {
        "PUSH" | "OKTA_PUSH" => provider == "OKTA" && factor_type == "push",
        "TOTP" | "OKTA_TOTP" => provider == "OKTA" && factor_type == "token:software:totp",
        "GOOGLE" | "GOOGLE_TOTP" => provider == "GOOGLE",
        "WEBAUTHN" | "WEBAUTHN_KEYCHAIN" => factor_type == "webauthn",
        "U2F" | "FIDO" => factor_type == "u2f" || provider == "FIDO",
        _ => provider == preference,
    }
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
        Some("push") => 0,
        Some("u2f") => 1,
        Some("webauthn") => 1,
        Some("token:software:totp") => 2,
        _ => 3,
    }
}

fn with_factor_details(factor: &Value, label: &str) -> String {
    let details = factor_details(factor);
    if details.is_empty() {
        label.to_string()
    } else {
        format!("{label} ({})", details.join(", "))
    }
}

fn factor_details(factor: &Value) -> Vec<String> {
    let mut details = Vec::new();
    let profile = &factor["profile"];
    if let Some(value) = profile["name"].as_str()
        && !value.is_empty()
    {
        push_unique_detail(&mut details, format!("name: {value}"));
    }

    if let Some(id) = factor["id"].as_str()
        && !id.is_empty()
    {
        push_unique_detail(&mut details, format!("factor id: {}", short_id(id)));
    }

    details
}

fn push_unique_detail(details: &mut Vec<String>, detail: String) {
    if !details.iter().any(|existing| existing == &detail) {
        details.push(detail);
    }
}

fn short_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
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
        Some("webauthn") => with_factor_details(factor, "WebAuthn platform authenticator"),
        Some(other) => format!("Unknown MFA type: {other}"),
        None => "Unknown MFA type".to_string(),
    }
}

fn webauthn_challenge(
    response: &Value,
    origin: &str,
) -> Result<crate::webauthn_keychain::WebAuthnChallenge> {
    let challenge = response["_embedded"]["factor"]["_embedded"]["challenge"]["challenge"]
        .as_str()
        .ok_or_else(|| anyhow!("WebAuthn challenge missing challenge value"))?;
    let credential_id = response["_embedded"]["factor"]["profile"]["credentialId"]
        .as_str()
        .ok_or_else(|| anyhow!("WebAuthn challenge missing credentialId"))?;
    let user_verification =
        response["_embedded"]["factor"]["_embedded"]["challenge"]["userVerification"]
            .as_str()
            .unwrap_or("required");
    let relying_party_id = url::Url::parse(origin)?
        .host_str()
        .ok_or_else(|| anyhow!("Okta origin missing host"))?
        .to_string();
    Ok(crate::webauthn_keychain::WebAuthnChallenge {
        origin: origin.to_string(),
        relying_party_id,
        credential_id: credential_id.to_string(),
        challenge: challenge.to_string(),
        user_verification: user_verification.to_string(),
    })
}

fn webauthn_creation_options(
    response: &Value,
    origin: &str,
    fallback_user: &str,
) -> Result<crate::webauthn_keychain::WebAuthnCreationOptions> {
    let challenge = response["_embedded"]["factor"]["_embedded"]["activation"]["challenge"]
        .as_str()
        .or_else(|| response["_embedded"]["factor"]["_embedded"]["challenge"]["challenge"].as_str())
        .or_else(|| response["_embedded"]["challenge"]["challenge"].as_str())
        .ok_or_else(|| anyhow!("WebAuthn enrollment activation missing challenge value"))?;
    let user = &response["_embedded"]["user"];
    let profile = &user["profile"];
    let user_id = user["id"]
        .as_str()
        .or_else(|| profile["login"].as_str())
        .unwrap_or(fallback_user);
    let user_name = profile["login"].as_str().unwrap_or(fallback_user);
    let display_name = match (profile["firstName"].as_str(), profile["lastName"].as_str()) {
        (Some(first), Some(last)) => format!("{first} {last}"),
        _ => user_name.to_string(),
    };
    let relying_party_id = url::Url::parse(origin)?
        .host_str()
        .ok_or_else(|| anyhow!("Okta origin missing host"))?
        .to_string();
    Ok(crate::webauthn_keychain::WebAuthnCreationOptions {
        origin: origin.to_string(),
        relying_party_id,
        user_id: user_id.to_string(),
        user_name: user_name.to_string(),
        user_display_name: display_name,
        challenge: challenge.to_string(),
    })
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
            "id": "ost123456789abcdef",
            "provider": "OKTA",
            "factorType": "token:software:totp",
            "profile": {
                "credentialId": "user@example.com"
            }
        });
        assert_eq!(
            build_base_factor_name(&factor),
            "Okta Verify - TOTP (factor id: ost123456789)"
        );
    }

    #[test]
    fn factor_name_includes_multiple_device_details() {
        let factor = json!({
            "id": "opftabcdef1234567890",
            "provider": "OKTA",
            "factorType": "push",
            "profile": {
                "name": "Tommy's iPhone",
                "deviceName": "iPhone 15 Pro",
                "platform": "IOS",
                "credentialId": "user@example.com"
            }
        });
        assert_eq!(
            build_base_factor_name(&factor),
            "Okta Verify - Push (name: Tommy's iPhone, factor id: opftabcdef12)"
        );
    }

    #[test]
    fn parses_webauthn_creation_options() {
        let response = json!({
            "stateToken": "state-2",
            "_embedded": {
                "user": {
                    "id": "user-id",
                    "profile": {
                        "login": "user@example.com",
                        "firstName": "User",
                        "lastName": "Example"
                    }
                },
                "factor": {
                    "_embedded": {
                        "activation": {
                            "challenge": "challenge-value"
                        }
                    }
                }
            }
        });
        let options =
            webauthn_creation_options(&response, "https://example.okta.com", "fallback").unwrap();
        assert_eq!(options.relying_party_id, "example.okta.com");
        assert_eq!(options.user_id, "user-id");
        assert_eq!(options.user_name, "user@example.com");
        assert_eq!(options.user_display_name, "User Example");
        assert_eq!(options.challenge, "challenge-value");
    }
}
