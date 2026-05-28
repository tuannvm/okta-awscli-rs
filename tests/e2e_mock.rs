use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use okta_awscli_rs::aws::{AwsAuth, AwsPartition, Role, StsProvider, StsToken};
use okta_awscli_rs::config::OktaConfig;
use okta_awscli_rs::okta::OktaAuth;
use std::fs;
use tempfile::tempdir;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone, Debug)]
struct FakeSts;

#[async_trait]
impl StsProvider for FakeSts {
    async fn assume_role_with_saml(
        &self,
        _role: &Role,
        _assertion: &str,
        _duration: u32,
    ) -> Result<StsToken> {
        Ok(StsToken {
            access_key_id: "AKIAFAKE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: "session".to_string(),
            expiration: Utc::now(),
        })
    }

    async fn valid_profile_credentials(
        &self,
        _profile: &str,
        _partition: AwsPartition,
    ) -> Result<bool> {
        Ok(false)
    }

    async fn account_alias(
        &self,
        _token: &StsToken,
        _partition: AwsPartition,
    ) -> Result<Option<String>> {
        Ok(Some("mock-account".to_string()))
    }
}

#[tokio::test]
async fn mock_okta_to_aws_credentials_flow() -> Result<()> {
    let server = MockServer::start().await;
    let assertion = assertion_with_role();
    Mock::given(method("POST"))
        .and(path("/api/v1/authn"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "SUCCESS",
            "sessionToken": "session-token"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/sessions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": "sid123" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/me/appLinks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "appName": "amazon_aws", "label": "AWS", "linkUrl": format!("{}/saml", server.uri()), "sortOrder": 1 }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/saml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><input name="SAMLResponse" value="{assertion}"></html>"#
        )))
        .mount(&server)
        .await;

    let temp = tempdir()?;
    let config_path = temp.path().join(".okta-aws");
    fs::write(
        &config_path,
        format!(
            "[default]\nbase-url = {}\nusername = jane\nprofile = mock\nduration = 3600\n",
            server.uri()
        ),
    )?;
    let mut config = OktaConfig::load(config_path)?;
    let mut okta = OktaAuth::new(
        &config,
        "default",
        "jane".to_string(),
        "pw".to_string(),
        None,
        false,
    )?;
    let (_, saml) = okta.get_assertion(&mut config).await?;
    let aws = AwsAuth::new(
        Some("mock".to_string()),
        "default".to_string(),
        false,
        Some("arn:aws:iam::123456789012:role/Admin".to_string()),
        None,
    )?;
    let role = aws.choose_aws_role(&saml, false, &FakeSts).await?;
    let token = FakeSts.assume_role_with_saml(&role, &saml, 3600).await?;

    assert_eq!(role.role_arn, "arn:aws:iam::123456789012:role/Admin");
    assert_eq!(token.access_key_id, "AKIAFAKE");
    Ok(())
}

#[tokio::test]
async fn primary_totp_mfa_sends_pass_code() -> Result<()> {
    let server = MockServer::start().await;
    let assertion = assertion_with_role();
    Mock::given(method("POST"))
        .and(path("/api/v1/authn"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "MFA_REQUIRED",
            "stateToken": "state-1",
            "_embedded": {
                "factors": [{
                    "factorType": "token:software:totp",
                    "provider": "OKTA",
                    "profile": { "credentialId": "jane@example.com" },
                    "_links": {
                        "verify": { "href": format!("{}/api/v1/authn/factors/f1/verify", server.uri()) }
                    }
                }]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authn/factors/f1/verify"))
        .and(body_partial_json(serde_json::json!({
            "stateToken": "state-1",
            "passCode": "654321"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "SUCCESS",
            "sessionToken": "session-token"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/sessions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": "sid123" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/me/appLinks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            { "appName": "amazon_aws", "label": "AWS", "linkUrl": format!("{}/saml", server.uri()), "sortOrder": 1 }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/saml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><input name="SAMLResponse" value="{assertion}"></html>"#
        )))
        .mount(&server)
        .await;

    let temp = tempdir()?;
    let config_path = temp.path().join(".okta-aws");
    fs::write(
        &config_path,
        format!(
            "[default]\nbase-url = {}\nusername = jane\nprofile = mock\nduration = 3600\n",
            server.uri()
        ),
    )?;
    let mut config = OktaConfig::load(config_path)?;
    let mut okta = OktaAuth::new(
        &config,
        "default",
        "jane".to_string(),
        "pw".to_string(),
        Some("654321".to_string()),
        false,
    )?;
    let (_, saml) = okta.get_assertion(&mut config).await?;

    assert_eq!(saml, assertion);
    Ok(())
}

fn assertion_with_role() -> String {
    let xml = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><AttributeValue>arn:aws:iam::123456789012:saml-provider/Okta,arn:aws:iam::123456789012:role/Admin</AttributeValue></Attribute></Assertion>"#;
    base64::engine::general_purpose::STANDARD.encode(xml)
}
