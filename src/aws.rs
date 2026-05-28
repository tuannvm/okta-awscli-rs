use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_iam::config::Credentials as IamCredentials;
use aws_sdk_sts::config::Region;
use base64::Engine;
use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsPartition {
    Aws,
    AwsUsGov,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Role {
    pub principal_arn: String,
    pub role_arn: String,
}

#[derive(Clone, Debug)]
pub struct StsToken {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime<Utc>,
}

#[async_trait]
pub trait StsProvider {
    async fn assume_role_with_saml(
        &self,
        role: &Role,
        assertion: &str,
        duration: u32,
    ) -> Result<StsToken>;
    async fn valid_profile_credentials(
        &self,
        profile: &str,
        partition: AwsPartition,
    ) -> Result<bool>;
    async fn account_alias(
        &self,
        token: &StsToken,
        partition: AwsPartition,
    ) -> Result<Option<String>>;
}

#[derive(Clone, Debug, Default)]
pub struct AwsSdkProvider;

#[async_trait]
impl StsProvider for AwsSdkProvider {
    async fn assume_role_with_saml(
        &self,
        role: &Role,
        assertion: &str,
        duration: u32,
    ) -> Result<StsToken> {
        let region = sts_region(partition_from_arn(&role.principal_arn));
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(region)
            .load()
            .await;
        let client = aws_sdk_sts::Client::new(&conf);
        let response = client
            .assume_role_with_saml()
            .role_arn(&role.role_arn)
            .principal_arn(&role.principal_arn)
            .saml_assertion(assertion)
            .duration_seconds(duration as i32)
            .send()
            .await
            .context("Could not retrieve credentials from AWS STS")?;
        let creds = response
            .credentials()
            .ok_or_else(|| anyhow!("AWS STS response did not include credentials"))?;
        let expiration = creds.expiration();
        Ok(StsToken {
            access_key_id: creds.access_key_id().to_string(),
            secret_access_key: creds.secret_access_key().to_string(),
            session_token: creds.session_token().to_string(),
            expiration: DateTime::<Utc>::from_timestamp(
                expiration.secs(),
                expiration.subsec_nanos(),
            )
            .ok_or_else(|| anyhow!("invalid AWS expiration timestamp"))?,
        })
    }

    async fn valid_profile_credentials(
        &self,
        profile: &str,
        partition: AwsPartition,
    ) -> Result<bool> {
        let region = sts_region(partition);
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile)
            .region(region)
            .load()
            .await;
        let client = aws_sdk_sts::Client::new(&conf);
        match client.get_caller_identity().send().await {
            Ok(_) => Ok(true),
            Err(err) => {
                log::info!("Existing STS credentials are not usable: {err}");
                Ok(false)
            }
        }
    }

    async fn account_alias(
        &self,
        token: &StsToken,
        partition: AwsPartition,
    ) -> Result<Option<String>> {
        let region = match partition {
            AwsPartition::Aws => Region::new("us-east-1"),
            AwsPartition::AwsUsGov => Region::new("us-gov-west-1"),
        };
        let credentials = IamCredentials::new(
            token.access_key_id.clone(),
            token.secret_access_key.clone(),
            Some(token.session_token.clone()),
            None,
            "okta-awscli-rs",
        );
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(region)
            .credentials_provider(credentials)
            .load()
            .await;
        let client = aws_sdk_iam::Client::new(&conf);
        let aliases = client
            .list_account_aliases()
            .send()
            .await?
            .account_aliases()
            .to_vec();
        Ok(aliases.into_iter().next())
    }
}

#[derive(Clone, Debug)]
pub struct AwsAuth {
    pub profile: Option<String>,
    pub okta_profile: String,
    pub lookup: bool,
    pub role: Option<String>,
    pub creds_dir: PathBuf,
    pub creds_file: PathBuf,
    pub partition: AwsPartition,
}

impl AwsAuth {
    pub fn new(
        profile: Option<String>,
        okta_profile: String,
        lookup: bool,
        role: Option<String>,
        configured_profile: Option<String>,
    ) -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("could not locate home directory"))?;
        let (creds_dir, creds_file) =
            if let Ok(shared) = std::env::var("AWS_SHARED_CREDENTIALS_FILE") {
                let file = PathBuf::from(shared);
                (
                    file.parent()
                        .unwrap_or_else(|| std::path::Path::new("."))
                        .to_path_buf(),
                    file,
                )
            } else {
                let dir = home.join(".aws");
                let file = dir.join("credentials");
                (dir, file)
            };
        let resolved_profile = profile.or(configured_profile);
        let partition = role
            .as_deref()
            .map(partition_from_arn)
            .unwrap_or(AwsPartition::Aws);
        Ok(Self {
            profile: resolved_profile,
            okta_profile,
            lookup,
            role,
            creds_dir,
            creds_file,
            partition,
        })
    }

    pub async fn check_sts_token<P: StsProvider + Sync>(&self, provider: &P) -> Result<bool> {
        let Some(profile) = &self.profile else {
            return Ok(false);
        };
        if !self.creds_dir.exists() || !self.creds_file.exists() {
            log::info!("AWS credentials file does not exist. Not checking.");
            return Ok(false);
        }
        let creds = CredentialsFile::load(self.creds_file.clone())?;
        if !creds.sections.contains_key(profile) {
            log::info!("No existing credentials found. Requesting new credentials.");
            return Ok(false);
        }
        let valid = provider
            .valid_profile_credentials(profile, self.partition)
            .await?;
        if valid {
            log::info!("STS credentials are valid. Nothing to do.");
            self.set_default_profile(creds)?;
        }
        Ok(valid)
    }

    pub async fn choose_aws_role<P: StsProvider + Sync>(
        &self,
        assertion: &str,
        refresh_role: bool,
        provider: &P,
    ) -> Result<Role> {
        let roles = extract_available_roles(assertion)?;
        if roles.is_empty() {
            bail!("No AWS roles were found in the SAML assertion");
        }
        if let Some(role_arn) = &self.role {
            if let Some(role) = roles.iter().find(|role| &role.role_arn == role_arn) {
                if !refresh_role {
                    log::info!("Using predefined role: {}", role_arn);
                    return Ok(role.clone());
                }
                log::info!("Refreshing role");
            } else {
                log::info!(
                    "Predefined role, {}, not found in the list of roles assigned to you.",
                    role_arn
                );
            }
        }
        log::info!("Please choose a role.");
        for (index, role) in roles.iter().enumerate() {
            if self.lookup {
                match provider.assume_role_with_saml(role, assertion, 900).await {
                    Ok(token) => match provider
                        .account_alias(&token, partition_from_arn(&role.principal_arn))
                        .await
                    {
                        Ok(Some(alias)) => println!(
                            "{}: {} - {}",
                            index + 1,
                            alias,
                            role.role_arn.split(':').nth(5).unwrap_or(&role.role_arn)
                        ),
                        Ok(None) => println!("{}: {}", index + 1, role.role_arn),
                        Err(err) => {
                            log::warn!("Unable to perform alias lookup: {err}");
                            println!("{}: {}", index + 1, role.role_arn);
                        }
                    },
                    Err(err) => {
                        log::warn!("Unable to perform alias lookup: {err}");
                        println!("{}: {}", index + 1, role.role_arn);
                    }
                }
            } else {
                println!("{}: {}", index + 1, role.role_arn);
            }
        }
        let selection: usize = dialoguer::Input::new()
            .with_prompt("Please select the AWS role")
            .interact_text()?;
        if selection == 0 || selection > roles.len() {
            bail!("Invalid role selection");
        }
        Ok(roles[selection - 1].clone())
    }

    pub fn write_sts_token(&self, token: &StsToken) -> Result<()> {
        let profile = self
            .profile
            .as_ref()
            .ok_or_else(|| anyhow!("AWS profile is required to write credentials"))?;
        fs::create_dir_all(&self.creds_dir)?;
        let mut file =
            CredentialsFile::load(self.creds_file.clone()).unwrap_or_else(|_| CredentialsFile {
                path: self.creds_file.clone(),
                sections: BTreeMap::new(),
            });
        file.set(profile, "aws_access_key_id", &token.access_key_id);
        file.set(profile, "aws_secret_access_key", &token.secret_access_key);
        file.set(
            profile,
            "aws_session_expiration",
            &token.expiration.to_rfc3339(),
        );
        file.set(profile, "aws_session_token", &token.session_token);
        file.save()?;
        log::info!("Temporary credentials written to profile: {}", profile);
        log::info!(
            "Invoke using: aws --profile {} <service> <command>",
            profile
        );
        if profile != "default" {
            self.set_default_profile(file)?;
        }
        Ok(())
    }

    fn set_default_profile(&self, mut file: CredentialsFile) -> Result<()> {
        let Some(profile) = &self.profile else {
            return Ok(());
        };
        if let Some(values) = file.sections.get(profile).cloned() {
            file.sections.insert("default".to_string(), values);
            file.save()?;
        }
        Ok(())
    }

    pub fn execute_aws_args(&self, args: &[String]) -> Result<i32> {
        let profile = self.profile.as_ref().ok_or_else(|| {
            anyhow!(
                "--profile or profile in ~/.okta-aws is required when executing awscli arguments"
            )
        })?;
        let status = Command::new("aws")
            .arg("--profile")
            .arg(profile)
            .args(args)
            .status()
            .context("failed to invoke aws CLI")?;
        Ok(status.code().unwrap_or(1))
    }
}

#[derive(Clone, Debug)]
struct CredentialsFile {
    path: PathBuf,
    sections: BTreeMap<String, BTreeMap<String, String>>,
}

impl CredentialsFile {
    fn load(path: PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(&path)?;
        let mut sections = BTreeMap::new();
        let mut current = String::new();
        for raw in contents.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                current = name.trim().to_string();
                sections
                    .entry(current.clone())
                    .or_insert_with(BTreeMap::new);
                continue;
            }
            if let Some((key, value)) = line.split_once('=')
                && !current.is_empty()
            {
                sections
                    .entry(current.clone())
                    .or_insert_with(BTreeMap::new)
                    .insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        Ok(Self { path, sections })
    }

    fn set(&mut self, section: &str, key: &str, value: &str) {
        self.sections
            .entry(section.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }

    fn save(&self) -> Result<()> {
        let mut out = String::new();
        for (section, values) in &self.sections {
            out.push('[');
            out.push_str(section);
            out.push_str("]\n");
            for (key, value) in values {
                out.push_str(key);
                out.push_str(" = ");
                out.push_str(value);
                out.push('\n');
            }
            out.push('\n');
        }
        fs::write(&self.path, out)?;
        Ok(())
    }
}

pub fn extract_available_roles(assertion: &str) -> Result<Vec<Role>> {
    let xml = base64::engine::general_purpose::STANDARD.decode(assertion)?;
    Ok(extract_available_roles_from_xml(&xml)?
        .into_iter()
        .map(Role::from)
        .collect())
}

pub fn extract_available_roles_from_xml(xml: &[u8]) -> Result<Vec<(String, String)>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut roles = Vec::new();
    let mut in_role_attribute = false;
    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                let name = event.name();
                if name.as_ref().ends_with(b"Attribute") {
                    in_role_attribute = event.attributes().flatten().any(|attr| {
                        attr.key.as_ref() == b"Name"
                            && attr.value.as_ref() == b"https://aws.amazon.com/SAML/Attributes/Role"
                    });
                }
            }
            Event::Text(text) if in_role_attribute => {
                let value = text.decode()?.into_owned();
                if value.contains(":role/") && value.contains(":saml-provider/") {
                    let mut parts = value.split(',').map(str::trim);
                    let first = parts.next().unwrap_or_default().to_string();
                    let second = parts.next().unwrap_or_default().to_string();
                    if first
                        .split(':')
                        .nth(5)
                        .unwrap_or_default()
                        .starts_with("role/")
                    {
                        roles.push((second, first));
                    } else {
                        roles.push((first, second));
                    }
                }
            }
            Event::End(event) if event.name().as_ref().ends_with(b"Attribute") => {
                in_role_attribute = false
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(roles)
}

impl From<(String, String)> for Role {
    fn from(value: (String, String)) -> Self {
        Self {
            principal_arn: value.0,
            role_arn: value.1,
        }
    }
}

pub fn partition_from_arn(arn: &str) -> AwsPartition {
    match arn.split(':').nth(1) {
        Some("aws-us-gov") => AwsPartition::AwsUsGov,
        _ => AwsPartition::Aws,
    }
}

fn sts_region(partition: AwsPartition) -> Region {
    match partition {
        AwsPartition::Aws => Region::new("us-east-1"),
        AwsPartition::AwsUsGov => Region::new("us-gov-west-1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn extracts_roles_and_normalizes_order() {
        let xml = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><AttributeValue>arn:aws:iam::123:saml-provider/Okta,arn:aws:iam::123:role/Admin</AttributeValue><AttributeValue>arn:aws:iam::456:role/Dev,arn:aws:iam::456:saml-provider/Okta</AttributeValue></Attribute></Assertion>"#;
        let assertion = base64::engine::general_purpose::STANDARD.encode(xml);
        let roles = extract_available_roles(&assertion).unwrap();
        assert_eq!(
            roles[0].principal_arn,
            "arn:aws:iam::123:saml-provider/Okta"
        );
        assert_eq!(roles[0].role_arn, "arn:aws:iam::123:role/Admin");
        assert_eq!(
            roles[1].principal_arn,
            "arn:aws:iam::456:saml-provider/Okta"
        );
        assert_eq!(roles[1].role_arn, "arn:aws:iam::456:role/Dev");
    }

    #[test]
    fn detects_gov_partition() {
        assert_eq!(
            partition_from_arn("arn:aws-us-gov:iam::123:role/Admin"),
            AwsPartition::AwsUsGov
        );
    }
}
