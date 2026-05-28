use anyhow::{Context, Result, anyhow};
use dialoguer::{Confirm, Input};
use log::{debug, info, warn};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileConfig {
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub factor: Option<String>,
    pub role: Option<String>,
    pub profile: Option<String>,
    pub app_link: Option<String>,
    pub duration: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct OktaConfig {
    pub path: PathBuf,
    sections: BTreeMap<String, BTreeMap<String, String>>,
}

impl OktaConfig {
    pub fn load(path: PathBuf) -> Result<Self> {
        let sections = if path.exists() {
            parse_ini(
                &fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?,
            )
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, sections })
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(dirs::home_dir()
            .ok_or_else(|| anyhow!("could not locate home directory"))?
            .join(".okta-aws"))
    }

    pub fn profiles(&self) -> Vec<String> {
        self.sections.keys().cloned().collect()
    }

    pub fn profile(&self, name: &str) -> ProfileConfig {
        ProfileConfig {
            base_url: self.get(name, "base-url"),
            username: self.get(name, "username"),
            password: self.get(name, "password"),
            factor: self.get(name, "factor"),
            role: self.get(name, "role"),
            profile: self.get(name, "profile"),
            app_link: self.get(name, "app-link"),
            duration: self
                .get(name, "duration")
                .and_then(|value| match value.parse::<u32>() {
                    Ok(parsed) => Some(parsed),
                    Err(_) => {
                        warn!("Duration could not be converted to a number, ignoring.");
                        None
                    }
                }),
        }
    }

    pub fn base_url_for(&self, name: &str) -> Result<String> {
        let base_url = self
            .get(name, "base-url")
            .or_else(|| self.get("default", "base-url"))
            .ok_or_else(|| anyhow!("No profile found. Please define a default profile, or specify a named profile using --okta-profile"))?;
        info!("Authenticating to: {}", base_url);
        Ok(base_url
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string())
    }

    pub fn app_link_for(&self, name: &str) -> Result<Option<String>> {
        let app_link = self
            .get(name, "app-link")
            .or_else(|| self.get("default", "app-link"));
        if let Some(link) = app_link {
            Url::parse(&link)
                .with_context(|| format!("The app-link provided is an invalid url: {link}"))?;
            info!("App Link set as: {}", link);
            Ok(Some(link))
        } else {
            log::error!("The app-link is missing. Will try to retrieve it from Okta");
            Ok(None)
        }
    }

    pub fn username_for(&self, name: &str) -> Result<String> {
        if let Some(username) = self
            .get(name, "username")
            .or_else(|| self.get("default", "username"))
        {
            info!("Authenticating as: {}", username);
            Ok(username)
        } else {
            Ok(Input::new().with_prompt("Enter username").interact_text()?)
        }
    }

    pub fn password_for(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .get(name, "password")
            .or_else(|| self.get("default", "password")))
    }

    pub fn factor_for(&self, name: &str) -> Option<String> {
        let factor = self
            .get(name, "factor")
            .or_else(|| self.get("default", "factor"));
        if let Some(value) = &factor {
            debug!("Setting MFA factor to {}", value);
        }
        factor
    }

    pub fn role_for(&self, name: &str) -> Option<String> {
        self.get(name, "role")
    }

    pub fn aws_profile_for(&self, name: &str) -> Option<String> {
        self.get(name, "profile")
    }

    pub fn duration_for(&self, name: &str) -> Option<u32> {
        self.profile(name)
            .duration
            .or_else(|| self.profile("default").duration)
    }

    pub fn set_value(&mut self, profile: &str, key: &str, value: &str) {
        self.sections
            .entry(profile.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }

    pub fn write_role_to_profile(&mut self, profile: &str, role_arn: &str) -> Result<()> {
        let base_url = self.base_url_for(profile)?;
        self.set_value(profile, "base-url", &base_url);
        self.set_value(profile, "role", role_arn);
        self.save()
    }

    pub fn write_applink_to_profile(&mut self, profile: &str, app_link: &str) -> Result<()> {
        let base_url = self.base_url_for(profile)?;
        self.set_value(profile, "base-url", &base_url);
        self.set_value(profile, "app-link", app_link);
        self.save()
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serialize_ini(&self.sections))
            .with_context(|| format!("writing {}", self.path.display()))
    }

    fn get(&self, profile: &str, key: &str) -> Option<String> {
        self.sections
            .get(profile)
            .and_then(|section| section.get(key))
            .cloned()
    }
}

pub fn configure_interactive(path: &Path) -> Result<()> {
    let mut config = OktaConfig::load(path.to_path_buf())?;
    if path.exists() {
        println!(
            "You have preconfigured Okta profiles: {:?}",
            config.profiles()
        );
        println!(
            "This command will append new profile to the existing {} config file",
            path.display()
        );
    } else {
        println!(
            "This command will create a new {} config file",
            path.display()
        );
    }

    if !Confirm::new()
        .with_prompt("Would you like to proceed?")
        .interact()?
    {
        return Ok(());
    }

    let okta_profile: String = Input::new()
        .with_prompt("Enter Okta profile name")
        .allow_empty(true)
        .interact_text()?;
    let okta_profile = if okta_profile.trim().is_empty() {
        "default".to_string()
    } else {
        okta_profile
    };
    let aws_profile: String = Input::new()
        .with_prompt("Enter AWS profile name")
        .interact_text()?;
    let base_url: String = Input::new()
        .with_prompt("Enter Okta base url [your main organisation Okta url]")
        .interact_text()?;
    let username: String = Input::new()
        .with_prompt("Enter Okta username")
        .interact_text()?;
    let app_link: String = Input::new()
        .with_prompt("Enter AWS app-link [optional]")
        .allow_empty(true)
        .interact_text()?;
    let duration: String = Input::new()
        .with_prompt("Duration in seconds to request a session token for [Default=3600]")
        .allow_empty(true)
        .interact_text()?;

    config.set_value(&okta_profile, "base-url", &base_url);
    config.set_value(&okta_profile, "profile", &aws_profile);
    config.set_value(&okta_profile, "username", &username);
    if !app_link.trim().is_empty() {
        config.set_value(&okta_profile, "app-link", &app_link);
    }
    config.set_value(
        &okta_profile,
        "duration",
        if duration.trim().is_empty() {
            "3600"
        } else {
            duration.trim()
        },
    );
    config.save()?;
    println!(
        "Configuration {} successfully updated. Now you can authenticate to Okta",
        path.display()
    );
    println!(
        "Execute 'okta-awscli -o {okta_profile} -p {aws_profile} sts get-caller-identity' to authenticate and retrieve credentials"
    );
    Ok(())
}

fn parse_ini(contents: &str) -> BTreeMap<String, BTreeMap<String, String>> {
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
    sections
}

fn serialize_ini(sections: &BTreeMap<String, BTreeMap<String, String>>) -> String {
    let mut out = String::new();
    for (section, values) in sections {
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_fallbacks_and_duration() {
        let sections = parse_ini(
            "[default]\nbase-url = example.okta.com\nduration = 3600\n\n[prod]\nusername = me\n",
        );
        let cfg = OktaConfig {
            path: PathBuf::new(),
            sections,
        };
        assert_eq!(cfg.base_url_for("prod").unwrap(), "example.okta.com");
        assert_eq!(cfg.duration_for("prod"), Some(3600));
        assert_eq!(cfg.username_for("prod").unwrap(), "me");
    }
}
