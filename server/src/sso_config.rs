//! SSO Configuration Module
//!
//! Supports multiple OAuth2/OIDC providers including:
//! - Google
//! - GitHub
//! - GitLab
//! - Microsoft Azure AD
//! - Okta
//! - Auth0
//! - Keycloak
//! - Generic OIDC providers

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SSO Provider type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SsoProviderType {
    Google,
    GitHub,
    GitLab,
    Microsoft,
    Azure,
    Okta,
    Auth0,
    Keycloak,
    #[serde(rename = "oidc")]
    GenericOidc,
}

impl SsoProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Microsoft => "microsoft",
            Self::Azure => "azure",
            Self::Okta => "okta",
            Self::Auth0 => "auth0",
            Self::Keycloak => "keycloak",
            Self::GenericOidc => "oidc",
        }
    }
}

/// Individual SSO Provider Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoProviderConfig {
    /// Provider type
    pub provider_type: SsoProviderType,

    /// Provider display name
    pub name: String,

    /// OAuth2 client ID
    pub client_id: String,

    /// OAuth2 client secret
    pub client_secret: String,

    /// Authorization endpoint URL (optional for well-known providers)
    pub auth_url: Option<String>,

    /// Token endpoint URL (optional for well-known providers)
    pub token_url: Option<String>,

    /// UserInfo endpoint URL (optional for OIDC)
    pub userinfo_url: Option<String>,

    /// OIDC Discovery URL (e.g., https://accounts.google.com/.well-known/openid-configuration)
    pub discovery_url: Option<String>,

    /// OAuth2 scopes to request
    pub scopes: Vec<String>,

    /// Redirect URI (where OAuth provider sends user back)
    pub redirect_uri: String,

    /// Additional provider-specific parameters
    pub extra_params: Option<HashMap<String, String>>,

    /// Whether this provider is enabled
    pub enabled: bool,

    /// Whether to auto-register users from this provider
    pub auto_register: bool,

    /// Domain restrictions (e.g., only allow users from example.com)
    pub allowed_domains: Option<Vec<String>>,

    /// Email restrictions (specific email addresses or patterns)
    pub allowed_emails: Option<Vec<String>>,
}

impl SsoProviderConfig {
    /// Get the default auth URL for known providers
    pub fn get_auth_url(&self) -> String {
        if let Some(url) = &self.auth_url {
            return url.clone();
        }

        match self.provider_type {
            SsoProviderType::Google =>
                "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            SsoProviderType::GitHub =>
                "https://github.com/login/oauth/authorize".to_string(),
            SsoProviderType::GitLab =>
                "https://gitlab.com/oauth/authorize".to_string(),
            SsoProviderType::Microsoft | SsoProviderType::Azure =>
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
            _ => String::new(),
        }
    }

    /// Get the default token URL for known providers
    pub fn get_token_url(&self) -> String {
        if let Some(url) = &self.token_url {
            return url.clone();
        }

        match self.provider_type {
            SsoProviderType::Google =>
                "https://oauth2.googleapis.com/token".to_string(),
            SsoProviderType::GitHub =>
                "https://github.com/login/oauth/access_token".to_string(),
            SsoProviderType::GitLab =>
                "https://gitlab.com/oauth/token".to_string(),
            SsoProviderType::Microsoft | SsoProviderType::Azure =>
                "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
            _ => String::new(),
        }
    }

    /// Get the default userinfo URL for known providers
    pub fn get_userinfo_url(&self) -> String {
        if let Some(url) = &self.userinfo_url {
            return url.clone();
        }

        match self.provider_type {
            SsoProviderType::Google =>
                "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            SsoProviderType::GitHub =>
                "https://api.github.com/user".to_string(),
            SsoProviderType::GitLab =>
                "https://gitlab.com/api/v4/user".to_string(),
            SsoProviderType::Microsoft | SsoProviderType::Azure =>
                "https://graph.microsoft.com/v1.0/me".to_string(),
            _ => String::new(),
        }
    }

    /// Get default scopes for known providers
    pub fn get_default_scopes(&self) -> Vec<String> {
        if !self.scopes.is_empty() {
            return self.scopes.clone();
        }

        match self.provider_type {
            SsoProviderType::Google => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            SsoProviderType::GitHub => vec![
                "read:user".to_string(),
                "user:email".to_string(),
            ],
            SsoProviderType::GitLab => vec![
                "read_user".to_string(),
                "email".to_string(),
            ],
            SsoProviderType::Microsoft | SsoProviderType::Azure => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "User.Read".to_string(),
            ],
            _ => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
        }
    }
}

/// Complete SSO Configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SsoConfig {
    /// Whether SSO is enabled globally
    pub enabled: bool,

    /// List of configured providers
    pub providers: Vec<SsoProviderConfig>,

    /// JWT secret for signing session tokens
    pub jwt_secret: String,

    /// JWT token expiration time in seconds (default: 24 hours)
    pub jwt_expiration_seconds: u64,

    /// Session cookie name
    pub session_cookie_name: String,

    /// Session cookie domain
    pub session_cookie_domain: Option<String>,

    /// Whether to use secure cookies (HTTPS only)
    pub session_cookie_secure: bool,

    /// Cookie same-site policy
    pub session_cookie_samesite: String,

    /// Base URL of the application (for constructing redirect URIs)
    pub base_url: String,

    /// Whether to allow API key authentication alongside SSO
    pub allow_api_key_auth: bool,

    /// Whether SSO is required (if true, API keys are only for service accounts)
    pub require_sso: bool,
}

impl SsoConfig {
    /// Load SSO configuration from environment variables
    pub fn from_env() -> Self {
        let enabled = std::env::var("SSO_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        if !enabled {
            return Self {
                enabled: false,
                allow_api_key_auth: true,
                ..Default::default()
            };
        }

        let jwt_secret = std::env::var("SSO_JWT_SECRET")
            .unwrap_or_else(|_| {
                tracing::warn!("SSO_JWT_SECRET not set, generating random secret");
                use sha2::{Digest, Sha256};
                let random = uuid::Uuid::new_v4();
                let hash = Sha256::digest(random.as_bytes());
                hex::encode(hash)
            });

        let base_url = std::env::var("SSO_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        let jwt_expiration_seconds = std::env::var("SSO_JWT_EXPIRATION_SECONDS")
            .unwrap_or_else(|_| "86400".to_string())
            .parse::<u64>()
            .unwrap_or(86400);

        let allow_api_key_auth = std::env::var("SSO_ALLOW_API_KEY_AUTH")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        let require_sso = std::env::var("SSO_REQUIRE")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        let session_cookie_secure = std::env::var("SSO_COOKIE_SECURE")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        // Load providers from environment
        let mut providers = Vec::new();
        providers.extend(Self::load_provider_from_env("GOOGLE", SsoProviderType::Google));
        providers.extend(Self::load_provider_from_env("GITHUB", SsoProviderType::GitHub));
        providers.extend(Self::load_provider_from_env("GITLAB", SsoProviderType::GitLab));
        providers.extend(Self::load_provider_from_env("MICROSOFT", SsoProviderType::Microsoft));
        providers.extend(Self::load_provider_from_env("AZURE", SsoProviderType::Azure));
        providers.extend(Self::load_provider_from_env("OKTA", SsoProviderType::Okta));
        providers.extend(Self::load_provider_from_env("AUTH0", SsoProviderType::Auth0));
        providers.extend(Self::load_provider_from_env("KEYCLOAK", SsoProviderType::Keycloak));
        providers.extend(Self::load_provider_from_env("OIDC", SsoProviderType::GenericOidc));

        Self {
            enabled,
            providers,
            jwt_secret,
            jwt_expiration_seconds,
            session_cookie_name: "package_repo_session".to_string(),
            session_cookie_domain: std::env::var("SSO_COOKIE_DOMAIN").ok(),
            session_cookie_secure,
            session_cookie_samesite: "Lax".to_string(),
            base_url,
            allow_api_key_auth,
            require_sso,
        }
    }

    /// Load a specific provider configuration from environment variables
    fn load_provider_from_env(prefix: &str, provider_type: SsoProviderType) -> Option<SsoProviderConfig> {
        let enabled_key = format!("SSO_{}_ENABLED", prefix);
        let enabled = std::env::var(&enabled_key)
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        if !enabled {
            return None;
        }

        let client_id = std::env::var(format!("SSO_{}_CLIENT_ID", prefix)).ok()?;
        let client_secret = std::env::var(format!("SSO_{}_CLIENT_SECRET", prefix)).ok()?;

        let name = std::env::var(format!("SSO_{}_NAME", prefix))
            .unwrap_or_else(|_| format!("{:?}", provider_type));

        let auth_url = std::env::var(format!("SSO_{}_AUTH_URL", prefix)).ok();
        let token_url = std::env::var(format!("SSO_{}_TOKEN_URL", prefix)).ok();
        let userinfo_url = std::env::var(format!("SSO_{}_USERINFO_URL", prefix)).ok();
        let discovery_url = std::env::var(format!("SSO_{}_DISCOVERY_URL", prefix)).ok();

        let scopes = std::env::var(format!("SSO_{}_SCOPES", prefix))
            .ok()
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let redirect_uri = std::env::var(format!("SSO_{}_REDIRECT_URI", prefix))
            .unwrap_or_else(|_| {
                let base = std::env::var("SSO_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string());
                format!("{}/auth/callback/{}", base, provider_type.as_str())
            });

        let auto_register = std::env::var(format!("SSO_{}_AUTO_REGISTER", prefix))
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        let allowed_domains = std::env::var(format!("SSO_{}_ALLOWED_DOMAINS", prefix))
            .ok()
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

        let allowed_emails = std::env::var(format!("SSO_{}_ALLOWED_EMAILS", prefix))
            .ok()
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

        Some(SsoProviderConfig {
            provider_type,
            name,
            client_id,
            client_secret,
            auth_url,
            token_url,
            userinfo_url,
            discovery_url,
            scopes,
            redirect_uri,
            extra_params: None,
            enabled: true,
            auto_register,
            allowed_domains,
            allowed_emails,
        })
    }

    /// Get a provider by its type
    pub fn get_provider(&self, provider_type: &str) -> Option<&SsoProviderConfig> {
        self.providers.iter().find(|p| p.provider_type.as_str() == provider_type && p.enabled)
    }

    /// Get all enabled providers
    pub fn enabled_providers(&self) -> Vec<&SsoProviderConfig> {
        self.providers.iter().filter(|p| p.enabled).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_serialization() {
        assert_eq!(SsoProviderType::Google.as_str(), "google");
        assert_eq!(SsoProviderType::GitHub.as_str(), "github");
        assert_eq!(SsoProviderType::GenericOidc.as_str(), "oidc");
    }

    #[test]
    fn test_default_sso_config() {
        let config = SsoConfig::default();
        assert!(!config.enabled);
        assert!(config.providers.is_empty());
    }
}
