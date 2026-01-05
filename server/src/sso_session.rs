//! SSO Session Management with JWT
//!
//! This module handles JWT-based session management for SSO authentication.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT Claims for user sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// User ID (email or unique identifier)
    pub sub: String,

    /// User's full name
    pub name: Option<String>,

    /// User's email
    pub email: String,

    /// User's email verification status
    pub email_verified: bool,

    /// SSO provider used
    pub provider: String,

    /// Session ID
    pub jti: String,

    /// Issued at (Unix timestamp)
    pub iat: i64,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issuer
    pub iss: String,

    /// Audience
    pub aud: String,

    /// User roles/permissions (optional)
    pub roles: Option<Vec<String>>,

    /// Additional user metadata
    pub metadata: Option<serde_json::Value>,
}

impl SessionClaims {
    /// Create new session claims
    pub fn new(
        email: String,
        name: Option<String>,
        provider: String,
        expiration_seconds: u64,
        email_verified: bool,
    ) -> Self {
        let now = Utc::now();
        let exp = now + Duration::seconds(expiration_seconds as i64);

        Self {
            sub: email.clone(),
            name,
            email,
            email_verified,
            provider,
            jti: Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            iss: "package-repo-server".to_string(),
            aud: "package-repo-api".to_string(),
            roles: None,
            metadata: None,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        self.exp < now
    }

    /// Get expiration as DateTime
    pub fn expiration_time(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.exp, 0).unwrap_or_else(Utc::now)
    }

    /// Get issued at as DateTime
    pub fn issued_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.iat, 0).unwrap_or_else(Utc::now)
    }
}

/// JWT Token Manager
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtManager {
    /// Create a new JWT manager with the given secret
    pub fn new(secret: &str) -> Self {
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["package-repo-api"]);
        validation.set_issuer(&["package-repo-server"]);

        Self {
            encoding_key,
            decoding_key,
            validation,
        }
    }

    /// Generate a JWT token from claims
    pub fn generate_token(&self, claims: &SessionClaims) -> Result<String, jsonwebtoken::errors::Error> {
        let header = Header::new(Algorithm::HS256);
        encode(&header, claims, &self.encoding_key)
    }

    /// Validate and decode a JWT token
    pub fn validate_token(&self, token: &str) -> Result<SessionClaims, jsonwebtoken::errors::Error> {
        let token_data = decode::<SessionClaims>(token, &self.decoding_key, &self.validation)?;

        // Additional expiration check
        if token_data.claims.is_expired() {
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::ExpiredSignature,
            ));
        }

        Ok(token_data.claims)
    }

    /// Extract token from Authorization header
    pub fn extract_token_from_header(auth_header: &str) -> Option<String> {
        let trimmed = auth_header.trim();

        if let Some(token) = trimmed.strip_prefix("Bearer ") {
            Some(token.trim().to_string())
        } else {
            None
        }
    }
}

/// User profile information from SSO provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// User ID from provider
    pub id: String,

    /// User's email
    pub email: String,

    /// Whether email is verified
    pub email_verified: bool,

    /// User's full name
    pub name: Option<String>,

    /// User's given name
    pub given_name: Option<String>,

    /// User's family name
    pub family_name: Option<String>,

    /// User's profile picture URL
    pub picture: Option<String>,

    /// User's locale
    pub locale: Option<String>,

    /// SSO provider
    pub provider: String,

    /// Raw data from provider
    pub raw_data: serde_json::Value,
}

impl UserProfile {
    /// Extract email domain
    pub fn email_domain(&self) -> Option<String> {
        self.email.split('@').nth(1).map(|s| s.to_lowercase())
    }

    /// Check if email matches allowed domains
    pub fn is_domain_allowed(&self, allowed_domains: &[String]) -> bool {
        if allowed_domains.is_empty() {
            return true;
        }

        if let Some(domain) = self.email_domain() {
            allowed_domains.iter().any(|d| d.to_lowercase() == domain)
        } else {
            false
        }
    }

    /// Check if email matches allowed emails
    pub fn is_email_allowed(&self, allowed_emails: &[String]) -> bool {
        if allowed_emails.is_empty() {
            return true;
        }

        let email_lower = self.email.to_lowercase();
        allowed_emails.iter().any(|e| {
            let pattern = e.to_lowercase();
            // Support wildcards like *@example.com
            if pattern.starts_with('*') {
                email_lower.ends_with(&pattern[1..])
            } else {
                email_lower == pattern
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_claims_creation() {
        let claims = SessionClaims::new(
            "user@example.com".to_string(),
            Some("Test User".to_string()),
            "google".to_string(),
            3600,
            true,
        );

        assert_eq!(claims.email, "user@example.com");
        assert_eq!(claims.provider, "google");
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_jwt_token_generation_and_validation() {
        let secret = "test-secret-key-at-least-32-characters-long";
        let manager = JwtManager::new(secret);

        let claims = SessionClaims::new(
            "user@example.com".to_string(),
            Some("Test User".to_string()),
            "google".to_string(),
            3600,
            true,
        );

        let token = manager.generate_token(&claims).expect("Failed to generate token");
        assert!(!token.is_empty());

        let decoded = manager.validate_token(&token).expect("Failed to validate token");
        assert_eq!(decoded.email, claims.email);
        assert_eq!(decoded.provider, claims.provider);
    }

    #[test]
    fn test_extract_token_from_header() {
        let header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        let token = JwtManager::extract_token_from_header(header);
        assert!(token.is_some());
        assert_eq!(token.unwrap(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

        let invalid = "Invalid header";
        assert!(JwtManager::extract_token_from_header(invalid).is_none());
    }

    #[test]
    fn test_user_profile_domain_check() {
        let profile = UserProfile {
            id: "123".to_string(),
            email: "user@example.com".to_string(),
            email_verified: true,
            name: Some("Test User".to_string()),
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            provider: "google".to_string(),
            raw_data: serde_json::json!({}),
        };

        assert_eq!(profile.email_domain(), Some("example.com".to_string()));

        let allowed = vec!["example.com".to_string()];
        assert!(profile.is_domain_allowed(&allowed));

        let not_allowed = vec!["other.com".to_string()];
        assert!(!profile.is_domain_allowed(&not_allowed));
    }

    #[test]
    fn test_user_profile_email_wildcard() {
        let profile = UserProfile {
            id: "123".to_string(),
            email: "user@example.com".to_string(),
            email_verified: true,
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            provider: "google".to_string(),
            raw_data: serde_json::json!({}),
        };

        let allowed = vec!["*@example.com".to_string()];
        assert!(profile.is_email_allowed(&allowed));

        let not_allowed = vec!["*@other.com".to_string()];
        assert!(!profile.is_email_allowed(&not_allowed));
    }
}
