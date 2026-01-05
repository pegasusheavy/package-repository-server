//! SSO Authentication Handlers
//!
//! Implements OAuth2/OIDC authentication flows for multiple providers.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use oauth2::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use crate::sso_config::{SsoConfig, SsoProviderConfig, SsoProviderType};
use crate::sso_session::{JwtManager, SessionClaims, UserProfile};
use crate::sso_state::{OAuthStateData, StatelessStateManager};

/// Application state with SSO configuration
pub struct SsoState {
    pub config: SsoConfig,
    pub jwt_manager: JwtManager,
    pub state_manager: StatelessStateManager,
}

/// OAuth2 authorization request
#[derive(Debug, Serialize)]
pub struct AuthorizationRequest {
    pub authorization_url: String,
    pub state: String,
}

/// OAuth2 callback query parameters
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// SSO login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub token: String,
    pub user: UserInfo,
    pub expires_at: i64,
}

/// User information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: String,
    pub name: Option<String>,
    pub email_verified: bool,
    pub provider: String,
}

/// List of available SSO providers
#[derive(Debug, Serialize)]
pub struct ProvidersListResponse {
    pub providers: Vec<ProviderInfo>,
}

#[derive(Debug, Serialize)]
pub struct ProviderInfo {
    pub id: String,
    pub name: String,
    pub enabled: bool,
}

/// GET /auth/providers - List available SSO providers
pub async fn list_providers(state: web::Data<Arc<SsoState>>) -> Result<HttpResponse> {
    if !state.config.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "SSO is not enabled",
        })));
    }

    let providers: Vec<ProviderInfo> = state.config.enabled_providers()
        .iter()
        .map(|p| ProviderInfo {
            id: p.provider_type.as_str().to_string(),
            name: p.name.clone(),
            enabled: p.enabled,
        })
        .collect();

    Ok(HttpResponse::Ok().json(ProvidersListResponse { providers }))
}

/// GET /auth/login/{provider} - Initiate SSO login
pub async fn initiate_login(
    provider_id: web::Path<String>,
    state: web::Data<Arc<SsoState>>,
) -> Result<HttpResponse> {
    if !state.config.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "SSO is not enabled",
        })));
    }

    let provider = match state.config.get_provider(&provider_id) {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("SSO provider '{}' not found or not enabled", provider_id),
            })));
        }
    };

    info!("Initiating SSO login with provider: {}", provider.name);

    // Build OAuth2 client
    let client = match build_oauth_client(provider) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build OAuth client: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to initialize OAuth client",
            })));
        }
    };

    // Generate PKCE challenge for extra security
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let csrf_token = CsrfToken::new_random();
    
    // Create stateless OAuth state data
    let state_data = OAuthStateData::new(
        pkce_verifier.secret().clone(),
        csrf_token.secret().clone(),
        provider_id.to_string(),
    );
    
    // Encode state into encrypted token (stateless - no server-side storage needed)
    let encoded_state = match state.state_manager.encode(&state_data) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to encode OAuth state: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create OAuth state",
            })));
        }
    };
    
    // Build authorization URL with our encoded state
    let mut auth_request = client
        .authorize_url(|| CsrfToken::new(encoded_state.clone()))
        .set_pkce_challenge(pkce_challenge);
    
    // Add scopes
    for scope in provider.get_default_scopes() {
        auth_request = auth_request.add_scope(Scope::new(scope));
    }
    
    let (auth_url, _) = auth_request.url();
    
    debug!("Generated authorization URL with stateless state");
    
    Ok(HttpResponse::Ok().json(AuthorizationRequest {
        authorization_url: auth_url.to_string(),
        state: encoded_state,
    }))
}

/// GET /auth/callback/{provider} - OAuth callback handler
pub async fn handle_callback(
    provider_id: web::Path<String>,
    query: web::Query<CallbackQuery>,
    state: web::Data<Arc<SsoState>>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    if !state.config.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "SSO is not enabled",
        })));
    }
    
    // Decode and validate stateless OAuth state
    let state_data = match state.state_manager.decode(&query.state) {
        Ok(d) => d,
        Err(e) => {
            error!("Invalid OAuth state: {}", e);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid or expired OAuth state",
                "details": "The OAuth flow has expired or the state parameter was tampered with",
            })));
        }
    };
    
    // Verify provider matches
    if state_data.provider != provider_id.as_str() {
        error!("Provider mismatch in OAuth state");
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Provider mismatch",
        })));
    }
    
    let provider = match state.config.get_provider(&provider_id) {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("SSO provider '{}' not found", provider_id),
            })));
        }
    };
    
    info!("Handling OAuth callback for provider: {}", provider.name);
    
    // Build OAuth2 client
    let client = match build_oauth_client(provider) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build OAuth client: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to initialize OAuth client",
            })));
        }
    };
    
    // Exchange authorization code for access token with PKCE verifier
    let code = AuthorizationCode::new(query.code.clone());
    let pkce_verifier = PkceCodeVerifier::new(state_data.pkce_verifier);
    
    let token_result = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await;

    let token = match token_result {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to exchange authorization code: {}", e);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Failed to exchange authorization code",
                "details": e.to_string(),
            })));
        }
    };

    // Fetch user profile
    let user_profile = match fetch_user_profile(provider, token.access_token().secret()).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to fetch user profile: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch user profile",
                "details": e.to_string(),
            })));
        }
    };

    info!("Successfully authenticated user: {}", user_profile.email);

    // Check domain restrictions
    if let Some(allowed_domains) = &provider.allowed_domains {
        if !user_profile.is_domain_allowed(allowed_domains) {
            warn!("User {} domain not allowed", user_profile.email);
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Your email domain is not authorized to access this service",
            })));
        }
    }

    // Check email restrictions
    if let Some(allowed_emails) = &provider.allowed_emails {
        if !user_profile.is_email_allowed(allowed_emails) {
            warn!("User {} email not allowed", user_profile.email);
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Your email address is not authorized to access this service",
            })));
        }
    }

    // Generate JWT session token
    let claims = SessionClaims::new(
        user_profile.email.clone(),
        user_profile.name.clone(),
        provider.provider_type.as_str().to_string(),
        state.config.jwt_expiration_seconds,
        user_profile.email_verified,
    );

    let jwt_token = match state.jwt_manager.generate_token(&claims) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to generate JWT token: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate session token",
            })));
        }
    };

    Ok(HttpResponse::Ok().json(LoginResponse {
        success: true,
        token: jwt_token,
        user: UserInfo {
            email: user_profile.email,
            name: user_profile.name,
            email_verified: user_profile.email_verified,
            provider: provider.provider_type.as_str().to_string(),
        },
        expires_at: claims.exp,
    }))
}

/// GET /auth/validate - Validate current session token
pub async fn validate_session(
    req: HttpRequest,
    state: web::Data<Arc<SsoState>>,
) -> Result<HttpResponse> {
    if !state.config.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "SSO is not enabled",
        })));
    }

    // Extract token from Authorization header
    let auth_header = match req.headers().get("Authorization") {
        Some(h) => match h.to_str() {
            Ok(s) => s,
            Err(_) => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid Authorization header",
                })));
            }
        },
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Missing Authorization header",
            })));
        }
    };

    let token = match JwtManager::extract_token_from_header(auth_header) {
        Some(t) => t,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid token format",
            })));
        }
    };

    // Validate token
    let claims = match state.jwt_manager.validate_token(&token) {
        Ok(c) => c,
        Err(e) => {
            debug!("Token validation failed: {}", e);
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid or expired token",
            })));
        }
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": true,
        "user": UserInfo {
            email: claims.email,
            name: claims.name,
            email_verified: claims.email_verified,
            provider: claims.provider,
        },
        "expires_at": claims.exp,
    })))
}

/// POST /auth/logout - Logout (invalidate session)
pub async fn logout(req: HttpRequest) -> Result<HttpResponse> {
    // In a stateless JWT system, logout is client-side (delete token)
    // For server-side logout, you would need a token blacklist

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully. Please delete your session token.",
    })))
}

/// Build OAuth2 client from provider configuration
fn build_oauth_client(provider: &SsoProviderConfig) -> anyhow::Result<BasicClient> {
    let client_id = ClientId::new(provider.client_id.clone());
    let client_secret = ClientSecret::new(provider.client_secret.clone());
    let auth_url = oauth2::AuthUrl::new(provider.get_auth_url())?;
    let token_url = oauth2::TokenUrl::new(provider.get_token_url())?;

    let client = BasicClient::new(
        client_id,
        Some(client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(provider.redirect_uri.clone())?);

    Ok(client)
}

/// Fetch user profile from SSO provider
async fn fetch_user_profile(
    provider: &SsoProviderConfig,
    access_token: &str,
) -> anyhow::Result<UserProfile> {
    let userinfo_url = provider.get_userinfo_url();

    if userinfo_url.is_empty() {
        return Err(anyhow::anyhow!("UserInfo URL not configured for provider"));
    }

    let client = reqwest::Client::new();
    let response = client
        .get(&userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch user profile: HTTP {}",
            response.status()
        ));
    }

    let data: Value = response.json().await?;

    // Parse user profile based on provider
    let profile = parse_user_profile(&provider.provider_type, data)?;

    Ok(profile)
}

/// Parse user profile from provider-specific format
fn parse_user_profile(provider_type: &SsoProviderType, data: Value) -> anyhow::Result<UserProfile> {
    match provider_type {
        SsoProviderType::Google => {
            Ok(UserProfile {
                id: data["sub"].as_str().unwrap_or_default().to_string(),
                email: data["email"].as_str().ok_or_else(|| anyhow::anyhow!("Missing email"))?.to_string(),
                email_verified: data["email_verified"].as_bool().unwrap_or(false),
                name: data["name"].as_str().map(|s| s.to_string()),
                given_name: data["given_name"].as_str().map(|s| s.to_string()),
                family_name: data["family_name"].as_str().map(|s| s.to_string()),
                picture: data["picture"].as_str().map(|s| s.to_string()),
                locale: data["locale"].as_str().map(|s| s.to_string()),
                provider: "google".to_string(),
                raw_data: data,
            })
        }
        SsoProviderType::GitHub => {
            // GitHub requires separate call for email
            let email = data["email"].as_str()
                .or_else(|| data["login"].as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing email/login"))?
                .to_string();

            Ok(UserProfile {
                id: data["id"].to_string(),
                email,
                email_verified: true, // GitHub emails are verified
                name: data["name"].as_str().map(|s| s.to_string()),
                given_name: None,
                family_name: None,
                picture: data["avatar_url"].as_str().map(|s| s.to_string()),
                locale: None,
                provider: "github".to_string(),
                raw_data: data,
            })
        }
        SsoProviderType::GitLab => {
            Ok(UserProfile {
                id: data["id"].to_string(),
                email: data["email"].as_str().ok_or_else(|| anyhow::anyhow!("Missing email"))?.to_string(),
                email_verified: data["confirmed_at"].is_string(),
                name: data["name"].as_str().map(|s| s.to_string()),
                given_name: None,
                family_name: None,
                picture: data["avatar_url"].as_str().map(|s| s.to_string()),
                locale: None,
                provider: "gitlab".to_string(),
                raw_data: data,
            })
        }
        SsoProviderType::Microsoft | SsoProviderType::Azure => {
            Ok(UserProfile {
                id: data["id"].as_str().unwrap_or_default().to_string(),
                email: data["mail"].as_str()
                    .or_else(|| data["userPrincipalName"].as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing email"))?
                    .to_string(),
                email_verified: true, // Microsoft emails are verified
                name: data["displayName"].as_str().map(|s| s.to_string()),
                given_name: data["givenName"].as_str().map(|s| s.to_string()),
                family_name: data["surname"].as_str().map(|s| s.to_string()),
                picture: None,
                locale: None,
                provider: "microsoft".to_string(),
                raw_data: data,
            })
        }
        _ => {
            // Generic OIDC parsing
            Ok(UserProfile {
                id: data["sub"].as_str().unwrap_or_default().to_string(),
                email: data["email"].as_str().ok_or_else(|| anyhow::anyhow!("Missing email"))?.to_string(),
                email_verified: data["email_verified"].as_bool().unwrap_or(false),
                name: data["name"].as_str().map(|s| s.to_string()),
                given_name: data["given_name"].as_str().map(|s| s.to_string()),
                family_name: data["family_name"].as_str().map(|s| s.to_string()),
                picture: data["picture"].as_str().map(|s| s.to_string()),
                locale: data["locale"].as_str().map(|s| s.to_string()),
                provider: provider_type.as_str().to_string(),
                raw_data: data,
            })
        }
    }
}

/// Configure SSO routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/providers", web::get().to(list_providers))
            .route("/login/{provider}", web::get().to(initiate_login))
            .route("/callback/{provider}", web::get().to(handle_callback))
            .route("/validate", web::get().to(validate_session))
            .route("/logout", web::post().to(logout))
    );
}
