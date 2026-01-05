//! Authentication module for API key validation
//!
//! This module provides secure API key extraction and validation.
//! Uses timing-safe comparison to prevent timing attacks.

use actix_web::HttpRequest;
use tracing::warn;

use crate::security::{log_auth_failure, secure_compare, validate_api_key_format};
use crate::AppState;

/// Extracts client IP from request for logging purposes
pub fn get_client_ip(req: &HttpRequest) -> Option<String> {
    // Check X-Forwarded-For header first (for reverse proxies)
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP in the chain
            return Some(forwarded_str.split(',').next()?.trim().to_string());
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.trim().to_string());
        }
    }

    // Fall back to peer address
    req.peer_addr().map(|addr| addr.ip().to_string())
}

/// Extracts API key from request headers
/// Checks both "Authorization: Bearer <token>" and "X-API-Key: <token>" headers
///
/// Security: This function only extracts the key, validation happens separately
pub fn extract_api_key(req: &HttpRequest) -> Option<String> {
    // Check Authorization: Bearer <token>
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            let trimmed = auth_str.trim();

            // Check for Bearer token
            if let Some(token) = trimmed.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }

            // Check for Basic auth (used by some package managers)
            if let Some(encoded) = trimmed.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    encoded.trim(),
                ) {
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        // Format is usually "username:password" - use password as API key
                        if let Some((_user, pass)) = decoded_str.split_once(':') {
                            if !pass.is_empty() {
                                return Some(pass.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Check X-API-Key header
    if let Some(key) = req.headers().get("X-API-Key") {
        if let Ok(key_str) = key.to_str() {
            let key = key_str.trim();
            if !key.is_empty() {
                return Some(key.to_string());
            }
        }
    }

    // Check query parameter (less secure, but some tools require it)
    if let Some(key) = req.query_string().split('&').find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let name = parts.next()?;
        let value = parts.next()?;
        if name == "api_key" || name == "token" {
            Some(value.to_string())
        } else {
            None
        }
    }) {
        if !key.is_empty() {
            return Some(key);
        }
    }

    None
}

/// Validates the extracted API key against configured keys using timing-safe comparison
///
/// Security: Uses constant-time comparison to prevent timing attacks
pub fn validate_api_key(req: &HttpRequest, state: &AppState) -> bool {
    let client_ip = get_client_ip(req);
    let ip_str = client_ip.as_deref();

    // Check if API keys are configured
    if state.api_keys.is_empty() {
        warn!("No API keys configured - authentication will always fail");
        log_auth_failure("No API keys configured on server", ip_str);
        return false;
    }

    // Extract API key from request
    let provided_key = match extract_api_key(req) {
        Some(k) => k,
        None => {
            log_auth_failure("No API key provided", ip_str);
            return false;
        }
    };

    // Validate key format (optional, but helps catch obvious issues)
    let format_check = validate_api_key_format(&provided_key);
    if !format_check.passed {
        log_auth_failure(
            &format!("Invalid API key format: {:?}", format_check.errors),
            ip_str,
        );
        return false;
    }

    // Check against all configured keys using timing-safe comparison
    // We iterate through ALL keys to maintain constant time even if early match
    let mut found = false;
    for valid_key in &state.api_keys {
        if secure_compare(&provided_key, valid_key) {
            found = true;
            // Don't break early - continue to maintain constant time
        }
    }

    if !found {
        log_auth_failure("Invalid API key provided", ip_str);
    }

    found
}

/// Returns the validated API key if present and valid, None otherwise
pub fn get_valid_api_key(req: &HttpRequest, state: &AppState) -> Option<String> {
    if validate_api_key(req, state) {
        extract_api_key(req)
    } else {
        None
    }
}

/// Middleware-style function to require authentication
/// Returns an error response if authentication fails, None if successful
pub fn require_auth(req: &HttpRequest, state: &AppState) -> Option<actix_web::HttpResponse> {
    if !validate_api_key(req, state) {
        Some(
            actix_web::HttpResponse::Unauthorized()
                .insert_header(("WWW-Authenticate", "Bearer"))
                .json(serde_json::json!({
                    "error": "Authentication required",
                    "message": "Valid API key required. Provide via Authorization: Bearer <key> or X-API-Key header."
                })),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_extract_api_key_bearer() {
        // Note: These tests would require mocking HttpRequest
        // which is complex in actix-web. In production, use integration tests.
    }
}
