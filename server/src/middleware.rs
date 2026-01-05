//! Security middleware for the package repository server
//!
//! This module provides defense-in-depth security through HTTP headers and request tracking.

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::Error;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::task::{Context, Poll};
use tracing::{debug, info_span};
use uuid::Uuid;

// ============================================================================
// Security Headers Middleware
// ============================================================================

/// Security headers middleware that adds comprehensive HTTP security headers
/// to all responses. These headers provide defense-in-depth against various
/// web-based attacks.
pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SecurityHeadersMiddleware { service })
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            let headers = res.headers_mut();

            // Prevent clickjacking attacks
            // Only allow this site to frame itself
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("SAMEORIGIN"),
            );

            // Prevent MIME type sniffing attacks
            // Force browser to use declared content-type
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );

            // Enable XSS protection in older browsers
            // Modern browsers have this built-in but header doesn't hurt
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("1; mode=block"),
            );

            // Prevent information leakage through referrer
            // Only send origin (not full URL) to same-origin destinations
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );

            // Content Security Policy
            // Very restrictive - only allow self-hosted resources
            // This is appropriate for an API server
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static(
                    "default-src 'none'; frame-ancestors 'none'; form-action 'none'"
                ),
            );

            // Permissions Policy (formerly Feature-Policy)
            // Disable potentially dangerous browser features
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static(
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
                ),
            );

            // Strict Transport Security
            // Force HTTPS for 1 year, include subdomains
            // Only effective if served over HTTPS
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
            );

            // Prevent caching of sensitive responses
            // Package managers should handle their own caching
            headers.insert(
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
            );

            // Prevent old IE from executing downloads in wrong security context
            headers.insert(
                HeaderName::from_static("x-download-options"),
                HeaderValue::from_static("noopen"),
            );

            // Indicate this is served by our package repo server
            // Helps with debugging, no security info leaked
            headers.insert(
                HeaderName::from_static("x-powered-by"),
                HeaderValue::from_static("package-repo-server"),
            );

            Ok(res)
        })
    }
}

// ============================================================================
// Request ID Middleware
// ============================================================================

/// Request ID middleware that assigns a unique ID to each request
/// for tracking and audit logging purposes.
pub struct RequestId;

impl<S, B> Transform<S, ServiceRequest> for RequestId
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestIdMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestIdMiddleware { service })
    }
}

pub struct RequestIdMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestIdMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Check if client provided a request ID (for correlation)
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Extract request info for logging
        let method = req.method().to_string();
        let path = req.path().to_string();
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Create a span for this request
        let span = info_span!(
            "request",
            request_id = %request_id,
            method = %method,
            path = %path,
            client_ip = %client_ip
        );

        let _guard = span.enter();
        debug!("Processing request");

        let fut = self.service.call(req);
        let request_id_clone = request_id.clone();

        Box::pin(async move {
            let mut res = fut.await?;

            // Add request ID to response headers for client correlation
            res.headers_mut().insert(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str(&request_id_clone)
                    .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
            );

            Ok(res)
        })
    }
}

// ============================================================================
// Rate Limiting Structures (for future implementation)
// ============================================================================

/// Rate limit configuration for different operation types
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window for read operations
    pub read_limit: u32,
    /// Maximum requests per window for write operations
    pub write_limit: u32,
    /// Window duration in seconds
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            read_limit: 1000,   // 1000 reads per window
            write_limit: 100,   // 100 writes per window
            window_seconds: 60, // 1 minute windows
        }
    }
}

// ============================================================================
// Client Fingerprinting (for audit logging)
// ============================================================================

/// Extracts a fingerprint of the client for audit logging
/// This helps identify clients even if they don't authenticate
#[derive(Debug, Clone)]
pub struct ClientFingerprint {
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
}

impl ClientFingerprint {
    /// Extract fingerprint from request
    pub fn from_request(req: &ServiceRequest) -> Self {
        let ip_address = req
            .connection_info()
            .realip_remote_addr()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let accept_language = req
            .headers()
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let accept_encoding = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        ClientFingerprint {
            ip_address,
            user_agent,
            accept_language,
            accept_encoding,
        }
    }

    /// Generate a hash of the fingerprint for grouping similar clients
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.ip_address);
        hasher.update(self.user_agent.as_deref().unwrap_or(""));
        hasher.update(self.accept_language.as_deref().unwrap_or(""));
        hasher.update(self.accept_encoding.as_deref().unwrap_or(""));
        hex::encode(&hasher.finalize()[..8]) // First 8 bytes for brevity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.read_limit, 1000);
        assert_eq!(config.write_limit, 100);
        assert_eq!(config.window_seconds, 60);
    }
}
