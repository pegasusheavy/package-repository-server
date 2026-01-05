//! Stateless OAuth State Management
//!
//! This module provides stateless OAuth state management by encoding
//! all necessary OAuth flow data (PKCE verifier, CSRF token) in an
//! encrypted and signed state parameter.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// OAuth state data that needs to persist across the OAuth flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStateData {
    /// PKCE code verifier (needed to complete the OAuth exchange)
    pub pkce_verifier: String,
    
    /// CSRF token for security
    pub csrf_token: String,
    
    /// Provider ID
    pub provider: String,
    
    /// Timestamp when state was created
    pub created_at: i64,
    
    /// Return URL after successful authentication
    pub return_url: Option<String>,
}

impl OAuthStateData {
    /// Create new OAuth state data
    pub fn new(pkce_verifier: String, csrf_token: String, provider: String) -> Self {
        Self {
            pkce_verifier,
            csrf_token,
            provider,
            created_at: Utc::now().timestamp(),
            return_url: None,
        }
    }
    
    /// Check if state has expired (default: 10 minutes)
    pub fn is_expired(&self, max_age_seconds: i64) -> bool {
        let now = Utc::now().timestamp();
        now - self.created_at > max_age_seconds
    }
}

/// Stateless state manager for OAuth flows
pub struct StatelessStateManager {
    encryption_key: [u8; 32],
}

impl StatelessStateManager {
    /// Create a new stateless state manager
    pub fn new(secret: &str) -> Self {
        // Derive encryption key from secret
        let mut hasher = Sha256::new();
        hasher.update(b"OAUTH_STATE_ENCRYPTION:");
        hasher.update(secret.as_bytes());
        let hash = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash[..32]);
        
        Self {
            encryption_key: key,
        }
    }
    
    /// Encode OAuth state data into a URL-safe encrypted string
    pub fn encode(&self, data: &OAuthStateData) -> Result<String, anyhow::Error> {
        // Serialize to JSON
        let json = serde_json::to_vec(data)?;
        
        // Generate random nonce
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let cipher = Aes256Gcm::new(&self.encryption_key.into());
        let ciphertext = cipher
            .encrypt(nonce, json.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        // Combine nonce + ciphertext
        let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        
        // Base64 encode for URL safety
        Ok(URL_SAFE_NO_PAD.encode(&combined))
    }
    
    /// Decode and validate OAuth state data
    pub fn decode(&self, encoded: &str) -> Result<OAuthStateData, anyhow::Error> {
        // Base64 decode
        let combined = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| anyhow::anyhow!("Invalid state encoding: {}", e))?;
        
        if combined.len() < 12 {
            return Err(anyhow::anyhow!("State too short"));
        }
        
        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt
        let cipher = Aes256Gcm::new(&self.encryption_key.into());
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        // Deserialize
        let data: OAuthStateData = serde_json::from_slice(&plaintext)?;
        
        // Validate expiration (10 minutes max)
        if data.is_expired(600) {
            return Err(anyhow::anyhow!("OAuth state expired"));
        }
        
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode_state() {
        let manager = StatelessStateManager::new("test-secret-key");
        
        let data = OAuthStateData::new(
            "pkce_verifier_123".to_string(),
            "csrf_token_456".to_string(),
            "google".to_string(),
        );
        
        let encoded = manager.encode(&data).expect("Failed to encode");
        assert!(!encoded.is_empty());
        
        let decoded = manager.decode(&encoded).expect("Failed to decode");
        assert_eq!(decoded.pkce_verifier, data.pkce_verifier);
        assert_eq!(decoded.csrf_token, data.csrf_token);
        assert_eq!(decoded.provider, data.provider);
    }
    
    #[test]
    fn test_expired_state() {
        let mut data = OAuthStateData::new(
            "verifier".to_string(),
            "token".to_string(),
            "provider".to_string(),
        );
        
        // Set created_at to 11 minutes ago
        data.created_at = Utc::now().timestamp() - 660;
        
        assert!(data.is_expired(600));
    }
    
    #[test]
    fn test_tampering_detection() {
        let manager = StatelessStateManager::new("test-secret");
        
        let data = OAuthStateData::new(
            "verifier".to_string(),
            "token".to_string(),
            "provider".to_string(),
        );
        
        let mut encoded = manager.encode(&data).expect("Failed to encode");
        
        // Tamper with the encoded string
        encoded.push_str("tampered");
        
        // Should fail to decode
        assert!(manager.decode(&encoded).is_err());
    }
}
