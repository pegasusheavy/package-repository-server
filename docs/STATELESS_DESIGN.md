# Stateless Backend Design

## Overview

The Package Repository Server backend is **completely stateless**, meaning it requires no server-side session storage, Redis, or database for authentication state. This provides several benefits:

- **Horizontal Scalability**: Add more servers without shared state concerns
- **No Session Storage**: No Redis, Memcached, or database sessions needed
- **Simplified Deployment**: Deploy anywhere without persistent storage
- **Cloud-Friendly**: Perfect for containers, serverless, and auto-scaling
- **High Availability**: No single point of failure for session storage

## How It Works

### JWT-Based Authentication

All user sessions are managed via **JWT (JSON Web Tokens)**:

```
Client Request → JWT Token in Header → Server Validates Signature → Allow/Deny
```

- **No database lookups** needed for authentication
- Tokens are **self-contained** with user info and expiration
- Server only needs the **JWT secret** to validate tokens
- Tokens can't be tampered with (cryptographically signed)

### Stateless OAuth2 Flow

The OAuth2 authentication flow is stateless using **encrypted state parameters**:

#### 1. Login Initiation (`/auth/login/{provider}`)

```rust
// Generate PKCE verifier and CSRF token
let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
let csrf_token = CsrfToken::new_random();

// Create state data
let state_data = OAuthStateData {
    pkce_verifier: pkce_verifier.secret().clone(),
    csrf_token: csrf_token.secret().clone(),
    provider: "google",
    created_at: now(),
};

// Encrypt and encode state (AES-256-GCM)
let encrypted_state = state_manager.encode(&state_data);

// Redirect to OAuth provider with encrypted state
redirect_to_provider(encrypted_state);
```

**No server-side storage** - all OAuth state is encrypted into the URL parameter.

#### 2. OAuth Callback (`/auth/callback/{provider}`)

```rust
// Decrypt and validate state parameter
let state_data = state_manager.decode(query.state)?;

// Validate expiration (default: 10 minutes)
if state_data.is_expired() {
    return error("OAuth flow expired");
}

// Use PKCE verifier from decrypted state
let token = exchange_code(code, state_data.pkce_verifier);

// Generate JWT session token
let jwt = jwt_manager.generate_token(user_info);
```

**No database lookups** - state is validated cryptographically.

## Stateless State Management

### Encryption

OAuth state data is encrypted using **AES-256-GCM**:

```rust
pub struct StatelessStateManager {
    encryption_key: [u8; 32],  // Derived from JWT secret
}

impl StatelessStateManager {
    pub fn encode(&self, data: &OAuthStateData) -> Result<String> {
        // 1. Serialize to JSON
        let json = serde_json::to_vec(data)?;
        
        // 2. Generate random nonce (96 bits)
        let nonce = generate_random_nonce();
        
        // 3. Encrypt with AES-256-GCM
        let ciphertext = aes_gcm.encrypt(nonce, json)?;
        
        // 4. Combine nonce + ciphertext
        let combined = [nonce, ciphertext].concat();
        
        // 5. Base64 URL-safe encode
        base64_url_encode(combined)
    }
    
    pub fn decode(&self, encoded: &str) -> Result<OAuthStateData> {
        // 1. Base64 decode
        let combined = base64_url_decode(encoded)?;
        
        // 2. Split nonce and ciphertext
        let (nonce, ciphertext) = combined.split_at(12);
        
        // 3. Decrypt
        let plaintext = aes_gcm.decrypt(nonce, ciphertext)?;
        
        // 4. Deserialize JSON
        let data = serde_json::from_slice(plaintext)?;
        
        // 5. Validate expiration
        if data.is_expired(600) {  // 10 minutes
            return Err("Expired");
        }
        
        Ok(data)
    }
}
```

### Security Properties

- **Authentication**: AES-GCM provides authenticated encryption
- **Integrity**: Any tampering is detected during decryption
- **Confidentiality**: State data is encrypted and unreadable
- **Time-Bounded**: Automatic expiration (default: 10 minutes)
- **Non-Replayable**: Each state is single-use (OAuth code can only be exchanged once)

## Benefits of Stateless Design

### 1. Horizontal Scalability

```
                    ┌──────────────┐
                    │ Load Balancer│
                    └──────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐        ┌────▼────┐       ┌────▼────┐
   │ Server 1│        │ Server 2│       │ Server 3│
   └─────────┘        └─────────┘       └─────────┘
   
   No shared session storage needed!
   Each server can validate tokens independently.
```

**Add servers without configuration changes** - no session replication, no sticky sessions.

### 2. Simplified Deployment

**No Infrastructure Dependencies:**
- ❌ No Redis cluster
- ❌ No Memcached
- ❌ No session database
- ❌ No distributed cache
- ✅ Just the application server

**Docker Compose Example:**
```yaml
services:
  package-repo:
    image: package-repo-server
    environment:
      - SSO_JWT_SECRET=${JWT_SECRET}
    replicas: 3  # Scale instantly!
```

### 3. Cloud Native

Perfect for:
- **Kubernetes**: StatefulSets not needed
- **AWS Lambda**: Truly serverless authentication
- **Cloud Run**: Instant scale to zero
- **Azure Container Instances**: No persistent storage
- **DigitalOcean App Platform**: Simplified deployment

### 4. High Availability

```
┌─────────────────────────────────────────────────┐
│  Traditional (Stateful)                         │
├─────────────────────────────────────────────────┤
│  App Server ──→ Session Store (Redis)           │
│                      ↓                           │
│              Single Point of Failure            │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Stateless (This Implementation)                │
├─────────────────────────────────────────────────┤
│  App Server ──→ Self-Contained JWT              │
│                      ↓                           │
│              No External Dependencies           │
└─────────────────────────────────────────────────┘
```

## Configuration

### Required Environment Variables

Only **one secret** is needed for all stateless operations:

```bash
# JWT secret for signing tokens AND encrypting OAuth state
SSO_JWT_SECRET=$(openssl rand -hex 32)
```

The same secret is used for:
1. **JWT token signing** (HS256)
2. **OAuth state encryption** (AES-256-GCM key derivation)

### No Additional Configuration Needed

Unlike stateful systems, no need for:
```bash
# ❌ Not needed
REDIS_URL=redis://localhost:6379
SESSION_STORE_TYPE=redis
SESSION_COOKIE_SECRET=xyz
MEMCACHED_SERVERS=localhost:11211
```

## Token Lifecycle

### JWT Session Tokens

```
┌──────────────────────────────────────────────────┐
│ 1. User logs in via SSO                          │
│    ↓                                              │
│ 2. Server generates JWT                          │
│    - User info (email, name)                     │
│    - Provider (google, github, etc.)             │
│    - Expiration (default: 24 hours)              │
│    ↓                                              │
│ 3. Client stores JWT (localStorage)              │
│    ↓                                              │
│ 4. Client includes JWT in API requests           │
│    Authorization: Bearer <JWT>                   │
│    ↓                                              │
│ 5. Server validates JWT signature                │
│    - No database lookup needed                   │
│    - Check expiration                            │
│    - Extract user info from token                │
│    ↓                                              │
│ 6. Allow/deny request                            │
└──────────────────────────────────────────────────┘
```

### OAuth State Tokens

```
┌──────────────────────────────────────────────────┐
│ 1. Initiate login                                │
│    ↓                                              │
│ 2. Generate PKCE verifier + CSRF token           │
│    ↓                                              │
│ 3. Encrypt state data                            │
│    - PKCE verifier                               │
│    - CSRF token                                  │
│    - Provider                                    │
│    - Timestamp                                   │
│    ↓                                              │
│ 4. Redirect to OAuth provider with encrypted     │
│    state in URL                                  │
│    ↓                                              │
│ 5. OAuth provider redirects back with state      │
│    ↓                                              │
│ 6. Decrypt and validate state                    │
│    - Check expiration (10 minutes)               │
│    - Verify provider matches                     │
│    - Extract PKCE verifier                       │
│    ↓                                              │
│ 7. Exchange code for token using PKCE            │
│    ↓                                              │
│ 8. Generate JWT session token                    │
└──────────────────────────────────────────────────┘
```

## Security Considerations

### Token Security

**JWT Tokens:**
- Signed with HMAC-SHA256
- Can't be modified without detection
- Contain expiration timestamp
- Should be transmitted over HTTPS only

**OAuth State:**
- Encrypted with AES-256-GCM
- Authenticated encryption (tamper-proof)
- Short-lived (10 minutes max)
- Single-use (OAuth code is one-time)

### Secret Management

**Critical:** The `SSO_JWT_SECRET` is the only secret needed:

```bash
# Generate a strong secret
SSO_JWT_SECRET=$(openssl rand -hex 32)

# Store securely
# - Environment variable
# - Kubernetes Secret
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault
```

**Never:**
- ❌ Commit secrets to git
- ❌ Log secrets
- ❌ Share secrets in plaintext
- ❌ Use weak/short secrets

**Rotation:**
```bash
# Generate new secret
NEW_SECRET=$(openssl rand -hex 32)

# Update environment variable
SSO_JWT_SECRET=$NEW_SECRET

# Restart servers
# Note: All existing sessions will be invalidated
```

### HTTPS Requirement

**Stateless design requires HTTPS** to protect tokens in transit:

```bash
# Production configuration
SSO_COOKIE_SECURE=true  # HTTPS-only cookies
SSO_BASE_URL=https://packages.example.com  # HTTPS required
```

## Performance

### No Database Lookups

Traditional stateful authentication:
```
Request → Validate token → Query session DB → Check expiration → Allow
          (50-100ms typical for DB query)
```

Stateless authentication:
```
Request → Validate signature → Check expiration → Allow
          (<1ms - pure cryptography)
```

**Result:** 50-100x faster authentication checks.

### Memory Efficiency

**Stateful:**
- Session data stored per user
- Typical: 1-10 KB per session
- 10,000 users = 10-100 MB RAM

**Stateless:**
- No session storage
- Constant memory usage
- Scales to millions of users

## Comparison

| Feature | Stateful | Stateless (This Implementation) |
|---------|----------|--------------------------------|
| Session Storage | Redis/DB required | None needed |
| Horizontal Scaling | Complex (sticky sessions) | Simple (any server) |
| Deployment | Multi-component | Single binary |
| Latency | 50-100ms (DB query) | <1ms (crypto only) |
| Infrastructure | App + Redis/DB | App only |
| High Availability | Requires Redis cluster | Built-in |
| Cost | Higher (storage + compute) | Lower (compute only) |
| Serverless Compatible | No | Yes |

## Load Balancer Configuration

### No Sticky Sessions Required

**Traditional:**
```nginx
upstream backend {
    ip_hash;  # Sticky sessions required!
    server backend1:8080;
    server backend2:8080;
    server backend3:8080;
}
```

**Stateless:**
```nginx
upstream backend {
    least_conn;  # Any algorithm works!
    server backend1:8080;
    server backend2:8080;
    server backend3:8080;
}
```

## Testing Stateless Behavior

### Verify No Shared State

1. Start multiple instances:
```bash
# Terminal 1
PORT=8080 ./package-repo-server

# Terminal 2  
PORT=8081 ./package-repo-server

# Terminal 3
PORT=8082 ./package-repo-server
```

2. Login through instance 1:
```bash
# Get token from instance 1
TOKEN=$(curl http://localhost:8080/auth/... | jq -r .token)
```

3. Use token with different instances:
```bash
# Use token with instance 2
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/v1/packages

# Use token with instance 3
curl -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/v1/packages

# Both work! No shared state needed.
```

## Kubernetes Deployment Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: package-repo
spec:
  replicas: 5  # Scale freely!
  selector:
    matchLabels:
      app: package-repo
  template:
    metadata:
      labels:
        app: package-repo
    spec:
      containers:
      - name: package-repo
        image: package-repo-server:latest
        env:
        - name: SSO_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: sso-secret
              key: jwt-secret
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: package-repo
spec:
  type: LoadBalancer
  selector:
    app: package-repo
  ports:
  - port: 80
    targetPort: 8080
```

**No StatefulSet needed!** Use a regular Deployment and scale instantly.

## Conclusion

The stateless design makes the Package Repository Server:

- ✅ **Easier to deploy** (no external dependencies)
- ✅ **Faster** (no database lookups)
- ✅ **More scalable** (add servers instantly)
- ✅ **More reliable** (no session store failures)
- ✅ **Cloud-native** (perfect for containers)
- ✅ **Cost-effective** (fewer infrastructure components)

All while maintaining **enterprise-grade security** through cryptographic validation.
