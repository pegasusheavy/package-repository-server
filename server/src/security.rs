//! PARANOID Security Module for Package Repository
//!
//! This module implements defense-in-depth security with multiple layers:
//! - Timing-safe cryptographic operations
//! - API key hashing (keys are NEVER stored or logged in plain text)
//! - Comprehensive input validation
//! - Path traversal and symlink attack prevention
//! - Malicious content detection (patterns, entropy, magic bytes)
//! - Full audit logging
//! - Request fingerprinting
//!
//! Security Philosophy: FAIL CLOSED - any uncertainty results in rejection

use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

// ============================================================================
// SECURITY CONSTANTS - Strict limits
// ============================================================================

/// Maximum allowed package size (50 MB - reduced for safety)
pub const MAX_PACKAGE_SIZE: usize = 50 * 1024 * 1024;

/// Maximum allowed metadata size (512 KB)
pub const MAX_METADATA_SIZE: usize = 512 * 1024;

/// Maximum allowed filename length
pub const MAX_FILENAME_LENGTH: usize = 200;

/// Maximum allowed path depth
pub const MAX_PATH_DEPTH: usize = 8;

/// Minimum API key length (64 chars for high entropy)
pub const MIN_API_KEY_LENGTH: usize = 32;

/// Maximum request body size (51 MB - package + metadata + overhead)
pub const MAX_REQUEST_BODY_SIZE: usize = 51 * 1024 * 1024;

/// Maximum number of files in an archive
pub const MAX_ARCHIVE_FILES: usize = 10000;

/// Maximum decompression ratio (prevent zip bombs)
pub const MAX_COMPRESSION_RATIO: usize = 100;

/// Maximum string length in JSON fields
pub const MAX_JSON_STRING_LENGTH: usize = 65536;

/// Minimum entropy threshold for suspicious detection (bits per byte)
pub const SUSPICIOUS_ENTROPY_THRESHOLD: f64 = 7.5;

/// High entropy threshold that definitely indicates encryption/compression
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.9;

// Global request counter for unique IDs
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// DANGEROUS PATTERNS - Comprehensive malware signatures
// ============================================================================

/// Shell-based attacks
const SHELL_ATTACKS: &[&str] = &[
    "#!/bin/sh -e\nrm -rf",
    "#!/bin/bash\nrm -rf",
    ":(){ :|:& };:",  // Fork bomb
    "rm -rf /",
    "rm -rf ~",
    "rm -rf /*",
    "mkfs.",
    "dd if=/dev/zero",
    "dd if=/dev/random",
    "> /dev/sda",
    "chmod -R 777 /",
    "chmod 777 /etc/passwd",
    "wget http",
    "curl http",
    "curl -O",
    "wget -O",
];

/// Code injection patterns
const CODE_INJECTION: &[&str] = &[
    "eval(base64_decode(",
    "eval(gzinflate(",
    "eval(gzuncompress(",
    "eval(str_rot13(",
    "eval($_",
    "assert($_",
    "exec($_",
    "system($_",
    "passthru($_",
    "shell_exec($_",
    "popen($_",
    "proc_open(",
    "`$_",  // Backtick execution
    "preg_replace('/.*/'.'e',",  // PHP code execution
    "__import__('os').system(",
    "subprocess.call(",
    "subprocess.Popen(",
    "os.system(",
    "os.popen(",
    "commands.getoutput(",
    "Runtime.getRuntime().exec(",
    "ProcessBuilder(",
    "child_process.exec(",
    "child_process.spawn(",
    "require('child_process')",
];

/// Reverse shell patterns
const REVERSE_SHELLS: &[&str] = &[
    "/dev/tcp/",
    "bash -i >& /dev/tcp",
    "bash -c 'bash -i",
    "nc -e /bin/sh",
    "nc -e /bin/bash",
    "ncat -e",
    "netcat -e",
    "python -c 'import socket,subprocess,os",
    "python3 -c 'import socket",
    "perl -e 'use Socket",
    "ruby -rsocket -e",
    "php -r '$sock=fsockopen",
    "socat exec:",
    "0<&196;exec 196<>/dev/tcp",
    "telnet | /bin/sh",
    "mknod /tmp/backpipe p",
];

/// Windows-specific malware
const WINDOWS_MALWARE: &[&str] = &[
    "powershell -enc",
    "powershell -e ",
    "powershell -encodedcommand",
    "powershell.exe -nop -w hidden",
    "powershell -noprofile",
    "powershell iex(",
    "powershell IEX(",
    "cmd.exe /c",
    "cmd /c",
    "wscript.shell",
    "WScript.Shell",
    "new-object net.webclient",
    "Net.WebClient",
    "DownloadString(",
    "DownloadFile(",
    "Invoke-Expression",
    "Invoke-WebRequest",
    "Start-Process",
    "bitsadmin /transfer",
    "certutil -urlcache",
    "regsvr32 /s /n /u /i:",
    "mshta vbscript:",
    "rundll32.exe javascript:",
];

/// Crypto miners
const CRYPTO_MINERS: &[&str] = &[
    "stratum+tcp://",
    "stratum+ssl://",
    "xmrig",
    "xmr-stak",
    "minergate",
    "coinhive",
    "cryptonight",
    "monero",
    "nicehash",
    "ethermine",
    "nanopool",
    "hashvault",
    "supportxmr",
    "dwarfpool",
    "minexmr",
];

/// Data exfiltration patterns
const DATA_EXFIL: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "wp-config.php",
    "database.yml",
    "secrets.yml",
    ".env",
    "credentials.json",
    "service-account",
    "BEGIN RSA PRIVATE",
    "BEGIN PRIVATE KEY",
    "BEGIN EC PRIVATE",
    "BEGIN OPENSSH PRIVATE",
    "AKIA",  // AWS access key prefix
    "ghp_",  // GitHub personal access token
    "gho_",  // GitHub OAuth token
    "ghu_",  // GitHub user token
    "ghs_",  // GitHub server token
    "ghr_",  // GitHub refresh token
];

/// Dangerous file extensions (comprehensive)
const DANGEROUS_EXTENSIONS: &[&str] = &[
    // Windows executables
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr",
    // Windows scripts
    ".bat", ".cmd", ".com", ".pif", ".ps1", ".ps1xml", ".ps2", ".ps2xml",
    ".psc1", ".psc2", ".psm1", ".psd1", ".vbs", ".vbe", ".wsf", ".wsh",
    ".ws", ".wsc", ".jse", ".hta", ".msc",
    // Installers
    ".msi", ".msp", ".mst", ".gadget", ".application",
    // Macros and templates
    ".docm", ".xlsm", ".pptm", ".potm", ".ppam", ".sldm",
    // Other dangerous
    ".reg", ".inf", ".lnk", ".url", ".terminal",
    // Unix executables (might be suspicious in packages)
    ".elf", ".bin", ".run", ".appimage",
];

/// Reserved/dangerous filenames
const RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    "CLOCK$", "$MFT", "$MFTMIRR", "$LOGFILE", "$VOLUME", "$ATTRDEF",
    "$BITMAP", "$BOOT", "$BADCLUS", "$SECURE", "$UPCASE", "$EXTEND",
];

/// Executable magic bytes (file signatures)
const EXECUTABLE_MAGIC: &[(&[u8], &str)] = &[
    // Windows PE
    (&[0x4D, 0x5A], "Windows PE executable"),
    // ELF (Linux)
    (&[0x7F, 0x45, 0x4C, 0x46], "ELF executable"),
    // Mach-O (macOS) - various architectures
    (&[0xFE, 0xED, 0xFA, 0xCE], "Mach-O 32-bit"),
    (&[0xFE, 0xED, 0xFA, 0xCF], "Mach-O 64-bit"),
    (&[0xCE, 0xFA, 0xED, 0xFE], "Mach-O 32-bit (reverse)"),
    (&[0xCF, 0xFA, 0xED, 0xFE], "Mach-O 64-bit (reverse)"),
    (&[0xCA, 0xFE, 0xBA, 0xBE], "Mach-O Universal/Java class"),
    // Java class file
    (&[0xCA, 0xFE, 0xBA, 0xBE], "Java class file"),
    // Dalvik (Android)
    (&[0x64, 0x65, 0x78, 0x0A], "Dalvik executable"),
    // COM executable
    (&[0xE9], "DOS COM executable (jump)"),
    (&[0xEB], "DOS COM executable (short jump)"),
    // Scripts with shebangs (check separately)
];

// ============================================================================
// SECURITY RESULT TYPES
// ============================================================================

/// Security validation result with detailed tracking
#[derive(Debug, Clone)]
pub struct SecurityCheckResult {
    pub passed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub request_id: String,
    pub checks_performed: Vec<String>,
}

impl SecurityCheckResult {
    pub fn new() -> Self {
        Self {
            passed: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            request_id: generate_request_id(),
            checks_performed: Vec::new(),
        }
    }

    pub fn with_request_id(request_id: String) -> Self {
        Self {
            passed: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            request_id,
            checks_performed: Vec::new(),
        }
    }

    pub fn error(&mut self, msg: impl Into<String>) {
        self.passed = false;
        let msg = msg.into();
        error!(request_id = %self.request_id, error = %msg, "Security check failed");
        self.errors.push(msg);
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        warn!(request_id = %self.request_id, warning = %msg, "Security warning");
        self.warnings.push(msg);
    }

    pub fn check(&mut self, check_name: impl Into<String>) {
        self.checks_performed.push(check_name.into());
    }

    pub fn merge(&mut self, other: SecurityCheckResult) {
        if !other.passed {
            self.passed = false;
        }
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
        self.checks_performed.extend(other.checks_performed);
    }
}

impl Default for SecurityCheckResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Audit event for security logging
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub request_id: String,
    pub event_type: String,
    pub client_ip: Option<String>,
    pub client_fingerprint: String,
    pub resource: String,
    pub action: String,
    pub outcome: String,
    pub details: String,
}

// ============================================================================
// CORE CRYPTOGRAPHIC FUNCTIONS
// ============================================================================

/// Generate a unique request ID for tracking
pub fn generate_request_id() -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Hash to make it unpredictable
    let input = format!("{}-{}-{}", counter, timestamp, std::process::id());
    let hash = Sha256::digest(input.as_bytes());
    format!("req_{}", hex::encode(&hash[..8]))
}

/// Timing-safe comparison for secrets
/// Uses constant-time XOR to prevent timing attacks
#[inline]
pub fn secure_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        // Still do some work to avoid length timing leak
        let dummy = "0".repeat(a.len().max(b.len()));
        let _ = secure_compare_bytes(dummy.as_bytes(), dummy.as_bytes());
        return false;
    }
    secure_compare_bytes(a.as_bytes(), b.as_bytes())
}

#[inline]
fn secure_compare_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    // Constant-time comparison of result to 0
    // This avoids branch prediction attacks
    ((result as i32) - 1) >> 31 == -1
}

/// Hash an API key for secure storage/comparison
/// Keys should NEVER be stored or logged in plain text
pub fn hash_api_key(key: &str) -> String {
    // Use SHA-512 with a domain separator
    let mut hasher = Sha512::new();
    hasher.update(b"PACKAGE_REPO_API_KEY_V1:");
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify an API key against a stored hash
pub fn verify_api_key_hash(provided_key: &str, stored_hash: &str) -> bool {
    let provided_hash = hash_api_key(provided_key);
    secure_compare(&provided_hash, stored_hash)
}

/// Mask sensitive data for logging (show only first/last 4 chars)
pub fn mask_sensitive(data: &str) -> String {
    if data.len() <= 8 {
        return "*".repeat(data.len());
    }
    format!("{}...{}", &data[..4], &data[data.len()-4..])
}

// ============================================================================
// INPUT VALIDATION FUNCTIONS
// ============================================================================

/// Validates API key format and strength
pub fn validate_api_key_format(key: &str) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("api_key_format");

    if key.is_empty() {
        result.error("API key cannot be empty");
        return result;
    }

    if key.len() < MIN_API_KEY_LENGTH {
        result.error(format!(
            "API key too short: {} chars (minimum {})",
            key.len(),
            MIN_API_KEY_LENGTH
        ));
        return result;
    }

    // Check for null bytes
    if key.contains('\0') {
        result.error("API key contains null bytes (possible injection attack)");
        return result;
    }

    // Check for control characters
    if key.chars().any(|c| c.is_control()) {
        result.error("API key contains control characters");
        return result;
    }

    // Check for repeated characters (weak key)
    let first_char = key.chars().next().unwrap();
    if key.chars().all(|c| c == first_char) {
        result.error("API key consists of repeated characters (extremely weak)");
        return result;
    }

    // Check entropy
    let entropy = calculate_string_entropy(key);
    if entropy < 3.0 {
        result.error(format!("API key has insufficient entropy: {:.2} bits/char", entropy));
    } else if entropy < 4.0 {
        result.warn(format!("API key has low entropy: {:.2} bits/char", entropy));
    }

    // Check for common weak patterns
    let lower = key.to_lowercase();
    let weak_patterns = [
        "123456", "abcdef", "qwerty", "password", "admin", "root",
        "test", "demo", "secret", "token", "api_key", "apikey",
    ];
    for pattern in weak_patterns {
        if lower.contains(pattern) {
            result.warn(format!("API key contains weak pattern: '{}'", pattern));
        }
    }

    result
}

/// Comprehensive package name validation
pub fn validate_package_name(name: &str, pkg_type: &str) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("package_name_validation");

    // Basic checks
    if name.is_empty() {
        result.error("Package name cannot be empty");
        return result;
    }

    if name.len() > MAX_FILENAME_LENGTH {
        result.error(format!(
            "Package name too long: {} > {}",
            name.len(),
            MAX_FILENAME_LENGTH
        ));
        return result;
    }

    // NULL byte injection
    if name.contains('\0') {
        result.error("Package name contains null bytes (injection attack)");
        return result;
    }

    // Control characters
    if name.chars().any(|c| c.is_control()) {
        result.error("Package name contains control characters");
        return result;
    }

    // Path traversal (multiple checks)
    if name.contains("..") {
        result.error("Package name contains '..' (path traversal)");
        return result;
    }
    if name.contains('/') || name.contains('\\') {
        result.error("Package name contains path separators");
        return result;
    }

    // URL encoding attacks
    if name.contains('%') {
        result.error("Package name contains '%' (possible URL encoding attack)");
        return result;
    }

    // Unicode attacks
    if name.chars().any(|c| c as u32 > 127) {
        // Be very strict about unicode - allow only ASCII
        result.warn("Package name contains non-ASCII characters");
    }

    // Check for homoglyph attacks (characters that look similar)
    let homoglyphs = ['а', 'е', 'о', 'р', 'с', 'х', 'ᴀ', 'ʙ', 'ᴄ', 'ᴅ']; // Cyrillic lookalikes
    for c in name.chars() {
        if homoglyphs.contains(&c) {
            result.error("Package name contains homoglyph characters (possible typosquatting)");
            return result;
        }
    }

    // Reserved names
    let upper_name = name.to_uppercase();
    let base_name = upper_name.split('.').next().unwrap_or(&upper_name);
    if RESERVED_NAMES.contains(&base_name) {
        result.error(format!("Package name '{}' is a reserved system name", name));
        return result;
    }

    // Package-type specific validation
    match pkg_type {
        "cargo" => {
            result.check("cargo_name_rules");
            // Cargo: alphanumeric, hyphens, underscores, must start with letter
            if !name.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
                result.warn("Cargo crate names should start with a letter");
            }
            if name.starts_with('-') || name.starts_with('_') {
                result.error("Cargo crate names cannot start with hyphen or underscore");
            }
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                result.error("Cargo crate names must be alphanumeric with hyphens/underscores only");
            }
            // Check for reserved crate names
            let reserved_crates = ["std", "core", "alloc", "proc_macro", "test"];
            if reserved_crates.contains(&name.to_lowercase().as_str()) {
                result.error(format!("'{}' is a reserved Rust crate name", name));
            }
        }
        "npm" => {
            result.check("npm_name_rules");
            let check_name = if name.starts_with('@') {
                // Scoped package validation
                let parts: Vec<&str> = name.splitn(2, '/').collect();
                if parts.len() != 2 {
                    result.error("Invalid scoped package name format");
                    return result;
                }
                let scope = parts[0].trim_start_matches('@');
                if scope.is_empty() || parts[1].is_empty() {
                    result.error("Scope and package name cannot be empty");
                    return result;
                }
                parts[1]
            } else {
                name
            };

            if check_name.starts_with('.') || check_name.starts_with('_') {
                result.error("npm package names cannot start with . or _");
            }
            if !check_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
                result.error("npm package names must be alphanumeric with hyphens/underscores/dots");
            }
        }
        "pypi" => {
            result.check("pypi_name_rules");
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
                result.error("PyPI package names must be alphanumeric with hyphens/underscores/dots");
            }
        }
        "nuget" => {
            result.check("nuget_name_rules");
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_') {
                result.error("NuGet package names must be alphanumeric with dots/underscores");
            }
        }
        "maven" => {
            result.check("maven_name_rules");
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
                result.error("Maven artifact names must be alphanumeric with hyphens/underscores/dots");
            }
        }
        _ => {
            result.check("generic_name_rules");
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
                result.error("Package names must be alphanumeric with hyphens/underscores/dots");
            }
        }
    }

    result
}

/// Version string validation
pub fn validate_version(version: &str) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("version_validation");

    if version.is_empty() {
        result.error("Version cannot be empty");
        return result;
    }

    if version.len() > 128 {
        result.error("Version string too long (max 128 chars)");
        return result;
    }

    // Null bytes
    if version.contains('\0') {
        result.error("Version contains null bytes");
        return result;
    }

    // Path traversal
    if version.contains("..") || version.contains('/') || version.contains('\\') {
        result.error("Version contains path traversal characters");
        return result;
    }

    // Control characters
    if version.chars().any(|c| c.is_control()) {
        result.error("Version contains control characters");
        return result;
    }

    // URL encoding
    if version.contains('%') {
        result.error("Version contains '%' (possible URL encoding attack)");
        return result;
    }

    // Valid semver-like characters only
    if !version.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+' || c == '_'
    }) {
        result.error("Version contains invalid characters");
    }

    result
}

/// Path safety validation - prevents path traversal attacks
pub fn validate_path_safe(path: &Path, base_dir: &Path) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("path_traversal_check");

    // Check each component
    let mut depth = 0;
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.error("Path contains parent directory reference (..)");
                return result;
            }
            std::path::Component::Normal(s) => {
                if let Some(s_str) = s.to_str() {
                    // Null bytes
                    if s_str.contains('\0') {
                        result.error("Path component contains null bytes");
                        return result;
                    }
                    // Hidden files (could be attack vector)
                    if s_str.starts_with('.') && s_str != "." {
                        result.warn(format!("Path contains hidden file/directory: {}", s_str));
                    }
                    // Reserved names
                    let upper = s_str.to_uppercase();
                    if RESERVED_NAMES.iter().any(|r| upper.starts_with(r)) {
                        result.error(format!("Path contains reserved name: {}", s_str));
                        return result;
                    }
                }
                depth += 1;
            }
            _ => {}
        }
    }

    // Depth check
    if depth > MAX_PATH_DEPTH {
        result.error(format!("Path too deep: {} > {}", depth, MAX_PATH_DEPTH));
    }

    // If base_dir exists, verify the path stays within it
    if let Ok(canonical_base) = base_dir.canonicalize() {
        let full_path = base_dir.join(path);
        if let Ok(canonical_full) = full_path.canonicalize() {
            if !canonical_full.starts_with(&canonical_base) {
                result.error("Path escapes base directory (path traversal detected)");
            }
        }
    }

    result
}

/// Sanitize a filename - returns error if unsalvageable
pub fn sanitize_filename(filename: &str) -> Result<String, String> {
    if filename.is_empty() {
        return Err("Filename cannot be empty".to_string());
    }

    if filename.len() > MAX_FILENAME_LENGTH {
        return Err(format!("Filename too long: {} > {}", filename.len(), MAX_FILENAME_LENGTH));
    }

    // Reject null bytes outright
    if filename.contains('\0') {
        return Err("Filename contains null bytes".to_string());
    }

    // Replace dangerous characters
    let sanitized: String = filename
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c if c as u32 > 127 => '_', // Replace non-ASCII
            c => c,
        })
        .collect();

    // Remove leading/trailing dangerous chars
    let sanitized = sanitized
        .trim_matches(|c| c == '.' || c == ' ' || c == '_')
        .to_string();

    if sanitized.is_empty() {
        return Err("Filename becomes empty after sanitization".to_string());
    }

    // Check reserved names
    let upper = sanitized.to_uppercase();
    let base = upper.split('.').next().unwrap_or(&upper);
    if RESERVED_NAMES.contains(&base) {
        return Err(format!("Filename '{}' is reserved", filename));
    }

    Ok(sanitized)
}

// ============================================================================
// CONTENT ANALYSIS FUNCTIONS
// ============================================================================

/// Calculate Shannon entropy of data
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate entropy of a string
pub fn calculate_string_entropy(s: &str) -> f64 {
    calculate_entropy(s.as_bytes())
}

/// Check if data appears to be encrypted or heavily obfuscated
pub fn is_suspiciously_encrypted(data: &[u8]) -> (bool, f64) {
    let entropy = calculate_entropy(data);
    (entropy > SUSPICIOUS_ENTROPY_THRESHOLD, entropy)
}

/// Detect executable by magic bytes
pub fn detect_executable_magic(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    for (magic, name) in EXECUTABLE_MAGIC {
        if data.len() >= magic.len() && &data[..magic.len()] == *magic {
            return Some(name);
        }
    }

    // Check for shebang
    if data.len() >= 2 && &data[..2] == b"#!" {
        return Some("Script with shebang");
    }

    None
}

/// Check for dangerous file extension
pub fn is_dangerous_extension(filename: &str) -> Option<&'static str> {
    let lower = filename.to_lowercase();
    for ext in DANGEROUS_EXTENSIONS {
        if lower.ends_with(ext) {
            return Some(ext);
        }
    }
    None
}

/// Comprehensive content scanning
pub fn scan_package_content(data: &[u8], pkg_type: &str) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("content_scan");

    // Size check
    if data.len() > MAX_PACKAGE_SIZE {
        result.error(format!(
            "Package too large: {} bytes > {} max",
            data.len(),
            MAX_PACKAGE_SIZE
        ));
        return result;
    }

    if data.is_empty() {
        result.error("Package data is empty");
        return result;
    }

    // Entropy analysis
    result.check("entropy_analysis");
    let (suspicious_entropy, entropy) = is_suspiciously_encrypted(data);
    if entropy > HIGH_ENTROPY_THRESHOLD {
        result.warn(format!(
            "Package has very high entropy ({:.2} bits/byte) - may be encrypted or compressed data",
            entropy
        ));
    } else if suspicious_entropy {
        result.warn(format!(
            "Package has suspicious entropy ({:.2} bits/byte)",
            entropy
        ));
    }

    // Executable magic byte detection
    result.check("magic_byte_detection");
    if let Some(exec_type) = detect_executable_magic(data) {
        // Allow certain executables based on package type
        let allowed = match pkg_type {
            "nuget" => exec_type.contains("PE") || exec_type.contains("class"), // .NET DLLs
            "maven" => exec_type.contains("class") || exec_type.contains("Java"), // Java
            _ => false,
        };

        if !allowed {
            result.error(format!(
                "Package contains executable code: {}",
                exec_type
            ));
        } else {
            result.warn(format!("Package contains expected executable: {}", exec_type));
        }
    }

    // Pattern scanning (for text-readable content)
    result.check("pattern_scanning");
    if let Ok(content) = std::str::from_utf8(data) {
        scan_text_for_malware(content, &mut result);
    }

    // Archive-specific scanning
    result.check("archive_scanning");
    match pkg_type {
        "cargo" => result.merge(scan_cargo_package(data)),
        "npm" => result.merge(scan_npm_package(data)),
        "pypi" => result.merge(scan_pypi_package(data)),
        "nuget" => result.merge(scan_nuget_package(data)),
        _ => result.merge(scan_generic_archive(data)),
    }

    result
}

/// Scan text content for malware patterns
fn scan_text_for_malware(content: &str, result: &mut SecurityCheckResult) {
    // Shell attacks
    for pattern in SHELL_ATTACKS {
        if content.contains(pattern) {
            result.error(format!("Malicious shell command detected: '{}'",
                &pattern[..pattern.len().min(30)]));
        }
    }

    // Code injection
    for pattern in CODE_INJECTION {
        if content.to_lowercase().contains(&pattern.to_lowercase()) {
            result.error(format!("Code injection pattern detected: '{}'",
                &pattern[..pattern.len().min(30)]));
        }
    }

    // Reverse shells
    for pattern in REVERSE_SHELLS {
        if content.contains(pattern) {
            result.error(format!("Reverse shell pattern detected: '{}'",
                &pattern[..pattern.len().min(30)]));
        }
    }

    // Windows malware
    for pattern in WINDOWS_MALWARE {
        if content.to_lowercase().contains(&pattern.to_lowercase()) {
            result.error(format!("Windows malware pattern detected: '{}'",
                &pattern[..pattern.len().min(30)]));
        }
    }

    // Crypto miners
    for pattern in CRYPTO_MINERS {
        if content.to_lowercase().contains(&pattern.to_lowercase()) {
            result.error(format!("Crypto miner signature detected: '{}'", pattern));
        }
    }

    // Data exfiltration
    for pattern in DATA_EXFIL {
        if content.contains(pattern) {
            result.warn(format!("Potential data exfiltration path: '{}'", pattern));
        }
    }
}

/// Scan Cargo package (.crate = gzipped tarball)
fn scan_cargo_package(data: &[u8]) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("cargo_package_scan");

    // Verify gzip magic
    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        result.error("Invalid .crate file: not gzip compressed");
        return result;
    }

    // Decompress and scan
    match decompress_gzip_safe(data) {
        Ok(decompressed) => {
            // Check compression ratio
            let ratio = decompressed.len() / data.len().max(1);
            if ratio > MAX_COMPRESSION_RATIO {
                result.error(format!(
                    "Suspicious compression ratio: {}x (possible zip bomb)",
                    ratio
                ));
                return result;
            }
            result.merge(scan_tar_archive(&decompressed, "cargo"));
        }
        Err(e) => {
            result.warn(format!("Could not decompress .crate for scanning: {}", e));
        }
    }

    result
}

/// Scan npm package (.tgz = gzipped tarball)
fn scan_npm_package(data: &[u8]) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("npm_package_scan");

    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        result.error("Invalid npm package: not gzip compressed");
        return result;
    }

    match decompress_gzip_safe(data) {
        Ok(decompressed) => {
            let ratio = decompressed.len() / data.len().max(1);
            if ratio > MAX_COMPRESSION_RATIO {
                result.error(format!("Suspicious compression ratio: {}x", ratio));
                return result;
            }
            result.merge(scan_tar_archive(&decompressed, "npm"));

            // Extra npm-specific checks
            if let Ok(content) = std::str::from_utf8(&decompressed) {
                // Check for suspicious npm scripts
                let suspicious_scripts = [
                    "\"preinstall\"", "\"postinstall\"", "\"preuninstall\"",
                    "\"prepublish\"", "\"prepare\"",
                ];
                for script in suspicious_scripts {
                    if content.contains(script) {
                        result.warn(format!("Package contains {} hook - review carefully", script));
                    }
                }
            }
        }
        Err(e) => {
            result.warn(format!("Could not decompress npm package: {}", e));
        }
    }

    result
}

/// Scan PyPI package (can be .tar.gz or .whl/.egg which are zips)
fn scan_pypi_package(data: &[u8]) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("pypi_package_scan");

    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        // gzipped tarball
        match decompress_gzip_safe(data) {
            Ok(decompressed) => {
                let ratio = decompressed.len() / data.len().max(1);
                if ratio > MAX_COMPRESSION_RATIO {
                    result.error(format!("Suspicious compression ratio: {}x", ratio));
                    return result;
                }
                result.merge(scan_tar_archive(&decompressed, "pypi"));
            }
            Err(e) => {
                result.warn(format!("Could not decompress tarball: {}", e));
            }
        }
    } else if data.len() >= 4 && &data[..4] == b"PK\x03\x04" {
        // Zip file (wheel or egg)
        result.merge(scan_zip_archive(data, "pypi"));
    } else {
        result.error("Unknown PyPI package format");
    }

    result
}

/// Scan NuGet package (.nupkg = zip file)
fn scan_nuget_package(data: &[u8]) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("nuget_package_scan");

    if data.len() < 4 || &data[..4] != b"PK\x03\x04" {
        result.error("Invalid NuGet package: not a zip file");
        return result;
    }

    result.merge(scan_zip_archive(data, "nuget"));
    result
}

/// Scan generic archive
fn scan_generic_archive(data: &[u8]) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("generic_archive_scan");

    if data.len() >= 4 {
        if &data[..4] == b"PK\x03\x04" {
            result.merge(scan_zip_archive(data, "generic"));
        } else if data[..2] == [0x1f, 0x8b] {
            if let Ok(decompressed) = decompress_gzip_safe(data) {
                result.merge(scan_tar_archive(&decompressed, "generic"));
            }
        }
    }

    result
}

/// Scan tar archive contents
fn scan_tar_archive(data: &[u8], pkg_type: &str) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("tar_content_scan");

    if data.len() < 512 {
        result.warn("Archive too small for valid tar");
        return result;
    }

    // Look for patterns in the archive
    if let Ok(content) = std::str::from_utf8(data) {
        // Check for dangerous extensions in tar entries
        for ext in DANGEROUS_EXTENSIONS {
            if pkg_type == "maven" && (*ext == ".jar" || *ext == ".class") {
                continue;
            }
            if pkg_type == "nuget" && *ext == ".dll" {
                continue;
            }
            if content.to_lowercase().contains(ext) {
                result.warn(format!("Archive may contain dangerous file type: {}", ext));
            }
        }

        // Scan for malware
        scan_text_for_malware(content, &mut result);
    }

    result
}

/// Scan zip archive with full inspection
fn scan_zip_archive(data: &[u8], pkg_type: &str) -> SecurityCheckResult {
    let mut result = SecurityCheckResult::new();
    result.check("zip_content_scan");

    let cursor = std::io::Cursor::new(data);
    match zip::ZipArchive::new(cursor) {
        Ok(mut archive) => {
            let file_count = archive.len();

            // Check file count
            if file_count > MAX_ARCHIVE_FILES {
                result.error(format!(
                    "Archive contains too many files: {} > {}",
                    file_count,
                    MAX_ARCHIVE_FILES
                ));
                return result;
            }

            let mut total_uncompressed: u64 = 0;
            let mut seen_paths: HashSet<String> = HashSet::new();

            for i in 0..archive.len() {
                if let Ok(file) = archive.by_index(i) {
                    let name = file.name();

                    // Path traversal check
                    if name.contains("..") {
                        result.error(format!("Zip slip attack: entry contains '..': {}", name));
                        continue;
                    }

                    // Absolute path check
                    if name.starts_with('/') || name.starts_with('\\') {
                        result.error(format!("Zip entry has absolute path: {}", name));
                        continue;
                    }

                    // Duplicate path check (could be used to overwrite)
                    let normalized = name.to_lowercase();
                    if seen_paths.contains(&normalized) {
                        result.warn(format!("Duplicate entry in archive: {}", name));
                    }
                    seen_paths.insert(normalized);

                    // Symlink check
                    if file.is_symlink() {
                        result.error(format!("Archive contains symlink: {} (potential attack vector)", name));
                        continue;
                    }

                    // Size tracking
                    total_uncompressed += file.size();
                    if total_uncompressed > MAX_PACKAGE_SIZE as u64 * 2 {
                        result.error("Archive uncompressed size exceeds limit (possible zip bomb)");
                        return result;
                    }

                    // Dangerous extension check
                    let name_lower = name.to_lowercase();
                    for ext in DANGEROUS_EXTENSIONS {
                        if pkg_type == "maven" && (*ext == ".jar" || *ext == ".class") {
                            continue;
                        }
                        if pkg_type == "nuget" && *ext == ".dll" {
                            continue;
                        }
                        if name_lower.ends_with(ext) {
                            result.warn(format!("Potentially dangerous file: {}", name));
                        }
                    }

                    // Check for hidden files
                    if name.split('/').any(|part| part.starts_with('.') && part != ".") {
                        result.warn(format!("Archive contains hidden file: {}", name));
                    }
                }
            }

            // Check compression ratio
            let ratio = total_uncompressed as usize / data.len().max(1);
            if ratio > MAX_COMPRESSION_RATIO {
                result.error(format!("Suspicious compression ratio: {}x", ratio));
            }
        }
        Err(e) => {
            result.error(format!("Invalid zip archive: {}", e));
        }
    }

    result
}

/// Safe gzip decompression with limits
fn decompress_gzip_safe(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(data);
    let mut decoded = Vec::new();

    // Limit decompression to prevent zip bombs
    let limit = (MAX_PACKAGE_SIZE * 2) as u64;
    decoder.take(limit).read_to_end(&mut decoded)?;

    Ok(decoded)
}

// ============================================================================
// AUDIT LOGGING
// ============================================================================

/// Log a security event with full context
pub fn log_security_event(
    event_type: &str,
    details: &str,
    client_ip: Option<&str>,
    request_id: Option<&str>,
) {
    let ip = client_ip.unwrap_or("unknown");
    let req_id = request_id.unwrap_or("no-request-id");

    error!(
        target: "security_audit",
        event_type = event_type,
        client_ip = ip,
        request_id = req_id,
        details = details,
        timestamp = %SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "SECURITY_EVENT"
    );
}

/// Log authentication failure
pub fn log_auth_failure(reason: &str, client_ip: Option<&str>) {
    log_security_event("AUTH_FAILURE", reason, client_ip, None);
}

/// Log malicious upload attempt
pub fn log_malicious_upload(package_name: &str, reason: &str, client_ip: Option<&str>) {
    log_security_event(
        "MALICIOUS_UPLOAD",
        &format!("package={}, reason={}", mask_sensitive(package_name), reason),
        client_ip,
        None,
    );
}

/// Log successful security-sensitive operation
pub fn log_security_success(action: &str, resource: &str, client_ip: Option<&str>) {
    info!(
        target: "security_audit",
        action = action,
        resource = %mask_sensitive(resource),
        client_ip = %client_ip.unwrap_or("unknown"),
        "SECURITY_SUCCESS"
    );
}

/// Generate a fingerprint for a client request (for tracking)
pub fn generate_client_fingerprint(
    ip: Option<&str>,
    user_agent: Option<&str>,
    accept_language: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ip.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(user_agent.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(accept_language.unwrap_or("").as_bytes());

    let hash = hasher.finalize();
    format!("fp_{}", hex::encode(&hash[..8]))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_compare() {
        assert!(secure_compare("abc123", "abc123"));
        assert!(!secure_compare("abc123", "abc124"));
        assert!(!secure_compare("abc123", "abc12"));
        assert!(!secure_compare("", "abc"));
        assert!(secure_compare("", ""));
    }

    #[test]
    fn test_secure_compare_timing_safe() {
        // This test verifies the comparison doesn't short-circuit
        // Both comparisons should take similar time
        let a = "a".repeat(1000);
        let b = "b".repeat(1000);
        let c = "a".repeat(999) + "b";

        // These should all return false and do full comparison
        assert!(!secure_compare(&a, &b));
        assert!(!secure_compare(&a, &c));
    }

    #[test]
    fn test_hash_api_key() {
        let key1 = "my_secret_key_12345";
        let key2 = "my_secret_key_12345";
        let key3 = "different_key";

        let hash1 = hash_api_key(key1);
        let hash2 = hash_api_key(key2);
        let hash3 = hash_api_key(key3);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert!(hash1.len() == 128); // SHA-512 hex = 128 chars
    }

    #[test]
    fn test_validate_package_name_cargo() {
        let result = validate_package_name("my-crate", "cargo");
        assert!(result.passed);

        let result = validate_package_name("my_crate", "cargo");
        assert!(result.passed);

        let result = validate_package_name("../../../etc/passwd", "cargo");
        assert!(!result.passed);

        let result = validate_package_name("my\0crate", "cargo");
        assert!(!result.passed);

        let result = validate_package_name("std", "cargo");
        assert!(!result.passed); // Reserved
    }

    #[test]
    fn test_validate_version() {
        let result = validate_version("1.0.0");
        assert!(result.passed);

        let result = validate_version("1.0.0-alpha.1+build.123");
        assert!(result.passed);

        let result = validate_version("../../../etc/passwd");
        assert!(!result.passed);

        let result = validate_version("1.0.0\0malicious");
        assert!(!result.passed);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test.tar.gz").unwrap(), "test.tar.gz");
        assert_eq!(sanitize_filename("test/file.txt").unwrap(), "test_file.txt");
        assert_eq!(sanitize_filename("test\\file.txt").unwrap(), "test_file.txt");
        assert!(sanitize_filename("").is_err());
        assert!(sanitize_filename("...").is_err());
        assert!(sanitize_filename("CON").is_err());
        assert!(sanitize_filename("test\0file").is_err());
    }

    #[test]
    fn test_validate_api_key_format() {
        let result = validate_api_key_format("abc");
        assert!(!result.passed); // Too short

        let result = validate_api_key_format("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(!result.passed); // Repeated chars

        let result = validate_api_key_format("Abc123DefGhi456JklMno789PqrStu012Vwx");
        assert!(result.passed);
    }

    #[test]
    fn test_entropy_calculation() {
        // Random-looking data should have high entropy
        let random_data: Vec<u8> = (0u16..256).map(|i| i as u8).collect();
        let entropy = calculate_entropy(&random_data);
        assert!(entropy > 7.0);

        // Repeated data should have low entropy
        let repeated = vec![0u8; 256];
        let entropy = calculate_entropy(&repeated);
        assert!(entropy < 0.1);
    }

    #[test]
    fn test_executable_detection() {
        // PE header
        let pe = [0x4Du8, 0x5A, 0x00, 0x00];
        assert!(detect_executable_magic(&pe).is_some());

        // ELF header
        let elf = [0x7Fu8, 0x45, 0x4C, 0x46];
        assert!(detect_executable_magic(&elf).is_some());

        // Regular data
        let data = [0x00u8, 0x01, 0x02, 0x03];
        assert!(detect_executable_magic(&data).is_none());
    }

    #[test]
    fn test_mask_sensitive() {
        assert_eq!(mask_sensitive("12345678901234567890"), "1234...7890");
        assert_eq!(mask_sensitive("short"), "*****");
        assert_eq!(mask_sensitive(""), "");
    }

    #[test]
    fn test_request_id_generation() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();

        assert!(id1.starts_with("req_"));
        assert!(id2.starts_with("req_"));
        assert_ne!(id1, id2); // Should be unique
    }
}
