use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Cargo Registry Types
// ============================================================================

/// Cargo registry config.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoConfig {
    /// Download URL template (with {crate} and {version} placeholders)
    pub dl: String,
    /// API endpoint URL
    pub api: String,
    /// Require authentication for all operations
    #[serde(rename = "auth-required")]
    pub auth_required: bool,
}

/// Single version entry in Cargo index (one line of NDJSON)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoIndexEntry {
    pub name: String,
    pub vers: String,
    pub deps: Vec<CargoDependency>,
    /// SHA256 checksum of .crate file
    pub cksum: String,
    pub features: HashMap<String, Vec<String>>,
    pub yanked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<String>,
    /// Index format version (2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features2: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoDependency {
    pub name: String,
    /// Semver requirement
    pub req: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default = "default_true")]
    pub default_features: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// "normal", "dev", "build"
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Renamed dependency (if different from registry name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Registry URL for non-crates.io deps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_kind() -> String {
    "normal".to_string()
}

/// Publish request metadata (from cargo publish)
#[derive(Debug, Clone, Deserialize)]
pub struct CargoPublishMetadata {
    pub name: String,
    pub vers: String,
    pub deps: Vec<CargoDependency>,
    #[serde(default)]
    pub features: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub documentation: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub readme: Option<String>,
    #[serde(default)]
    pub readme_file: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub license_file: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub links: Option<String>,
    #[serde(default)]
    pub features2: Option<HashMap<String, Vec<String>>>,
}

/// Cargo API error response
#[derive(Debug, Serialize)]
pub struct CargoApiError {
    pub errors: Vec<CargoErrorDetail>,
}

#[derive(Debug, Serialize)]
pub struct CargoErrorDetail {
    pub detail: String,
}

impl CargoApiError {
    pub fn new(message: &str) -> Self {
        Self {
            errors: vec![CargoErrorDetail {
                detail: message.to_string(),
            }],
        }
    }
}

/// Cargo API success response for publish
#[derive(Debug, Serialize)]
pub struct CargoPublishResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<CargoWarnings>,
}

#[derive(Debug, Serialize)]
pub struct CargoWarnings {
    #[serde(default)]
    pub invalid_categories: Vec<String>,
    #[serde(default)]
    pub invalid_badges: Vec<String>,
    #[serde(default)]
    pub other: Vec<String>,
}

// ============================================================================
// npm Registry Types
// ============================================================================

/// npm package metadata (packument) - full document with all versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackument {
    pub name: String,
    #[serde(rename = "dist-tags")]
    pub dist_tags: HashMap<String, String>,
    pub versions: HashMap<String, NpmVersionMetadata>,
    /// version -> ISO timestamp
    #[serde(default)]
    pub time: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<NpmRepository>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<NpmPerson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintainers: Option<Vec<NpmPerson>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmVersionMetadata {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "devDependencies", default, skip_serializing_if = "Option::is_none")]
    pub dev_dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "peerDependencies", default, skip_serializing_if = "Option::is_none")]
    pub peer_dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "optionalDependencies", default, skip_serializing_if = "Option::is_none")]
    pub optional_dependencies: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scripts: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engines: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<NpmPerson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<NpmRepository>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    pub dist: NpmDist,
    #[serde(rename = "_id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "_npmUser", default, skip_serializing_if = "Option::is_none")]
    pub npm_user: Option<NpmPerson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmDist {
    /// Download URL for tarball
    pub tarball: String,
    /// SHA1 of tarball
    pub shasum: String,
    /// SRI hash (sha512)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    #[serde(rename = "fileCount", default, skip_serializing_if = "Option::is_none")]
    pub file_count: Option<u64>,
    #[serde(rename = "unpackedSize", default, skip_serializing_if = "Option::is_none")]
    pub unpacked_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NpmRepository {
    Simple(String),
    Detailed {
        #[serde(rename = "type")]
        repo_type: Option<String>,
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        directory: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NpmPerson {
    Simple(String),
    Detailed {
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
}

/// npm publish payload - sent by npm client
#[derive(Debug, Clone, Deserialize)]
pub struct NpmPublishPayload {
    pub name: String,
    #[serde(rename = "dist-tags")]
    pub dist_tags: HashMap<String, String>,
    pub versions: HashMap<String, NpmVersionMetadata>,
    #[serde(rename = "_attachments")]
    pub attachments: HashMap<String, NpmAttachment>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub readme: Option<String>,
    #[serde(default)]
    pub access: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NpmAttachment {
    pub content_type: String,
    /// Base64 encoded tarball
    pub data: String,
    pub length: u64,
}

/// npm API error response
#[derive(Debug, Serialize)]
pub struct NpmApiError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NpmApiError {
    pub fn new(error: &str) -> Self {
        Self {
            error: error.to_string(),
            reason: None,
        }
    }

    pub fn with_reason(error: &str, reason: &str) -> Self {
        Self {
            error: error.to_string(),
            reason: Some(reason.to_string()),
        }
    }
}

/// npm API success response
#[derive(Debug, Serialize)]
pub struct NpmPublishResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}
