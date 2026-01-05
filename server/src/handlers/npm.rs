use actix_web::{web, HttpRequest, HttpResponse, Responder};
use base64::prelude::*;
use sha1::{Digest, Sha1};
use sha2::Sha512;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tracing::{error, info, warn};

use crate::AppState;
use crate::security::{
    log_malicious_upload, scan_package_content, validate_package_name,
    validate_path_safe, MAX_PACKAGE_SIZE,
};

use super::auth::{get_client_ip, validate_api_key};
use super::registry_types::{
    NpmApiError, NpmDist, NpmPackument, NpmPublishPayload, NpmPublishResponse,
};

/// Helper to get the package storage path
fn get_package_path(data_dir: &str, package_name: &str) -> PathBuf {
    let mut path = PathBuf::from(data_dir).join("npm").join("packages");

    if package_name.starts_with('@') {
        // Scoped package: @scope/name -> @scope/name/
        let parts: Vec<&str> = package_name.splitn(2, '/').collect();
        if parts.len() == 2 {
            path = path.join(parts[0]).join(parts[1]);
        } else {
            path = path.join(package_name);
        }
    } else {
        path = path.join(package_name);
    }

    path
}

/// GET /npm/{package} - Get package metadata (packument)
pub async fn get_packument(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    // Validate API key for private registry
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(NpmApiError::new("authentication required"));
    }

    let package_name = path.into_inner();
    get_packument_internal(&state.data_dir, &package_name, &req).await
}

/// GET /npm/@{scope}/{package} - Get scoped package metadata
pub async fn get_scoped_packument(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    // Validate API key for private registry
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(NpmApiError::new("authentication required"));
    }

    let (scope, package) = path.into_inner();
    let package_name = format!("@{}/{}", scope, package);
    get_packument_internal(&state.data_dir, &package_name, &req).await
}

async fn get_packument_internal(data_dir: &str, package_name: &str, _req: &HttpRequest) -> HttpResponse {
    let package_path = get_package_path(data_dir, package_name);
    let packument_file = package_path.join("packument.json");

    match fs::read_to_string(&packument_file).await {
        Ok(content) => {
            match serde_json::from_str::<NpmPackument>(&content) {
                Ok(packument) => HttpResponse::Ok()
                    .content_type("application/json")
                    .json(packument),
                Err(e) => {
                    error!("Failed to parse packument: {}", e);
                    HttpResponse::InternalServerError()
                        .json(NpmApiError::new("corrupted package metadata"))
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HttpResponse::NotFound().json(NpmApiError::with_reason(
                "not_found",
                &format!("package {} not found", package_name),
            ))
        }
        Err(e) => {
            error!("Failed to read packument {:?}: {}", packument_file, e);
            HttpResponse::InternalServerError()
                .json(NpmApiError::new("failed to read package metadata"))
        }
    }
}

/// PUT /npm/{package} - Publish package
pub async fn publish_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<NpmPublishPayload>,
) -> impl Responder {
    // Validate API key
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(NpmApiError::new("authentication required"));
    }

    let package_name = path.into_inner();
    publish_package_internal(&state.data_dir, &package_name, body.into_inner(), &req).await
}

/// PUT /npm/@{scope}/{package} - Publish scoped package
pub async fn publish_scoped_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Json<NpmPublishPayload>,
) -> impl Responder {
    // Validate API key
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(NpmApiError::new("authentication required"));
    }

    let (scope, package) = path.into_inner();
    let package_name = format!("@{}/{}", scope, package);
    publish_package_internal(&state.data_dir, &package_name, body.into_inner(), &req).await
}

async fn publish_package_internal(
    data_dir: &str,
    package_name: &str,
    payload: NpmPublishPayload,
    req: &HttpRequest,
) -> HttpResponse {
    let client_ip = get_client_ip(req);

    // ========== SECURITY: Validate package name ==========
    let name_check = validate_package_name(package_name, "npm");
    if !name_check.passed {
        warn!("Rejected invalid npm package name '{}': {:?} from {:?}", package_name, name_check.errors, client_ip);
        log_malicious_upload(package_name, &name_check.errors.join(", "), client_ip.as_deref());
        return HttpResponse::BadRequest().json(NpmApiError::with_reason(
            "bad_request",
            &format!("invalid package name: {}", name_check.errors.join(", ")),
        ));
    }

    // Validate package name matches payload
    if payload.name != package_name {
        warn!("Package name mismatch: URL='{}' payload='{}' from {:?}", package_name, payload.name, client_ip);
        return HttpResponse::BadRequest().json(NpmApiError::with_reason(
            "bad_request",
            "package name mismatch",
        ));
    }

    let npm_base = PathBuf::from(data_dir).join("npm");
    let package_path = get_package_path(data_dir, package_name);

    // ========== SECURITY: Validate path is within allowed directory ==========
    let relative_path = package_path.strip_prefix(&npm_base).unwrap_or(&package_path);
    let path_check = validate_path_safe(relative_path, &npm_base);
    if !path_check.passed {
        error!("SECURITY: Path traversal attempt detected for npm package '{}': {:?} from {:?}",
            package_name, path_check.errors, client_ip);
        log_malicious_upload(package_name, &format!("path traversal: {}", path_check.errors.join(", ")), client_ip.as_deref());
        return HttpResponse::BadRequest().json(NpmApiError::with_reason(
            "bad_request",
            "invalid package path",
        ));
    }

    // Create package directory
    if let Err(e) = fs::create_dir_all(&package_path).await {
        error!("Failed to create package directory: {}", e);
        return HttpResponse::InternalServerError()
            .json(NpmApiError::new("failed to create package directory"));
    }

    // Get host for tarball URLs
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if req.connection_info().scheme() == "https" {
        "https"
    } else {
        "http"
    };

    // Process attachments (tarballs)
    for (filename, attachment) in &payload.attachments {
        // ========== SECURITY: Validate filename ==========
        if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
            error!("SECURITY: Invalid tarball filename '{}' from {:?}", filename, client_ip);
            log_malicious_upload(package_name, &format!("invalid filename: {}", filename), client_ip.as_deref());
            return HttpResponse::BadRequest()
                .json(NpmApiError::with_reason("bad_request", "invalid tarball filename"));
        }

        // Decode base64 tarball
        let tarball_data = match BASE64_STANDARD.decode(&attachment.data) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to decode tarball base64: {}", e);
                return HttpResponse::BadRequest()
                    .json(NpmApiError::with_reason("bad_request", "invalid tarball encoding"));
            }
        };

        // ========== SECURITY: Check tarball size ==========
        if tarball_data.len() > MAX_PACKAGE_SIZE {
            warn!("Rejected oversized npm tarball: {} bytes from {:?}", tarball_data.len(), client_ip);
            return HttpResponse::PayloadTooLarge()
                .json(NpmApiError::with_reason("bad_request", "tarball too large"));
        }

        // ========== SECURITY: Scan tarball content ==========
        let security_scan = scan_package_content(&tarball_data, "npm");
        if !security_scan.passed {
            error!("SECURITY: Rejected malicious npm package '{}': {:?} from {:?}",
                package_name, security_scan.errors, client_ip);
            log_malicious_upload(package_name, &security_scan.errors.join(", "), client_ip.as_deref());
            return HttpResponse::BadRequest()
                .json(NpmApiError::with_reason("bad_request", &format!("package rejected: {}", security_scan.errors.join(", "))));
        }

        // Log any warnings from security scan
        for warning in &security_scan.warnings {
            warn!("Security warning for npm package '{}': {}", package_name, warning);
        }

        // Write tarball
        let tarball_path = package_path.join(filename);
        if let Err(e) = fs::write(&tarball_path, &tarball_data).await {
            error!("Failed to write tarball: {}", e);
            return HttpResponse::InternalServerError()
                .json(NpmApiError::new("failed to write tarball"));
        }

        info!("Stored tarball {} ({} bytes)", filename, tarball_data.len());
    }

    // Load existing packument or create new one
    let packument_file = package_path.join("packument.json");
    let mut packument: NpmPackument = if packument_file.exists() {
        match fs::read_to_string(&packument_file).await {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| NpmPackument {
                name: package_name.to_string(),
                dist_tags: HashMap::new(),
                versions: HashMap::new(),
                time: HashMap::new(),
                description: None,
                readme: payload.readme.clone(),
                license: None,
                homepage: None,
                repository: None,
                keywords: None,
                author: None,
                maintainers: None,
            }),
            Err(_) => NpmPackument {
                name: package_name.to_string(),
                dist_tags: HashMap::new(),
                versions: HashMap::new(),
                time: HashMap::new(),
                description: None,
                readme: payload.readme.clone(),
                license: None,
                homepage: None,
                repository: None,
                keywords: None,
                author: None,
                maintainers: None,
            },
        }
    } else {
        NpmPackument {
            name: package_name.to_string(),
            dist_tags: HashMap::new(),
            versions: HashMap::new(),
            time: HashMap::new(),
            description: payload.description.clone(),
            readme: payload.readme.clone(),
            license: None,
            homepage: None,
            repository: None,
            keywords: None,
            author: None,
            maintainers: None,
        }
    };

    // Update time
    let now = chrono::Utc::now().to_rfc3339();
    if packument.time.is_empty() {
        packument.time.insert("created".to_string(), now.clone());
    }
    packument.time.insert("modified".to_string(), now.clone());

    // Merge versions
    for (version, mut version_meta) in payload.versions {
        // Check if version already exists
        if packument.versions.contains_key(&version) {
            return HttpResponse::Conflict().json(NpmApiError::with_reason(
                "conflict",
                &format!("version {} already exists", version),
            ));
        }

        // Calculate checksums and update dist
        let tarball_name = format!("{}-{}.tgz", package_name.replace('/', "-").trim_start_matches('@'), version);
        let tarball_path = package_path.join(&tarball_name);

        if let Ok(tarball_data) = fs::read(&tarball_path).await {
            let shasum = hex::encode(Sha1::digest(&tarball_data));
            let integrity = format!(
                "sha512-{}",
                BASE64_STANDARD.encode(Sha512::digest(&tarball_data))
            );

            // Build tarball URL
            let tarball_url = if package_name.starts_with('@') {
                format!(
                    "{}://{}/npm/{}/-/{}",
                    scheme, host, package_name, tarball_name
                )
            } else {
                format!(
                    "{}://{}/npm/{}/-/{}",
                    scheme, host, package_name, tarball_name
                )
            };

            version_meta.dist = NpmDist {
                tarball: tarball_url,
                shasum,
                integrity: Some(integrity),
                file_count: None,
                unpacked_size: None,
            };
        }

        packument.time.insert(version.clone(), now.clone());
        packument.versions.insert(version.clone(), version_meta);
    }

    // Update dist-tags
    for (tag, version) in payload.dist_tags {
        packument.dist_tags.insert(tag, version);
    }

    // Update description if provided
    if let Some(desc) = &payload.description {
        packument.description = Some(desc.clone());
    }

    // Write packument
    let packument_json = match serde_json::to_string_pretty(&packument) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize packument: {}", e);
            return HttpResponse::InternalServerError()
                .json(NpmApiError::new("failed to update package metadata"));
        }
    };

    if let Err(e) = fs::write(&packument_file, packument_json).await {
        error!("Failed to write packument: {}", e);
        return HttpResponse::InternalServerError()
            .json(NpmApiError::new("failed to write package metadata"));
    }

    info!("Published package {}", package_name);

    HttpResponse::Ok().json(NpmPublishResponse {
        ok: true,
        id: Some(package_name.to_string()),
        rev: None,
    })
}

/// GET /npm/{package}/-/{tarball} - Download tarball
pub async fn download_tarball(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    // Validate API key for private registry
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(NpmApiError::new("authentication required"));
    }

    let (package_name, tarball) = path.into_inner();
    download_tarball_internal(&state.data_dir, &package_name, &tarball).await
}

/// GET /npm/@{scope}/{package}/-/{tarball} - Download scoped tarball
pub async fn download_scoped_tarball(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    // Validate API key for private registry
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(NpmApiError::new("authentication required"));
    }

    let (scope, package, tarball) = path.into_inner();
    let package_name = format!("@{}/{}", scope, package);
    download_tarball_internal(&state.data_dir, &package_name, &tarball).await
}

async fn download_tarball_internal(data_dir: &str, package_name: &str, tarball: &str) -> HttpResponse {
    let package_path = get_package_path(data_dir, package_name);
    let tarball_path = package_path.join(tarball);

    match fs::read(&tarball_path).await {
        Ok(data) => HttpResponse::Ok()
            .content_type("application/gzip")
            .body(data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HttpResponse::NotFound().json(NpmApiError::with_reason(
                "not_found",
                &format!("tarball {} not found", tarball),
            ))
        }
        Err(e) => {
            error!("Failed to read tarball {:?}: {}", tarball_path, e);
            HttpResponse::InternalServerError()
                .json(NpmApiError::new("failed to read tarball"))
        }
    }
}

/// GET /npm/-/all - List all packages (for compatibility)
pub async fn list_packages(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(NpmApiError::new("authentication required"));
    }

    let npm_dir = PathBuf::from(&state.data_dir).join("npm").join("packages");

    let mut packages: HashMap<String, serde_json::Value> = HashMap::new();

    if let Ok(entries) = collect_npm_packages(&npm_dir).await {
        for (name, packument) in entries {
            packages.insert(
                name,
                serde_json::json!({
                    "name": packument.name,
                    "description": packument.description,
                    "dist-tags": packument.dist_tags,
                    "versions": packument.versions.keys().collect::<Vec<_>>()
                }),
            );
        }
    }

    HttpResponse::Ok().json(packages)
}

/// Recursively collect npm packages from directory
async fn collect_npm_packages(
    dir: &std::path::Path,
) -> Result<Vec<(String, NpmPackument)>, std::io::Error> {
    let mut packages = Vec::new();

    if !dir.exists() {
        return Ok(packages);
    }

    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        let file_name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_dir() {
            if file_name.starts_with('@') {
                // Scoped packages - recurse with scope prefix
                let scope_dir = entry.path();
                let mut scope_entries = fs::read_dir(&scope_dir).await?;

                while let Some(pkg_entry) = scope_entries.next_entry().await? {
                    let pkg_path = pkg_entry.path();
                    let packument_path = pkg_path.join("packument.json");

                    if packument_path.exists() {
                        if let Ok(content) = fs::read_to_string(&packument_path).await {
                            if let Ok(packument) = serde_json::from_str::<NpmPackument>(&content) {
                                let pkg_name = pkg_entry.file_name().to_string_lossy().to_string();
                                let full_name = format!("{}/{}", file_name, pkg_name);
                                packages.push((full_name, packument));
                            }
                        }
                    }
                }
            } else {
                // Unscoped package
                let packument_path = entry.path().join("packument.json");

                if packument_path.exists() {
                    if let Ok(content) = fs::read_to_string(&packument_path).await {
                        if let Ok(packument) = serde_json::from_str::<NpmPackument>(&content) {
                            packages.push((file_name, packument));
                        }
                    }
                }
            }
        }
    }

    Ok(packages)
}
