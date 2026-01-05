use actix_web::{web, HttpRequest, HttpResponse, Responder};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

use crate::AppState;
use crate::security::{
    log_malicious_upload, scan_package_content, validate_package_name, validate_version,
    validate_path_safe, MAX_PACKAGE_SIZE, MAX_METADATA_SIZE,
};
use crate::utils::cargo_index_path_optimized as get_index_path;

use super::auth::{get_client_ip, validate_api_key};
use super::registry_types::{
    CargoApiError, CargoConfig, CargoIndexEntry, CargoPublishMetadata, CargoPublishResponse,
};

/// GET /cargo/index/config.json - Registry configuration
/// This endpoint does NOT require authentication (needed for cargo to discover the registry)
pub async fn config_json(req: HttpRequest, _state: web::Data<AppState>) -> impl Responder {
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

    let config = CargoConfig {
        dl: format!(
            "{}://{}/cargo/api/v1/crates/{{crate}}/{{version}}/download",
            scheme, host
        ),
        api: format!("{}://{}/cargo", scheme, host),
        auth_required: true,
    };

    HttpResponse::Ok().json(config)
}

/// GET /cargo/index/{path:.*} - Crate metadata (NDJSON format)
/// Requires authentication for private registry
pub async fn crate_metadata(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    // Validate API key for private registry
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(CargoApiError::new("valid API key required"));
    }

    let index_path = path.into_inner();
    let file_path = PathBuf::from(&state.data_dir)
        .join("cargo")
        .join("index")
        .join(&index_path);

    match fs::read_to_string(&file_path).await {
        Ok(content) => HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HttpResponse::NotFound().json(CargoApiError::new("crate not found"))
        }
        Err(e) => {
            error!("Failed to read index file {:?}: {}", file_path, e);
            HttpResponse::InternalServerError()
                .json(CargoApiError::new("failed to read index"))
        }
    }
}

/// POST /cargo/api/v1/crates/new - Publish a new crate
/// Binary protocol: u32 json_len + json + u32 crate_len + .crate data
pub async fn publish_crate(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> impl Responder {
    let client_ip = get_client_ip(&req);

    // ========== SECURITY: Validate API key ==========
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(CargoApiError::new("valid API key required"));
    }

    // ========== SECURITY: Check total payload size ==========
    if body.len() > MAX_PACKAGE_SIZE + MAX_METADATA_SIZE {
        warn!("Rejected oversized payload: {} bytes from {:?}", body.len(), client_ip);
        return HttpResponse::PayloadTooLarge()
            .json(CargoApiError::new("payload too large"));
    }

    if body.len() < 8 {
        return HttpResponse::BadRequest().json(CargoApiError::new("invalid publish payload"));
    }

    // Parse binary format
    let json_len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;

    // ========== SECURITY: Check metadata size limit ==========
    if json_len > MAX_METADATA_SIZE {
        warn!("Rejected oversized metadata: {} bytes from {:?}", json_len, client_ip);
        return HttpResponse::BadRequest()
            .json(CargoApiError::new("metadata too large"));
    }

    if body.len() < 4 + json_len + 4 {
        return HttpResponse::BadRequest().json(CargoApiError::new("invalid publish payload size"));
    }

    let json_data = &body[4..4 + json_len];
    let crate_len =
        u32::from_le_bytes(body[4 + json_len..8 + json_len].try_into().unwrap()) as usize;

    // ========== SECURITY: Check crate size limit ==========
    if crate_len > MAX_PACKAGE_SIZE {
        warn!("Rejected oversized crate: {} bytes from {:?}", crate_len, client_ip);
        return HttpResponse::PayloadTooLarge()
            .json(CargoApiError::new("crate file too large"));
    }

    if body.len() < 8 + json_len + crate_len {
        return HttpResponse::BadRequest()
            .json(CargoApiError::new("incomplete crate data"));
    }

    let crate_data = &body[8 + json_len..8 + json_len + crate_len];

    // Parse metadata
    let metadata: CargoPublishMetadata = match serde_json::from_slice(json_data) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to parse publish metadata: {}", e);
            return HttpResponse::BadRequest()
                .json(CargoApiError::new(&format!("invalid metadata: {}", e)));
        }
    };

    // ========== SECURITY: Validate crate name ==========
    let name = metadata.name.to_lowercase();
    let name_check = validate_package_name(&name, "cargo");
    if !name_check.passed {
        warn!("Rejected invalid crate name '{}': {:?} from {:?}", name, name_check.errors, client_ip);
        log_malicious_upload(&name, &name_check.errors.join(", "), client_ip.as_deref());
        return HttpResponse::BadRequest()
            .json(CargoApiError::new(&format!("invalid crate name: {}", name_check.errors.join(", "))));
    }

    // ========== SECURITY: Validate version ==========
    let version_check = validate_version(&metadata.vers);
    if !version_check.passed {
        warn!("Rejected invalid version '{}': {:?} from {:?}", metadata.vers, version_check.errors, client_ip);
        log_malicious_upload(&name, &format!("invalid version: {}", version_check.errors.join(", ")), client_ip.as_deref());
        return HttpResponse::BadRequest()
            .json(CargoApiError::new(&format!("invalid version: {}", version_check.errors.join(", "))));
    }

    // ========== SECURITY: Scan package content for malicious patterns ==========
    let security_scan = scan_package_content(crate_data, "cargo");
    if !security_scan.passed {
        error!("SECURITY: Rejected malicious crate '{}' v{}: {:?} from {:?}",
            name, metadata.vers, security_scan.errors, client_ip);
        log_malicious_upload(&name, &security_scan.errors.join(", "), client_ip.as_deref());
        return HttpResponse::BadRequest()
            .json(CargoApiError::new(&format!("package rejected: {}", security_scan.errors.join(", "))));
    }

    // Log any warnings from security scan
    for warning in &security_scan.warnings {
        warn!("Security warning for crate '{}' v{}: {}", name, metadata.vers, warning);
    }

    // Calculate SHA256 checksum
    let cksum = hex::encode(Sha256::digest(crate_data));

    // Create storage paths
    let cargo_dir = PathBuf::from(&state.data_dir).join("cargo");
    let crate_relative_path = PathBuf::from("crates").join(&name).join(&metadata.vers);
    let crate_dir = cargo_dir.join(&crate_relative_path);
    let crate_file = crate_dir.join(format!("{}-{}.crate", name, metadata.vers));
    let index_dir = cargo_dir.join("index").join(get_index_path(&name));
    let index_file = index_dir.parent().unwrap().join(&name);

    // ========== SECURITY: Validate paths are within allowed directory ==========
    let path_check = validate_path_safe(&crate_relative_path, &cargo_dir);
    if !path_check.passed {
        error!("SECURITY: Path traversal attempt detected for crate '{}': {:?} from {:?}",
            name, path_check.errors, client_ip);
        log_malicious_upload(&name, &format!("path traversal: {}", path_check.errors.join(", ")), client_ip.as_deref());
        return HttpResponse::BadRequest()
            .json(CargoApiError::new("invalid package path"));
    }

    // Create directories
    if let Err(e) = fs::create_dir_all(&crate_dir).await {
        error!("Failed to create crate directory: {}", e);
        return HttpResponse::InternalServerError()
            .json(CargoApiError::new("failed to create crate directory"));
    }

    if let Err(e) = fs::create_dir_all(index_file.parent().unwrap()).await {
        error!("Failed to create index directory: {}", e);
        return HttpResponse::InternalServerError()
            .json(CargoApiError::new("failed to create index directory"));
    }

    // Write .crate file
    if let Err(e) = fs::write(&crate_file, crate_data).await {
        error!("Failed to write crate file: {}", e);
        return HttpResponse::InternalServerError()
            .json(CargoApiError::new("failed to write crate file"));
    }

    // Create index entry
    let index_entry = CargoIndexEntry {
        name: name.clone(),
        vers: metadata.vers.clone(),
        deps: metadata.deps,
        cksum,
        features: metadata.features,
        yanked: false,
        links: metadata.links,
        v: Some(2),
        features2: metadata.features2,
    };

    let entry_json = match serde_json::to_string(&index_entry) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize index entry: {}", e);
            return HttpResponse::InternalServerError()
                .json(CargoApiError::new("failed to create index entry"));
        }
    };

    // Append to index file (NDJSON format - one JSON per line)
    let mut file = match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&index_file)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open index file: {}", e);
            return HttpResponse::InternalServerError()
                .json(CargoApiError::new("failed to update index"));
        }
    };

    if let Err(e) = file.write_all(format!("{}\n", entry_json).as_bytes()).await {
        error!("Failed to write index entry: {}", e);
        return HttpResponse::InternalServerError()
            .json(CargoApiError::new("failed to write index entry"));
    }

    info!(
        "Published crate {} version {} ({} bytes)",
        name,
        metadata.vers,
        crate_len
    );

    HttpResponse::Ok().json(CargoPublishResponse { warnings: None })
}

/// GET /cargo/api/v1/crates/{crate}/{version}/download - Download .crate file
pub async fn download_crate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    // Validate API key for private registry
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(CargoApiError::new("valid API key required"));
    }

    let (crate_name, version) = path.into_inner();
    let name = crate_name.to_lowercase();

    let crate_file = PathBuf::from(&state.data_dir)
        .join("cargo")
        .join("crates")
        .join(&name)
        .join(&version)
        .join(format!("{}-{}.crate", name, version));

    match fs::read(&crate_file).await {
        Ok(data) => HttpResponse::Ok()
            .content_type("application/x-tar")
            .body(data),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HttpResponse::NotFound().json(CargoApiError::new("crate not found"))
        }
        Err(e) => {
            error!("Failed to read crate file {:?}: {}", crate_file, e);
            HttpResponse::InternalServerError()
                .json(CargoApiError::new("failed to read crate"))
        }
    }
}

/// DELETE /cargo/api/v1/crates/{crate}/{version}/yank - Yank a version
pub async fn yank_crate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(CargoApiError::new("valid API key required"));
    }

    let (crate_name, version) = path.into_inner();
    let name = crate_name.to_lowercase();

    match set_yanked(&state.data_dir, &name, &version, true).await {
        Ok(()) => {
            info!("Yanked crate {} version {}", name, version);
            HttpResponse::Ok().json(serde_json::json!({"ok": true}))
        }
        Err(e) => {
            error!("Failed to yank crate: {}", e);
            HttpResponse::InternalServerError().json(CargoApiError::new(&e))
        }
    }
}

/// PUT /cargo/api/v1/crates/{crate}/{version}/unyank - Unyank a version
pub async fn unyank_crate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(CargoApiError::new("valid API key required"));
    }

    let (crate_name, version) = path.into_inner();
    let name = crate_name.to_lowercase();

    match set_yanked(&state.data_dir, &name, &version, false).await {
        Ok(()) => {
            info!("Unyanked crate {} version {}", name, version);
            HttpResponse::Ok().json(serde_json::json!({"ok": true}))
        }
        Err(e) => {
            error!("Failed to unyank crate: {}", e);
            HttpResponse::InternalServerError().json(CargoApiError::new(&e))
        }
    }
}

/// Helper to set yanked status for a crate version
async fn set_yanked(data_dir: &str, name: &str, version: &str, yanked: bool) -> Result<(), String> {
    let index_path = get_index_path(name);
    let index_file = PathBuf::from(data_dir)
        .join("cargo")
        .join("index")
        .join(&index_path);

    // Read existing index
    let content = fs::read_to_string(&index_file)
        .await
        .map_err(|e| format!("failed to read index: {}", e))?;

    // Parse and update entries
    let mut lines: Vec<String> = Vec::new();
    let mut found = false;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let mut entry: CargoIndexEntry = serde_json::from_str(line)
            .map_err(|e| format!("failed to parse index entry: {}", e))?;

        if entry.vers == version {
            entry.yanked = yanked;
            found = true;
        }

        lines.push(serde_json::to_string(&entry).map_err(|e| format!("failed to serialize: {}", e))?);
    }

    if !found {
        return Err("version not found".to_string());
    }

    // Write updated index
    let new_content = lines.join("\n") + "\n";
    fs::write(&index_file, new_content)
        .await
        .map_err(|e| format!("failed to write index: {}", e))?;

    Ok(())
}

/// GET /cargo/api/v1/crates - List all crates (for packages API compatibility)
pub async fn list_crates(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(CargoApiError::new("valid API key required"));
    }

    let index_dir = PathBuf::from(&state.data_dir).join("cargo").join("index");

    let mut crates: Vec<serde_json::Value> = Vec::new();

    if let Ok(mut entries) = fs::read_dir(&index_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(file_type) = entry.file_type().await {
                if file_type.is_dir() {
                    // Recursively find index files
                    if let Ok(crate_list) = collect_crates_from_dir(entry.path()).await {
                        crates.extend(crate_list);
                    }
                }
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "crates": crates }))
}

/// Recursively collect crate info from index directories
fn collect_crates_from_dir(
    dir: PathBuf,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<serde_json::Value>, std::io::Error>> + Send>> {
    Box::pin(async move {
        let mut crates = Vec::new();
        let mut entries = fs::read_dir(&dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_dir() {
                if let Ok(sub_crates) = collect_crates_from_dir(entry.path()).await {
                    crates.extend(sub_crates);
                }
            } else if file_type.is_file() {
                // This is an index file - parse it
                if let Ok(content) = fs::read_to_string(entry.path()).await {
                    if let Some(last_line) = content.lines().filter(|l| !l.is_empty()).last() {
                        if let Ok(entry) = serde_json::from_str::<CargoIndexEntry>(last_line) {
                            crates.push(serde_json::json!({
                                "name": entry.name,
                                "version": entry.vers,
                                "yanked": entry.yanked
                            }));
                        }
                    }
                }
            }
        }

        Ok(crates)
    })
}
