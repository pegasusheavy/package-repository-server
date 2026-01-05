use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tracing::{error, info};

use crate::AppState;
use crate::utils::version_compare_optimized;

use super::auth::validate_api_key;

/// PyPI package metadata stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiPackageMetadata {
    pub name: String,
    pub versions: HashMap<String, PypiVersionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiVersionMetadata {
    pub version: String,
    pub summary: Option<String>,
    pub author: Option<String>,
    pub author_email: Option<String>,
    pub license: Option<String>,
    pub requires_python: Option<String>,
    pub requires_dist: Vec<String>,
    pub files: Vec<PypiFileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiFileInfo {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    pub requires_python: Option<String>,
}

/// JSON API response for package info
#[derive(Debug, Serialize)]
struct PypiJsonResponse {
    info: PypiPackageInfo,
    releases: HashMap<String, Vec<PypiReleaseFile>>,
    urls: Vec<PypiReleaseFile>,
}

#[derive(Debug, Serialize)]
struct PypiPackageInfo {
    name: String,
    version: String,
    summary: Option<String>,
    author: Option<String>,
    author_email: Option<String>,
    license: Option<String>,
    requires_python: Option<String>,
    requires_dist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct PypiReleaseFile {
    filename: String,
    url: String,
    size: u64,
    digests: PypiDigests,
    requires_python: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PypiDigests {
    sha256: String,
}

fn get_package_path(data_dir: &str, package_name: &str) -> PathBuf {
    // Normalize package name (PEP 503: lowercase, replace [-_.] with -)
    let normalized = normalize_package_name(package_name);
    PathBuf::from(data_dir).join("pypi").join("packages").join(&normalized)
}

fn normalize_package_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect()
}

/// GET /pypi/simple/ - List all packages (Simple API)
pub async fn simple_index(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().body("Authentication required");
    }

    let packages_dir = PathBuf::from(&state.data_dir).join("pypi").join("packages");

    let mut packages = Vec::new();
    if let Ok(mut entries) = fs::read_dir(&packages_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    packages.push(name.to_string());
                }
            }
        }
    }

    packages.sort();

    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head><title>Simple Index</title></head>\n<body>\n<h1>Simple Index</h1>\n");
    for pkg in packages {
        html.push_str(&format!("<a href=\"/pypi/simple/{}/\">{}</a><br/>\n", pkg, pkg));
    }
    html.push_str("</body>\n</html>");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

/// GET /pypi/simple/{package}/ - List package files (Simple API)
pub async fn simple_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().body("Authentication required");
    }

    let package_name = path.into_inner();
    let normalized = normalize_package_name(&package_name);
    let package_path = get_package_path(&state.data_dir, &package_name);
    let metadata_file = package_path.join("metadata.json");

    let host = req.headers().get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };

    let metadata: PypiPackageMetadata = match fs::read_to_string(&metadata_file).await {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(_) => return HttpResponse::NotFound().body("Package not found"),
        },
        Err(_) => return HttpResponse::NotFound().body("Package not found"),
    };

    let mut html = format!(
        "<!DOCTYPE html>\n<html>\n<head><title>Links for {}</title></head>\n<body>\n<h1>Links for {}</h1>\n",
        normalized, normalized
    );

    for (_, version_meta) in &metadata.versions {
        for file in &version_meta.files {
            let url = format!(
                "{}://{}/pypi/packages/{}/{}/{}#sha256={}",
                scheme, host, normalized, version_meta.version, file.filename, file.sha256
            );
            let mut attrs = format!("href=\"{}\"", url);
            if let Some(ref req_py) = file.requires_python {
                attrs.push_str(&format!(" data-requires-python=\"{}\"", html_escape(req_py)));
            }
            html.push_str(&format!("<a {}>{}</a><br/>\n", attrs, file.filename));
        }
    }

    html.push_str("</body>\n</html>");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// GET /pypi/pypi/{package}/json - Package JSON metadata
pub async fn package_json(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }

    let package_name = path.into_inner();
    get_package_json_internal(&req, &state, &package_name, None).await
}

/// GET /pypi/pypi/{package}/{version}/json - Version JSON metadata
pub async fn version_json(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }

    let (package_name, version) = path.into_inner();
    get_package_json_internal(&req, &state, &package_name, Some(&version)).await
}

async fn get_package_json_internal(
    req: &HttpRequest,
    state: &web::Data<AppState>,
    package_name: &str,
    version_filter: Option<&str>,
) -> HttpResponse {
    let package_path = get_package_path(&state.data_dir, package_name);
    let metadata_file = package_path.join("metadata.json");

    let host = req.headers().get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };

    let metadata: PypiPackageMetadata = match fs::read_to_string(&metadata_file).await {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(_) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Package not found"})),
        },
        Err(_) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Package not found"})),
    };

    let normalized = normalize_package_name(package_name);

    // Get the latest version or the requested version
    let latest_version = if let Some(v) = version_filter {
        v.to_string()
    } else {
        metadata.versions.keys()
            .max_by(|a, b| version_compare(a, b))
            .cloned()
            .unwrap_or_default()
    };

    let version_meta = match metadata.versions.get(&latest_version) {
        Some(v) => v,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Version not found"})),
    };

    // Build releases map
    let mut releases: HashMap<String, Vec<PypiReleaseFile>> = HashMap::new();
    for (ver, ver_meta) in &metadata.versions {
        let files: Vec<PypiReleaseFile> = ver_meta.files.iter().map(|f| {
            PypiReleaseFile {
                filename: f.filename.clone(),
                url: format!("{}://{}/pypi/packages/{}/{}/{}", scheme, host, normalized, ver, f.filename),
                size: f.size,
                digests: PypiDigests { sha256: f.sha256.clone() },
                requires_python: f.requires_python.clone(),
            }
        }).collect();
        releases.insert(ver.clone(), files);
    }

    let urls = releases.get(&latest_version).cloned().unwrap_or_default();

    let response = PypiJsonResponse {
        info: PypiPackageInfo {
            name: metadata.name.clone(),
            version: latest_version,
            summary: version_meta.summary.clone(),
            author: version_meta.author.clone(),
            author_email: version_meta.author_email.clone(),
            license: version_meta.license.clone(),
            requires_python: version_meta.requires_python.clone(),
            requires_dist: if version_meta.requires_dist.is_empty() {
                None
            } else {
                Some(version_meta.requires_dist.clone())
            },
        },
        releases,
        urls,
    };

    HttpResponse::Ok().json(response)
}

fn version_compare(a: &str, b: &str) -> std::cmp::Ordering {
    version_compare_optimized(a, b)
}

/// POST /pypi/ - Upload package (legacy upload API)
pub async fn upload_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    mut payload: Multipart,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().body("Authentication required");
    }

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut author: Option<String> = None;
    let mut author_email: Option<String> = None;
    let mut license: Option<String> = None;
    let mut requires_python: Option<String> = None;
    let mut requires_dist: Vec<String> = Vec::new();
    let mut file_data: Option<(String, Vec<u8>)> = None;

    // Parse multipart form
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                error!("Multipart error: {}", e);
                return HttpResponse::BadRequest().body("Invalid multipart data");
            }
        };

        let field_name = field.name().to_string();

        if field_name == "content" || field_name == ":action" {
            // Skip action field
            continue;
        }

        if field_name == "requires_dist" {
            // Collect all requires_dist values
            let mut value = Vec::new();
            while let Some(chunk) = field.next().await {
                if let Ok(data) = chunk {
                    value.extend_from_slice(&data);
                }
            }
            if let Ok(s) = String::from_utf8(value) {
                if !s.is_empty() {
                    requires_dist.push(s);
                }
            }
            continue;
        }

        let content_disposition = field.content_disposition();
        let filename = content_disposition.get_filename().map(|s| s.to_string());

        let mut data = Vec::new();
        while let Some(chunk) = field.next().await {
            if let Ok(d) = chunk {
                data.extend_from_slice(&d);
            }
        }

        if filename.is_some() && (field_name == "content" || data.len() > 1000) {
            // This is the file upload
            file_data = Some((filename.unwrap_or_else(|| "unknown.tar.gz".to_string()), data));
        } else {
            // This is a form field
            let value = String::from_utf8_lossy(&data).to_string();
            match field_name.as_str() {
                "name" => name = Some(value),
                "version" => version = Some(value),
                "summary" => summary = Some(value),
                "author" => author = Some(value),
                "author_email" => author_email = Some(value),
                "license" => license = Some(value),
                "requires_python" => requires_python = Some(value),
                _ => {}
            }
        }
    }

    let name = match name {
        Some(n) => n,
        None => return HttpResponse::BadRequest().body("Missing package name"),
    };
    let version = match version {
        Some(v) => v,
        None => return HttpResponse::BadRequest().body("Missing package version"),
    };
    let (filename, data) = match file_data {
        Some(f) => f,
        None => return HttpResponse::BadRequest().body("Missing package file"),
    };

    let normalized = normalize_package_name(&name);
    let package_path = get_package_path(&state.data_dir, &name);
    let version_path = package_path.join(&version);

    // Create directories
    if let Err(e) = fs::create_dir_all(&version_path).await {
        error!("Failed to create directory: {}", e);
        return HttpResponse::InternalServerError().body("Failed to create package directory");
    }

    // Calculate SHA256
    let sha256 = hex::encode(Sha256::digest(&data));
    let file_size = data.len() as u64;

    // Write file
    let file_path = version_path.join(&filename);
    if let Err(e) = fs::write(&file_path, &data).await {
        error!("Failed to write file: {}", e);
        return HttpResponse::InternalServerError().body("Failed to write package file");
    }

    // Update metadata
    let metadata_file = package_path.join("metadata.json");
    let mut metadata: PypiPackageMetadata = if let Ok(content) = fs::read_to_string(&metadata_file).await {
        serde_json::from_str(&content).unwrap_or(PypiPackageMetadata {
            name: name.clone(),
            versions: HashMap::new(),
        })
    } else {
        PypiPackageMetadata {
            name: name.clone(),
            versions: HashMap::new(),
        }
    };

    let file_info = PypiFileInfo {
        filename: filename.clone(),
        size: file_size,
        sha256,
        requires_python: requires_python.clone(),
    };

    if let Some(ver_meta) = metadata.versions.get_mut(&version) {
        // Add file to existing version
        if !ver_meta.files.iter().any(|f| f.filename == filename) {
            ver_meta.files.push(file_info);
        }
    } else {
        // Create new version
        metadata.versions.insert(version.clone(), PypiVersionMetadata {
            version: version.clone(),
            summary,
            author,
            author_email,
            license,
            requires_python,
            requires_dist,
            files: vec![file_info],
        });
    }

    // Write metadata
    let metadata_json = match serde_json::to_string_pretty(&metadata) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize metadata: {}", e);
            return HttpResponse::InternalServerError().body("Failed to update metadata");
        }
    };

    if let Err(e) = fs::write(&metadata_file, metadata_json).await {
        error!("Failed to write metadata: {}", e);
        return HttpResponse::InternalServerError().body("Failed to write metadata");
    }

    info!("Published PyPI package {} version {} ({})", normalized, version, filename);

    HttpResponse::Ok().body("Package uploaded successfully")
}

/// GET /pypi/packages/{package}/{version}/{filename} - Download package file
pub async fn download_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().body("Authentication required");
    }

    let (package_name, version, filename) = path.into_inner();
    let package_path = get_package_path(&state.data_dir, &package_name);
    let file_path = package_path.join(&version).join(&filename);

    match fs::read(&file_path).await {
        Ok(data) => {
            let content_type = if filename.ends_with(".whl") {
                "application/zip"
            } else if filename.ends_with(".tar.gz") {
                "application/gzip"
            } else {
                "application/octet-stream"
            };

            HttpResponse::Ok()
                .content_type(content_type)
                .body(data)
        }
        Err(_) => HttpResponse::NotFound().body("File not found"),
    }
}
