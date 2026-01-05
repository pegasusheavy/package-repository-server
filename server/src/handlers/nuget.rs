use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::PathBuf;
use tokio::fs;
use tracing::{error, info};
use zip::ZipArchive;

use crate::AppState;
use crate::utils::{extract_xml_value_optimized, version_compare_optimized};

use super::auth::validate_api_key;

/// NuGet V3 API Implementation
/// https://docs.microsoft.com/en-us/nuget/api/overview

fn get_nuget_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("nuget")
}

fn get_package_path(data_dir: &str, id: &str, version: &str) -> PathBuf {
    let id_lower = id.to_lowercase();
    get_nuget_path(data_dir)
        .join("packages")
        .join(&id_lower)
        .join(version)
        .join(format!("{}.{}.nupkg", id_lower, version))
}

fn get_nuspec_path(data_dir: &str, id: &str, version: &str) -> PathBuf {
    let id_lower = id.to_lowercase();
    get_nuget_path(data_dir)
        .join("packages")
        .join(&id_lower)
        .join(version)
        .join(format!("{}.nuspec", id_lower))
}

// ============================================================================
// Service Index (Entry Point)
// ============================================================================

#[derive(Debug, Serialize)]
struct ServiceIndex {
    version: String,
    resources: Vec<ServiceResource>,
}

#[derive(Debug, Serialize)]
struct ServiceResource {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

/// GET /nuget/v3/index.json - Service index (entry point for NuGet clients)
pub async fn service_index(req: HttpRequest) -> impl Responder {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let base_url = format!("{}://{}/nuget", scheme, host);

    let index = ServiceIndex {
        version: "3.0.0".to_string(),
        resources: vec![
            ServiceResource {
                id: format!("{}/v3-flatcontainer/", base_url),
                resource_type: "PackageBaseAddress/3.0.0".to_string(),
                comment: Some("Base URL for package content".to_string()),
            },
            ServiceResource {
                id: format!("{}/v3/registration/", base_url),
                resource_type: "RegistrationsBaseUrl/3.6.0".to_string(),
                comment: Some("Base URL for package metadata".to_string()),
            },
            ServiceResource {
                id: format!("{}/api/v2/package", base_url),
                resource_type: "PackagePublish/2.0.0".to_string(),
                comment: Some("Package publish endpoint".to_string()),
            },
            ServiceResource {
                id: format!("{}/query", base_url),
                resource_type: "SearchQueryService/3.5.0".to_string(),
                comment: Some("Search packages".to_string()),
            },
        ],
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .json(index)
}

// ============================================================================
// Package Content (Flat Container)
// ============================================================================

#[derive(Debug, Serialize)]
struct PackageVersions {
    versions: Vec<String>,
}

/// GET /nuget/v3-flatcontainer/{id}/index.json - List package versions
pub async fn list_versions(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"NuGet\""))
            .body("Authentication required");
    }

    let id = path.into_inner().to_lowercase();
    let package_dir = get_nuget_path(&state.data_dir).join("packages").join(&id);

    if !package_dir.exists() {
        return HttpResponse::NotFound().body("Package not found");
    }

    let mut versions = Vec::new();
    if let Ok(mut entries) = fs::read_dir(&package_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    versions.push(name.to_string());
                }
            }
        }
    }

    versions.sort_by(|a, b| version_compare(a, b));

    HttpResponse::Ok()
        .content_type("application/json")
        .json(PackageVersions { versions })
}

/// GET /nuget/v3-flatcontainer/{id}/{version}/{filename} - Download package or nuspec
pub async fn download_content(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"NuGet\""))
            .body("Authentication required");
    }

    let (id, version, filename) = path.into_inner();
    let id_lower = id.to_lowercase();
    let version_lower = version.to_lowercase();

    let file_path = if filename.ends_with(".nupkg") {
        get_package_path(&state.data_dir, &id_lower, &version_lower)
    } else if filename.ends_with(".nuspec") {
        get_nuspec_path(&state.data_dir, &id_lower, &version_lower)
    } else {
        return HttpResponse::NotFound().body("File not found");
    };

    match fs::read(&file_path).await {
        Ok(data) => {
            let content_type = if filename.ends_with(".nupkg") {
                "application/octet-stream"
            } else {
                "application/xml"
            };
            HttpResponse::Ok().content_type(content_type).body(data)
        }
        Err(_) => HttpResponse::NotFound().body("File not found"),
    }
}

// ============================================================================
// Registration (Package Metadata)
// ============================================================================

#[derive(Debug, Serialize)]
struct RegistrationIndex {
    #[serde(rename = "@id")]
    id: String,
    count: usize,
    items: Vec<RegistrationPage>,
}

#[derive(Debug, Serialize)]
struct RegistrationPage {
    #[serde(rename = "@id")]
    id: String,
    count: usize,
    items: Vec<RegistrationLeaf>,
    lower: String,
    upper: String,
}

#[derive(Debug, Serialize)]
struct RegistrationLeaf {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "catalogEntry")]
    catalog_entry: CatalogEntry,
    #[serde(rename = "packageContent")]
    package_content: String,
}

#[derive(Debug, Serialize)]
struct CatalogEntry {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "id")]
    package_id: String,
    version: String,
    authors: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "projectUrl")]
    project_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "licenseUrl")]
    license_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

/// GET /nuget/v3/registration/{id}/index.json - Package registration (metadata)
pub async fn registration_index(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"NuGet\""))
            .body("Authentication required");
    }

    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let base_url = format!("{}://{}/nuget", scheme, host);

    let id = path.into_inner().to_lowercase();
    let package_dir = get_nuget_path(&state.data_dir).join("packages").join(&id);

    if !package_dir.exists() {
        return HttpResponse::NotFound().body("Package not found");
    }

    // Collect versions and metadata
    let mut items = Vec::new();
    if let Ok(mut entries) = fs::read_dir(&package_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }

            let version = entry.file_name().to_string_lossy().to_string();
            let nuspec_path = get_nuspec_path(&state.data_dir, &id, &version);

            let (authors, description, project_url, license_url, tags) =
                if let Ok(nuspec) = fs::read_to_string(&nuspec_path).await {
                    parse_nuspec_metadata(&nuspec)
                } else {
                    ("Unknown".to_string(), "".to_string(), None, None, None)
                };

            items.push(RegistrationLeaf {
                id: format!("{}/v3/registration/{}/{}.json", base_url, id, version),
                catalog_entry: CatalogEntry {
                    id: format!("{}/v3/registration/{}/{}.json", base_url, id, version),
                    package_id: id.clone(),
                    version: version.clone(),
                    authors,
                    description,
                    project_url,
                    license_url,
                    tags,
                },
                package_content: format!(
                    "{}/v3-flatcontainer/{}/{}/{}.{}.nupkg",
                    base_url, id, version, id, version
                ),
            });
        }
    }

    items.sort_by(|a, b| version_compare(&a.catalog_entry.version, &b.catalog_entry.version));

    let lower = items
        .first()
        .map(|i| i.catalog_entry.version.clone())
        .unwrap_or_default();
    let upper = items
        .last()
        .map(|i| i.catalog_entry.version.clone())
        .unwrap_or_default();

    let page = RegistrationPage {
        id: format!("{}/v3/registration/{}/index.json#page/0", base_url, id),
        count: items.len(),
        items,
        lower,
        upper,
    };

    let index = RegistrationIndex {
        id: format!("{}/v3/registration/{}/index.json", base_url, id),
        count: 1,
        items: vec![page],
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .json(index)
}

// ============================================================================
// Search
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    q: Option<String>,
    skip: Option<usize>,
    take: Option<usize>,
    #[serde(rename = "prerelease")]
    _prerelease: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    #[serde(rename = "totalHits")]
    total_hits: usize,
    data: Vec<SearchResult>,
}

#[derive(Debug, Serialize)]
struct SearchResult {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "id")]
    package_id: String,
    version: String,
    description: String,
    authors: Vec<String>,
    #[serde(rename = "totalDownloads")]
    total_downloads: u64,
    versions: Vec<SearchVersion>,
}

#[derive(Debug, Serialize)]
struct SearchVersion {
    version: String,
    downloads: u64,
    #[serde(rename = "@id")]
    id: String,
}

/// GET /nuget/query - Search packages
pub async fn search(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<SearchQuery>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"NuGet\""))
            .body("Authentication required");
    }

    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let base_url = format!("{}://{}/nuget", scheme, host);

    let packages_dir = get_nuget_path(&state.data_dir).join("packages");
    let search_term = query.q.as_deref().unwrap_or("").to_lowercase();
    let skip = query.skip.unwrap_or(0);
    let take = query.take.unwrap_or(20);

    let mut results = Vec::new();

    if packages_dir.exists() {
        if let Ok(mut entries) = fs::read_dir(&packages_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }

                let package_id = entry.file_name().to_string_lossy().to_string();

                // Filter by search term
                if !search_term.is_empty() && !package_id.to_lowercase().contains(&search_term) {
                    continue;
                }

                // Get versions
                let mut versions = Vec::new();
                if let Ok(mut ver_entries) = fs::read_dir(entry.path()).await {
                    while let Ok(Some(ver_entry)) = ver_entries.next_entry().await {
                        if ver_entry
                            .file_type()
                            .await
                            .map(|t| t.is_dir())
                            .unwrap_or(false)
                        {
                            let ver = ver_entry.file_name().to_string_lossy().to_string();
                            versions.push(SearchVersion {
                                version: ver.clone(),
                                downloads: 0,
                                id: format!("{}/v3/registration/{}/{}.json", base_url, package_id, ver),
                            });
                        }
                    }
                }

                if versions.is_empty() {
                    continue;
                }

                versions.sort_by(|a, b| version_compare(&a.version, &b.version));
                let latest = versions.last().unwrap().version.clone();

                // Get metadata from latest version
                let nuspec_path = get_nuspec_path(&state.data_dir, &package_id, &latest);
                let (authors, description, _, _, _) =
                    if let Ok(nuspec) = fs::read_to_string(&nuspec_path).await {
                        parse_nuspec_metadata(&nuspec)
                    } else {
                        ("Unknown".to_string(), "".to_string(), None, None, None)
                    };

                results.push(SearchResult {
                    id: format!("{}/v3/registration/{}/index.json", base_url, package_id),
                    package_id: package_id.clone(),
                    version: latest,
                    description,
                    authors: vec![authors],
                    total_downloads: 0,
                    versions,
                });
            }
        }
    }

    let total_hits = results.len();
    let data: Vec<_> = results.into_iter().skip(skip).take(take).collect();

    HttpResponse::Ok()
        .content_type("application/json")
        .json(SearchResponse { total_hits, data })
}

// ============================================================================
// Package Push
// ============================================================================

/// PUT /nuget/api/v2/package - Push package
pub async fn push_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    mut payload: Multipart,
) -> impl Responder {
    // NuGet uses X-NuGet-ApiKey header for authentication
    let api_key = req
        .headers()
        .get("X-NuGet-ApiKey")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let is_valid = api_key
        .as_ref()
        .map(|k| state.api_keys.contains(k))
        .unwrap_or(false);

    if !is_valid && !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"NuGet\""))
            .body("Authentication required");
    }

    // Read the .nupkg file from multipart
    let mut nupkg_data: Option<Vec<u8>> = None;

    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                error!("Multipart error: {}", e);
                return HttpResponse::BadRequest().body("Invalid multipart data");
            }
        };

        let mut data = Vec::new();
        while let Some(chunk) = field.next().await {
            match chunk {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(e) => {
                    error!("Error reading chunk: {}", e);
                    return HttpResponse::BadRequest().body("Error reading data");
                }
            }
        }

        if !data.is_empty() {
            nupkg_data = Some(data);
            break;
        }
    }

    let nupkg_data = match nupkg_data {
        Some(d) => d,
        None => return HttpResponse::BadRequest().body("No package data received"),
    };

    // Parse the .nupkg (it's a ZIP file)
    let cursor = std::io::Cursor::new(&nupkg_data);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => {
            error!("Invalid nupkg file: {}", e);
            return HttpResponse::BadRequest().body("Invalid nupkg file");
        }
    };

    // Find and extract .nuspec file
    let mut nuspec_content: Option<String> = None;
    let mut nuspec_filename: Option<String> = None;

    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            if file.name().ends_with(".nuspec") {
                nuspec_filename = Some(file.name().to_string());
                break;
            }
        }
    }

    if let Some(ref filename) = nuspec_filename {
        if let Ok(mut file) = archive.by_name(filename) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                nuspec_content = Some(content);
            }
        }
    }

    let nuspec = match nuspec_content {
        Some(c) => c,
        None => return HttpResponse::BadRequest().body("No .nuspec file found in package"),
    };

    // Parse package ID and version from nuspec
    let (package_id, version) = match parse_nuspec_id_version(&nuspec) {
        Some((id, ver)) => (id.to_lowercase(), ver),
        None => return HttpResponse::BadRequest().body("Could not parse package ID/version from .nuspec"),
    };

    // Create package directory
    let package_dir = get_nuget_path(&state.data_dir)
        .join("packages")
        .join(&package_id)
        .join(&version);

    if let Err(e) = fs::create_dir_all(&package_dir).await {
        error!("Failed to create package directory: {}", e);
        return HttpResponse::InternalServerError().body("Failed to create package directory");
    }

    // Write .nupkg file
    let nupkg_path = package_dir.join(format!("{}.{}.nupkg", package_id, version));
    if let Err(e) = fs::write(&nupkg_path, &nupkg_data).await {
        error!("Failed to write nupkg: {}", e);
        return HttpResponse::InternalServerError().body("Failed to write package");
    }

    // Write .nuspec file
    let nuspec_path = package_dir.join(format!("{}.nuspec", package_id));
    if let Err(e) = fs::write(&nuspec_path, &nuspec).await {
        error!("Failed to write nuspec: {}", e);
        return HttpResponse::InternalServerError().body("Failed to write nuspec");
    }

    info!("Published NuGet package: {} v{}", package_id, version);

    HttpResponse::Created().finish()
}

/// DELETE /nuget/api/v2/package/{id}/{version} - Delete package
pub async fn delete_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let api_key = req
        .headers()
        .get("X-NuGet-ApiKey")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let is_valid = api_key
        .as_ref()
        .map(|k| state.api_keys.contains(k))
        .unwrap_or(false);

    if !is_valid && !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"NuGet\""))
            .body("Authentication required");
    }

    let (id, version) = path.into_inner();
    let id_lower = id.to_lowercase();

    let package_dir = get_nuget_path(&state.data_dir)
        .join("packages")
        .join(&id_lower)
        .join(&version);

    if !package_dir.exists() {
        return HttpResponse::NotFound().body("Package not found");
    }

    if let Err(e) = fs::remove_dir_all(&package_dir).await {
        error!("Failed to delete package: {}", e);
        return HttpResponse::InternalServerError().body("Failed to delete package");
    }

    // Clean up empty parent directory
    let parent_dir = get_nuget_path(&state.data_dir)
        .join("packages")
        .join(&id_lower);
    if let Ok(mut entries) = fs::read_dir(&parent_dir).await {
        if entries.next_entry().await.ok().flatten().is_none() {
            let _ = fs::remove_dir(&parent_dir).await;
        }
    }

    info!("Deleted NuGet package: {} v{}", id_lower, version);

    HttpResponse::NoContent().finish()
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_nuspec_id_version(nuspec: &str) -> Option<(String, String)> {
    // Simple XML parsing for id and version
    let id = extract_xml_value(nuspec, "id")?;
    let version = extract_xml_value(nuspec, "version")?;
    Some((id, version))
}

fn parse_nuspec_metadata(
    nuspec: &str,
) -> (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<Vec<String>>,
) {
    let authors = extract_xml_value(nuspec, "authors").unwrap_or_else(|| "Unknown".to_string());
    let description = extract_xml_value(nuspec, "description").unwrap_or_default();
    let project_url = extract_xml_value(nuspec, "projectUrl");
    let license_url = extract_xml_value(nuspec, "licenseUrl");
    let tags = extract_xml_value(nuspec, "tags").map(|t| {
        t.split_whitespace()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    });

    (authors, description, project_url, license_url, tags)
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    extract_xml_value_optimized(xml, tag)
}

fn version_compare(a: &str, b: &str) -> std::cmp::Ordering {
    version_compare_optimized(a, b)
}
