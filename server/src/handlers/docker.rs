use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};
use uuid::Uuid;

use crate::AppState;

use super::auth::validate_api_key;

/// Docker Registry HTTP API V2

const DOCKER_UPLOAD_UUID_HEADER: &str = "Docker-Upload-UUID";
const DOCKER_CONTENT_DIGEST_HEADER: &str = "Docker-Content-Digest";

fn get_registry_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("docker").join("registry")
}

fn get_blob_path(data_dir: &str, digest: &str) -> PathBuf {
    // digest format: sha256:abc123...
    let parts: Vec<&str> = digest.split(':').collect();
    if parts.len() == 2 {
        get_registry_path(data_dir)
            .join("blobs")
            .join(parts[0])
            .join(&parts[1][..2])
            .join(parts[1])
    } else {
        get_registry_path(data_dir).join("blobs").join(digest)
    }
}

fn get_manifest_path(data_dir: &str, name: &str, reference: &str) -> PathBuf {
    let repo_path = get_registry_path(data_dir).join("repositories").join(name);
    if reference.starts_with("sha256:") {
        // Reference by digest
        repo_path.join("_manifests").join("revisions").join(reference)
    } else {
        // Reference by tag
        repo_path.join("_manifests").join("tags").join(reference).join("current")
    }
}

fn get_upload_path(data_dir: &str, name: &str, uuid: &str) -> PathBuf {
    get_registry_path(data_dir)
        .join("repositories")
        .join(name)
        .join("_uploads")
        .join(uuid)
}

/// GET /v2/ - API version check
pub async fn version_check(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Bearer realm=\"Docker Registry\",service=\"registry\""))
            .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
            .json(DockerError::new("UNAUTHORIZED", "authentication required"));
    }

    HttpResponse::Ok()
        .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .finish()
}

/// GET /v2/_catalog - List repositories
pub async fn catalog(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<PaginationQuery>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .json(DockerError::new("UNAUTHORIZED", "authentication required"));
    }

    let repos_path = get_registry_path(&state.data_dir).join("repositories");
    let mut repositories: Vec<String> = Vec::new();

    if let Ok(repos) = collect_repositories(repos_path, String::new()).await {
        repositories = repos;
    }

    repositories.sort();

    let n = query.n.unwrap_or(100);
    let start = query.last.as_ref()
        .and_then(|last| repositories.iter().position(|r| r == last))
        .map(|pos| pos + 1)
        .unwrap_or(0);

    let repos: Vec<String> = repositories.into_iter().skip(start).take(n).collect();

    HttpResponse::Ok().json(CatalogResponse { repositories: repos })
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    n: Option<usize>,
    last: Option<String>,
}

#[derive(Debug, Serialize)]
struct CatalogResponse {
    repositories: Vec<String>,
}

fn collect_repositories(
    dir: PathBuf,
    prefix: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, std::io::Error>> + Send>>
{
    Box::pin(async move {
        let mut repos = Vec::new();

        if !dir.exists() {
            return Ok(repos);
        }

        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with('_') {
                continue;
            }

            if file_type.is_dir() {
                let full_name = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", prefix, name)
                };

                // Check if this directory has _manifests (is a repo)
                let manifests_dir = entry.path().join("_manifests");
                if manifests_dir.exists() {
                    repos.push(full_name.clone());
                }

                // Recurse for nested repos
                if let Ok(sub_repos) = collect_repositories(entry.path(), full_name).await {
                    repos.extend(sub_repos);
                }
            }
        }

        Ok(repos)
    })
}

/// GET /v2/{name}/tags/list - List tags for repository
pub async fn list_tags(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .json(DockerError::new("UNAUTHORIZED", "authentication required"));
    }

    let name = path.into_inner();
    let tags_path = get_registry_path(&state.data_dir)
        .join("repositories")
        .join(&name)
        .join("_manifests")
        .join("tags");

    let mut tags: Vec<String> = Vec::new();

    if let Ok(mut entries) = fs::read_dir(&tags_path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(tag) = entry.file_name().to_str() {
                    tags.push(tag.to_string());
                }
            }
        }
    }

    tags.sort();

    HttpResponse::Ok().json(TagsResponse { name, tags })
}

#[derive(Debug, Serialize)]
struct TagsResponse {
    name: String,
    tags: Vec<String>,
}

/// HEAD /v2/{name}/blobs/{digest} - Check if blob exists
pub async fn head_blob(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (_name, digest) = path.into_inner();
    let blob_path = get_blob_path(&state.data_dir, &digest);

    match fs::metadata(&blob_path).await {
        Ok(meta) => HttpResponse::Ok()
            .insert_header(("Content-Length", meta.len().to_string()))
            .insert_header((DOCKER_CONTENT_DIGEST_HEADER, digest))
            .insert_header(("Content-Type", "application/octet-stream"))
            .finish(),
        Err(_) => HttpResponse::NotFound()
            .json(DockerError::new("BLOB_UNKNOWN", "blob unknown to registry")),
    }
}

/// GET /v2/{name}/blobs/{digest} - Download blob
pub async fn get_blob(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (_name, digest) = path.into_inner();
    let blob_path = get_blob_path(&state.data_dir, &digest);

    match fs::read(&blob_path).await {
        Ok(data) => HttpResponse::Ok()
            .insert_header((DOCKER_CONTENT_DIGEST_HEADER, digest))
            .insert_header(("Content-Type", "application/octet-stream"))
            .body(data),
        Err(_) => HttpResponse::NotFound()
            .json(DockerError::new("BLOB_UNKNOWN", "blob unknown to registry")),
    }
}

/// POST /v2/{name}/blobs/uploads/ - Start blob upload
pub async fn start_upload(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let name = path.into_inner();
    let uuid = Uuid::new_v4().to_string();
    let upload_path = get_upload_path(&state.data_dir, &name, &uuid);

    // Create upload directory and data file
    if let Err(e) = fs::create_dir_all(&upload_path).await {
        error!("Failed to create upload directory: {}", e);
        return HttpResponse::InternalServerError()
            .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
    }

    let data_file = upload_path.join("data");
    if let Err(e) = fs::write(&data_file, b"").await {
        error!("Failed to create upload file: {}", e);
        return HttpResponse::InternalServerError()
            .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
    }

    let host = req.headers().get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };

    HttpResponse::Accepted()
        .insert_header(("Location", format!("{}://{}/v2/{}/blobs/uploads/{}", scheme, host, name, uuid)))
        .insert_header((DOCKER_UPLOAD_UUID_HEADER, uuid))
        .insert_header(("Range", "0-0"))
        .finish()
}

/// PATCH /v2/{name}/blobs/uploads/{uuid} - Upload blob chunk
pub async fn patch_upload(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Bytes,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (name, uuid) = path.into_inner();
    let upload_path = get_upload_path(&state.data_dir, &name, &uuid);
    let data_file = upload_path.join("data");

    if !data_file.exists() {
        return HttpResponse::NotFound()
            .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload not found"));
    }

    // Append data to file
    let mut file = match fs::OpenOptions::new().append(true).open(&data_file).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open upload file: {}", e);
            return HttpResponse::InternalServerError()
                .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
        }
    };

    if let Err(e) = file.write_all(&body).await {
        error!("Failed to write upload data: {}", e);
        return HttpResponse::InternalServerError()
            .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
    }

    let file_size = fs::metadata(&data_file).await.map(|m| m.len()).unwrap_or(0);

    let host = req.headers().get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };

    HttpResponse::Accepted()
        .insert_header(("Location", format!("{}://{}/v2/{}/blobs/uploads/{}", scheme, host, name, uuid)))
        .insert_header((DOCKER_UPLOAD_UUID_HEADER, uuid))
        .insert_header(("Range", format!("0-{}", file_size.saturating_sub(1))))
        .finish()
}

/// PUT /v2/{name}/blobs/uploads/{uuid}?digest=... - Complete blob upload
pub async fn complete_upload(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<DigestQuery>,
    body: web::Bytes,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (name, uuid) = path.into_inner();
    let digest = &query.digest;
    let upload_path = get_upload_path(&state.data_dir, &name, &uuid);
    let data_file = upload_path.join("data");

    if !data_file.exists() {
        return HttpResponse::NotFound()
            .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload not found"));
    }

    // Append any final data
    if !body.is_empty() {
        let mut file = match fs::OpenOptions::new().append(true).open(&data_file).await {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open upload file: {}", e);
                return HttpResponse::InternalServerError()
                    .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
            }
        };

        if let Err(e) = file.write_all(&body).await {
            error!("Failed to write final upload data: {}", e);
            return HttpResponse::InternalServerError()
                .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
        }
    }

    // Read the complete blob
    let blob_data = match fs::read(&data_file).await {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to read upload data: {}", e);
            return HttpResponse::InternalServerError()
                .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
        }
    };

    // Verify digest
    let calculated_digest = format!("sha256:{}", hex::encode(Sha256::digest(&blob_data)));
    if &calculated_digest != digest {
        return HttpResponse::BadRequest()
            .json(DockerError::new("DIGEST_INVALID", "provided digest does not match uploaded content"));
    }

    // Move blob to final location
    let blob_path = get_blob_path(&state.data_dir, digest);
    if let Some(parent) = blob_path.parent() {
        if let Err(e) = fs::create_dir_all(parent).await {
            error!("Failed to create blob directory: {}", e);
            return HttpResponse::InternalServerError()
                .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
        }
    }

    if let Err(e) = fs::write(&blob_path, &blob_data).await {
        error!("Failed to write blob: {}", e);
        return HttpResponse::InternalServerError()
            .json(DockerError::new("BLOB_UPLOAD_UNKNOWN", "upload failed"));
    }

    // Clean up upload directory
    let _ = fs::remove_dir_all(&upload_path).await;

    info!("Uploaded blob {} ({} bytes)", digest, blob_data.len());

    let host = req.headers().get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };

    HttpResponse::Created()
        .insert_header(("Location", format!("{}://{}/v2/{}/blobs/{}", scheme, host, name, digest)))
        .insert_header((DOCKER_CONTENT_DIGEST_HEADER, digest.clone()))
        .finish()
}

#[derive(Debug, Deserialize)]
pub struct DigestQuery {
    digest: String,
}

/// HEAD /v2/{name}/manifests/{reference} - Check manifest exists
pub async fn head_manifest(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (name, reference) = path.into_inner();
    let manifest_path = get_manifest_path(&state.data_dir, &name, &reference);

    // Read the link file to get the actual digest
    let digest = if reference.starts_with("sha256:") {
        reference.clone()
    } else {
        match fs::read_to_string(&manifest_path).await {
            Ok(d) => d.trim().to_string(),
            Err(_) => return HttpResponse::NotFound()
                .json(DockerError::new("MANIFEST_UNKNOWN", "manifest unknown")),
        }
    };

    let blob_path = get_blob_path(&state.data_dir, &digest);
    match fs::metadata(&blob_path).await {
        Ok(meta) => HttpResponse::Ok()
            .insert_header(("Content-Length", meta.len().to_string()))
            .insert_header((DOCKER_CONTENT_DIGEST_HEADER, digest))
            .insert_header(("Content-Type", "application/vnd.docker.distribution.manifest.v2+json"))
            .finish(),
        Err(_) => HttpResponse::NotFound()
            .json(DockerError::new("MANIFEST_UNKNOWN", "manifest unknown")),
    }
}

/// GET /v2/{name}/manifests/{reference} - Get manifest
pub async fn get_manifest(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (name, reference) = path.into_inner();
    let manifest_path = get_manifest_path(&state.data_dir, &name, &reference);

    // Read the link file to get the actual digest
    let digest = if reference.starts_with("sha256:") {
        reference.clone()
    } else {
        match fs::read_to_string(&manifest_path).await {
            Ok(d) => d.trim().to_string(),
            Err(_) => return HttpResponse::NotFound()
                .json(DockerError::new("MANIFEST_UNKNOWN", "manifest unknown")),
        }
    };

    let blob_path = get_blob_path(&state.data_dir, &digest);
    match fs::read(&blob_path).await {
        Ok(data) => {
            // Try to determine content type from manifest
            let content_type = if let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&data) {
                manifest.get("mediaType")
                    .and_then(|m| m.as_str())
                    .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
                    .to_string()
            } else {
                "application/vnd.docker.distribution.manifest.v2+json".to_string()
            };

            HttpResponse::Ok()
                .insert_header((DOCKER_CONTENT_DIGEST_HEADER, digest))
                .insert_header(("Content-Type", content_type))
                .body(data)
        }
        Err(_) => HttpResponse::NotFound()
            .json(DockerError::new("MANIFEST_UNKNOWN", "manifest unknown")),
    }
}

/// PUT /v2/{name}/manifests/{reference} - Upload manifest
pub async fn put_manifest(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Bytes,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (name, reference) = path.into_inner();

    // Calculate digest
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body)));

    // Store manifest as a blob
    let blob_path = get_blob_path(&state.data_dir, &digest);
    if let Some(parent) = blob_path.parent() {
        if let Err(e) = fs::create_dir_all(parent).await {
            error!("Failed to create blob directory: {}", e);
            return HttpResponse::InternalServerError()
                .json(DockerError::new("MANIFEST_INVALID", "failed to store manifest"));
        }
    }

    if let Err(e) = fs::write(&blob_path, &body).await {
        error!("Failed to write manifest blob: {}", e);
        return HttpResponse::InternalServerError()
            .json(DockerError::new("MANIFEST_INVALID", "failed to store manifest"));
    }

    // Create tag link if reference is not a digest
    if !reference.starts_with("sha256:") {
        let tag_path = get_manifest_path(&state.data_dir, &name, &reference);
        if let Some(parent) = tag_path.parent() {
            if let Err(e) = fs::create_dir_all(parent).await {
                error!("Failed to create tag directory: {}", e);
                return HttpResponse::InternalServerError()
                    .json(DockerError::new("MANIFEST_INVALID", "failed to store manifest"));
            }
        }

        if let Err(e) = fs::write(&tag_path, &digest).await {
            error!("Failed to write tag link: {}", e);
            return HttpResponse::InternalServerError()
                .json(DockerError::new("MANIFEST_INVALID", "failed to store manifest"));
        }
    }

    // Create revision link
    let rev_path = get_registry_path(&state.data_dir)
        .join("repositories")
        .join(&name)
        .join("_manifests")
        .join("revisions")
        .join(&digest);

    if let Some(parent) = rev_path.parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    let _ = fs::write(&rev_path, &digest).await;

    info!("Uploaded manifest {} for {}", digest, name);

    let host = req.headers().get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if req.connection_info().scheme() == "https" { "https" } else { "http" };

    HttpResponse::Created()
        .insert_header(("Location", format!("{}://{}/v2/{}/manifests/{}", scheme, host, name, reference)))
        .insert_header((DOCKER_CONTENT_DIGEST_HEADER, digest))
        .finish()
}

/// DELETE /v2/{name}/manifests/{reference} - Delete manifest
pub async fn delete_manifest(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().finish();
    }

    let (name, reference) = path.into_inner();

    // Delete tag link if it's a tag
    if !reference.starts_with("sha256:") {
        let tag_path = get_manifest_path(&state.data_dir, &name, &reference);
        let _ = fs::remove_file(&tag_path).await;
        // Try to remove parent directory if empty
        if let Some(parent) = tag_path.parent() {
            let _ = fs::remove_dir(parent).await;
        }
    }

    HttpResponse::Accepted().finish()
}

#[derive(Debug, Serialize)]
struct DockerError {
    errors: Vec<DockerErrorDetail>,
}

#[derive(Debug, Serialize)]
struct DockerErrorDetail {
    code: String,
    message: String,
}

impl DockerError {
    fn new(code: &str, message: &str) -> Self {
        Self {
            errors: vec![DockerErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            }],
        }
    }
}
