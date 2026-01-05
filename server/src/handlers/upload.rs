use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use tokio::process::Command;
use tracing::{error, info};
use uuid::Uuid;

use crate::processor::PackageType;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct UploadParams {
    /// Distribution (for apt: stable, testing, etc.)
    pub dist: Option<String>,
    /// Architecture override
    pub arch: Option<String>,
}

#[derive(Debug, Serialize)]
struct UploadResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

fn validate_api_key(req: &HttpRequest, state: &AppState) -> bool {
    // Check Authorization header
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            let token = auth_str.trim_start_matches("Bearer ").trim();
            return state.api_keys.contains(&token.to_string());
        }
    }

    // Check X-API-Key header
    if let Some(api_key) = req.headers().get("X-API-Key") {
        if let Ok(key_str) = api_key.to_str() {
            return state.api_keys.contains(&key_str.to_string());
        }
    }

    false
}

pub async fn upload_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<UploadParams>,
    mut payload: Multipart,
) -> impl Responder {
    // Validate API key
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid or missing API key".to_string(),
            details: None,
        });
    }

    let pkg_type_str = path.into_inner();
    let pkg_type = match pkg_type_str.as_str() {
        "deb" => PackageType::Deb,
        "rpm" => PackageType::Rpm,
        "arch" => PackageType::Arch,
        "alpine" | "apk" => PackageType::Alpine,
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Unknown package type: {}", pkg_type_str),
                details: Some("Supported types: deb, rpm, arch, alpine".to_string()),
            });
        }
    };

    // Process multipart upload
    let mut temp_file: Option<PathBuf> = None;
    let mut original_filename: Option<String> = None;

    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                error!("Multipart error: {}", e);
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: "Failed to process upload".to_string(),
                    details: Some(e.to_string()),
                });
            }
        };

        // Get filename
        let content_disposition = field.content_disposition();
        let filename = content_disposition
            .get_filename()
            .map(|f| sanitize_filename::sanitize(f))
            .unwrap_or_else(|| format!("package-{}", Uuid::new_v4()));

        original_filename = Some(filename.clone());

        // Create temp file
        let temp_path = PathBuf::from("/tmp").join(format!("upload-{}-{}", Uuid::new_v4(), filename));

        let mut file = match std::fs::File::create(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to create temp file: {}", e);
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to save uploaded file".to_string(),
                    details: Some(e.to_string()),
                });
            }
        };

        // Write chunks to file
        while let Some(chunk) = field.next().await {
            match chunk {
                Ok(data) => {
                    if let Err(e) = file.write_all(&data) {
                        error!("Failed to write chunk: {}", e);
                        let _ = std::fs::remove_file(&temp_path);
                        return HttpResponse::InternalServerError().json(ErrorResponse {
                            error: "Failed to write uploaded data".to_string(),
                            details: Some(e.to_string()),
                        });
                    }
                }
                Err(e) => {
                    error!("Failed to read chunk: {}", e);
                    let _ = std::fs::remove_file(&temp_path);
                    return HttpResponse::BadRequest().json(ErrorResponse {
                        error: "Failed to read uploaded data".to_string(),
                        details: Some(e.to_string()),
                    });
                }
            }
        }

        temp_file = Some(temp_path);
        break; // Only process first file
    }

    let temp_path = match temp_file {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "No file uploaded".to_string(),
                details: None,
            });
        }
    };

    info!(
        "Processing {} package: {:?}",
        pkg_type_str,
        original_filename
    );

    // Process the package
    let processor_script = match pkg_type {
        PackageType::Deb => "process-deb",
        PackageType::Rpm => "process-rpm",
        PackageType::Arch => "process-arch",
        PackageType::Alpine => "process-alpine",
        PackageType::Cargo | PackageType::Npm => {
            // These types use dedicated registry endpoints, not the generic upload
            let _ = tokio::fs::remove_file(&temp_path).await;
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("{} packages must be published via their dedicated registry endpoints", pkg_type),
                details: Some("Use /cargo/api/v1/crates/new for Cargo or PUT /npm/<package> for npm".to_string()),
            });
        }
    };

    let mut cmd = Command::new(processor_script);
    cmd.arg("add").arg(&temp_path);

    // Add distribution argument for deb packages
    if let Some(dist) = &query.dist {
        if pkg_type == PackageType::Deb {
            cmd.arg(dist);
        }
    }

    // Set environment variables
    cmd.env("REPO_DATA_DIR", &state.data_dir);
    cmd.env("REPO_GPG_DIR", &state.gpg_dir);

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to execute processor: {}", e);
            let _ = std::fs::remove_file(&temp_path);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to process package".to_string(),
                details: Some(e.to_string()),
            });
        }
    };

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    if output.status.success() {
        info!("Package processed successfully");
        HttpResponse::Ok().json(UploadResponse {
            success: true,
            message: "Package uploaded and indexed successfully".to_string(),
            package_name: original_filename.clone(),
            package_version: None,
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Package processing failed: {}", stderr);
        HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Package processing failed".to_string(),
            details: Some(stderr.to_string()),
        })
    }
}
