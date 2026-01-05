use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::process::Command;
use tracing::info;

use crate::AppState;

#[derive(Debug, Serialize)]
struct PackageInfo {
    name: String,
    version: String,
    architecture: String,
    package_type: String,
    filename: String,
    size: u64,
}

#[derive(Debug, Serialize)]
struct PackageListResponse {
    packages: Vec<PackageInfo>,
    total: usize,
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub arch: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
struct SuccessResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

fn validate_api_key(req: &HttpRequest, state: &AppState) -> bool {
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            let token = auth_str.trim_start_matches("Bearer ").trim();
            return state.api_keys.contains(&token.to_string());
        }
    }

    if let Some(api_key) = req.headers().get("X-API-Key") {
        if let Ok(key_str) = api_key.to_str() {
            return state.api_keys.contains(&key_str.to_string());
        }
    }

    false
}

pub async fn list_packages(
    state: web::Data<AppState>,
    query: web::Query<ListParams>,
) -> impl Responder {
    let mut all_packages = Vec::new();

    // List packages from all repository types
    for pkg_type in &["deb", "rpm", "arch", "alpine", "cargo", "npm"] {
        if let Ok(packages) = list_packages_for_type(&state.data_dir, pkg_type, query.arch.as_deref()).await {
            all_packages.extend(packages);
        }
    }

    let total = all_packages.len();

    // Apply pagination
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100);
    let packages: Vec<_> = all_packages.into_iter().skip(offset).take(limit).collect();

    HttpResponse::Ok().json(PackageListResponse { packages, total })
}

pub async fn list_packages_by_type(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<ListParams>,
) -> impl Responder {
    let pkg_type = path.into_inner();

    match list_packages_for_type(&state.data_dir, &pkg_type, query.arch.as_deref()).await {
        Ok(packages) => {
            let total = packages.len();
            let offset = query.offset.unwrap_or(0);
            let limit = query.limit.unwrap_or(100);
            let packages: Vec<_> = packages.into_iter().skip(offset).take(limit).collect();

            HttpResponse::Ok().json(PackageListResponse { packages, total })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Failed to list packages".to_string(),
            details: Some(e),
        }),
    }
}

async fn list_packages_for_type(
    data_dir: &str,
    pkg_type: &str,
    arch_filter: Option<&str>,
) -> Result<Vec<PackageInfo>, String> {
    let mut packages = Vec::new();

    let (base_path, extension, _architectures) = match pkg_type {
        "deb" => (
            format!("{}/deb/pool", data_dir),
            ".deb",
            vec!["amd64", "arm64", "all"],
        ),
        "rpm" => (
            format!("{}/rpm", data_dir),
            ".rpm",
            vec!["x86_64", "aarch64", "noarch"],
        ),
        "arch" => (
            format!("{}/arch", data_dir),
            ".pkg.tar",
            vec!["x86_64", "aarch64", "any"],
        ),
        "alpine" => (
            format!("{}/alpine", data_dir),
            ".apk",
            vec!["x86_64", "aarch64", "noarch"],
        ),
        "cargo" => (
            format!("{}/cargo/crates", data_dir),
            ".crate",
            vec!["any"],
        ),
        "npm" => (
            format!("{}/npm/packages", data_dir),
            ".tgz",
            vec!["any"],
        ),
        _ => return Err(format!("Unknown package type: {}", pkg_type)),
    };

    let base = Path::new(&base_path);
    if !base.exists() {
        return Ok(packages);
    }

    // Walk directory tree to find packages
    fn walk_dir(
        dir: &Path,
        extension: &str,
        pkg_type: &str,
        packages: &mut Vec<PackageInfo>,
        arch_filter: Option<&str>,
    ) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    walk_dir(&path, extension, pkg_type, packages, arch_filter)?;
                } else if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
                    if filename.contains(extension) && !filename.ends_with(".sig") {
                        // Extract package info from filename
                        let (name, version, arch) = parse_package_filename(filename, pkg_type);

                        // Apply architecture filter
                        if let Some(filter) = arch_filter {
                            if arch != filter && arch != "all" && arch != "any" && arch != "noarch" {
                                continue;
                            }
                        }

                        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                        packages.push(PackageInfo {
                            name,
                            version,
                            architecture: arch,
                            package_type: pkg_type.to_string(),
                            filename: filename.to_string(),
                            size,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    walk_dir(base, extension, pkg_type, &mut packages, arch_filter)
        .map_err(|e| e.to_string())?;

    Ok(packages)
}

fn parse_package_filename(filename: &str, pkg_type: &str) -> (String, String, String) {
    match pkg_type {
        "deb" => {
            // Format: name_version_arch.deb
            let parts: Vec<&str> = filename.trim_end_matches(".deb").split('_').collect();
            if parts.len() >= 3 {
                (
                    parts[0].to_string(),
                    parts[1].to_string(),
                    parts[2].to_string(),
                )
            } else {
                (filename.to_string(), "unknown".to_string(), "unknown".to_string())
            }
        }
        "rpm" => {
            // Format: name-version-release.arch.rpm
            let without_ext = filename.trim_end_matches(".rpm");
            let parts: Vec<&str> = without_ext.rsplitn(2, '.').collect();
            if parts.len() >= 2 {
                let arch = parts[0];
                let name_version = parts[1];
                // Split name and version
                let nv_parts: Vec<&str> = name_version.rsplitn(3, '-').collect();
                if nv_parts.len() >= 3 {
                    (
                        nv_parts[2].to_string(),
                        format!("{}-{}", nv_parts[1], nv_parts[0]),
                        arch.to_string(),
                    )
                } else {
                    (name_version.to_string(), "unknown".to_string(), arch.to_string())
                }
            } else {
                (filename.to_string(), "unknown".to_string(), "unknown".to_string())
            }
        }
        "arch" => {
            // Format: name-version-release-arch.pkg.tar.zst
            let without_ext = filename
                .replace(".pkg.tar.zst", "")
                .replace(".pkg.tar.xz", "")
                .replace(".pkg.tar.gz", "");
            let parts: Vec<&str> = without_ext.rsplitn(4, '-').collect();
            if parts.len() >= 4 {
                (
                    parts[3].to_string(),
                    format!("{}-{}", parts[2], parts[1]),
                    parts[0].to_string(),
                )
            } else {
                (filename.to_string(), "unknown".to_string(), "unknown".to_string())
            }
        }
        "alpine" => {
            // Format: name-version-rrelease.apk
            let without_ext = filename.trim_end_matches(".apk");
            let parts: Vec<&str> = without_ext.rsplitn(3, '-').collect();
            if parts.len() >= 2 {
                (
                    parts.last().unwrap_or(&"unknown").to_string(),
                    parts[..parts.len() - 1].join("-"),
                    "unknown".to_string(), // Architecture needs to be read from PKGINFO
                )
            } else {
                (filename.to_string(), "unknown".to_string(), "unknown".to_string())
            }
        }
        "cargo" => {
            // Format: name-version.crate
            let without_ext = filename.trim_end_matches(".crate");
            if let Some(dash_pos) = without_ext.rfind('-') {
                let name = &without_ext[..dash_pos];
                let version = &without_ext[dash_pos + 1..];
                (name.to_string(), version.to_string(), "any".to_string())
            } else {
                (without_ext.to_string(), "unknown".to_string(), "any".to_string())
            }
        }
        "npm" => {
            // Format: name-version.tgz or scope-name-version.tgz
            let without_ext = filename.trim_end_matches(".tgz");
            if let Some(dash_pos) = without_ext.rfind('-') {
                let name = &without_ext[..dash_pos];
                let version = &without_ext[dash_pos + 1..];
                (name.to_string(), version.to_string(), "any".to_string())
            } else {
                (without_ext.to_string(), "unknown".to_string(), "any".to_string())
            }
        }
        _ => (filename.to_string(), "unknown".to_string(), "unknown".to_string()),
    }
}

pub async fn delete_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid or missing API key".to_string(),
            details: None,
        });
    }

    let (pkg_type, pkg_name) = path.into_inner();

    info!("Deleting package: {} from {}", pkg_name, pkg_type);

    let processor_script = match pkg_type.as_str() {
        "deb" => "process-deb",
        "rpm" => "process-rpm",
        "arch" => "process-arch",
        "alpine" | "apk" => "process-alpine",
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Unknown package type: {}", pkg_type),
                details: None,
            });
        }
    };

    let output = Command::new(processor_script)
        .arg("remove")
        .arg(&pkg_name)
        .env("REPO_DATA_DIR", &state.data_dir)
        .env("REPO_GPG_DIR", &state.gpg_dir)
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => HttpResponse::Ok().json(SuccessResponse {
            success: true,
            message: format!("Package {} removed successfully", pkg_name),
        }),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to remove package".to_string(),
                details: Some(stderr.to_string()),
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Failed to execute removal".to_string(),
            details: Some(e.to_string()),
        }),
    }
}

pub async fn rebuild_repo(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid or missing API key".to_string(),
            details: None,
        });
    }

    let pkg_type = path.into_inner();

    info!("Rebuilding repository: {}", pkg_type);

    let processor_script = match pkg_type.as_str() {
        "deb" => "process-deb",
        "rpm" => "process-rpm",
        "arch" => "process-arch",
        "alpine" | "apk" => "process-alpine",
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Unknown package type: {}", pkg_type),
                details: None,
            });
        }
    };

    let output = Command::new(processor_script)
        .arg("rebuild")
        .env("REPO_DATA_DIR", &state.data_dir)
        .env("REPO_GPG_DIR", &state.gpg_dir)
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => HttpResponse::Ok().json(SuccessResponse {
            success: true,
            message: format!("Repository {} rebuilt successfully", pkg_type),
        }),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to rebuild repository".to_string(),
                details: Some(stderr.to_string()),
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Failed to execute rebuild".to_string(),
            details: Some(e.to_string()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_deb_filename() {
        let (name, version, arch) = parse_package_filename("mypackage_1.0.0_amd64.deb", "deb");
        assert_eq!(name, "mypackage");
        assert_eq!(version, "1.0.0");
        assert_eq!(arch, "amd64");
    }

    #[test]
    fn test_parse_deb_filename_with_release() {
        let (name, version, arch) = parse_package_filename("nginx_1.24.0-1ubuntu1_arm64.deb", "deb");
        assert_eq!(name, "nginx");
        assert_eq!(version, "1.24.0-1ubuntu1");
        assert_eq!(arch, "arm64");
    }

    #[test]
    fn test_parse_deb_filename_all_arch() {
        let (name, version, arch) = parse_package_filename("python3-docs_3.11.0_all.deb", "deb");
        assert_eq!(name, "python3-docs");
        assert_eq!(version, "3.11.0");
        assert_eq!(arch, "all");
    }

    #[test]
    fn test_parse_rpm_filename() {
        let (name, version, arch) = parse_package_filename("mypackage-1.0.0-1.x86_64.rpm", "rpm");
        assert_eq!(name, "mypackage");
        assert_eq!(version, "1.0.0-1");
        assert_eq!(arch, "x86_64");
    }

    #[test]
    fn test_parse_rpm_filename_noarch() {
        let (name, version, arch) = parse_package_filename("python3-setuptools-50.3.2-4.noarch.rpm", "rpm");
        assert_eq!(name, "python3-setuptools");
        assert_eq!(version, "50.3.2-4");
        assert_eq!(arch, "noarch");
    }

    #[test]
    fn test_parse_arch_filename_zst() {
        let (name, version, arch) = parse_package_filename("mypackage-1.0.0-1-x86_64.pkg.tar.zst", "arch");
        assert_eq!(name, "mypackage");
        assert_eq!(version, "1.0.0-1");
        assert_eq!(arch, "x86_64");
    }

    #[test]
    fn test_parse_arch_filename_xz() {
        let (name, version, arch) = parse_package_filename("linux-headers-6.1.0-1-aarch64.pkg.tar.xz", "arch");
        assert_eq!(name, "linux-headers");
        assert_eq!(version, "6.1.0-1");
        assert_eq!(arch, "aarch64");
    }

    #[test]
    fn test_parse_arch_filename_any() {
        let (name, version, arch) = parse_package_filename("bash-completion-2.11-1-any.pkg.tar.zst", "arch");
        assert_eq!(name, "bash-completion");
        assert_eq!(version, "2.11-1");
        assert_eq!(arch, "any");
    }

    #[test]
    fn test_parse_alpine_filename() {
        let (name, version, _arch) = parse_package_filename("mypackage-1.0.0-r0.apk", "alpine");
        assert_eq!(name, "mypackage");
        assert!(version.contains("1.0.0"));
    }

    #[test]
    fn test_parse_alpine_filename_complex() {
        let (name, version, _arch) = parse_package_filename("openssl-3.1.4-r0.apk", "alpine");
        assert_eq!(name, "openssl");
        assert!(version.contains("3.1.4"));
    }

    #[test]
    fn test_parse_unknown_type() {
        let (name, version, arch) = parse_package_filename("somefile.tar.gz", "unknown");
        assert_eq!(name, "somefile.tar.gz");
        assert_eq!(version, "unknown");
        assert_eq!(arch, "unknown");
    }

    #[test]
    fn test_parse_malformed_deb_filename() {
        let (name, version, arch) = parse_package_filename("malformed.deb", "deb");
        assert_eq!(name, "malformed.deb");
        assert_eq!(version, "unknown");
        assert_eq!(arch, "unknown");
    }
}
