use actix_web::{web, HttpRequest, HttpResponse, Responder};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use std::path::PathBuf;
use tokio::fs;
use tracing::{error, info};

use crate::AppState;
use crate::utils::version_compare_optimized;

use super::auth::validate_api_key;

/// Maven repository layout:
/// /{groupId}/{artifactId}/{version}/{artifactId}-{version}.{extension}
/// /{groupId}/{artifactId}/{version}/{artifactId}-{version}.{extension}.sha1
/// /{groupId}/{artifactId}/{version}/{artifactId}-{version}.{extension}.md5
/// /{groupId}/{artifactId}/maven-metadata.xml

fn get_artifact_path(data_dir: &str, path: &str) -> PathBuf {
    PathBuf::from(data_dir).join("maven").join("repository").join(path)
}

/// GET /maven/{path:.*} - Download artifact or metadata
pub async fn get_artifact(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    // Maven requires auth for private repos
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"Maven Repository\""))
            .body("Authentication required");
    }

    let artifact_path = path.into_inner();
    let file_path = get_artifact_path(&state.data_dir, &artifact_path);

    match fs::read(&file_path).await {
        Ok(data) => {
            let content_type = guess_content_type(&artifact_path);
            HttpResponse::Ok()
                .content_type(content_type)
                .body(data)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HttpResponse::NotFound().body("Artifact not found")
        }
        Err(e) => {
            error!("Failed to read artifact {:?}: {}", file_path, e);
            HttpResponse::InternalServerError().body("Failed to read artifact")
        }
    }
}

/// PUT /maven/{path:.*} - Upload artifact or metadata
pub async fn put_artifact(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Bytes,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"Maven Repository\""))
            .body("Authentication required");
    }

    let artifact_path = path.into_inner();
    let file_path = get_artifact_path(&state.data_dir, &artifact_path);

    // Create parent directories
    if let Some(parent) = file_path.parent() {
        if let Err(e) = fs::create_dir_all(parent).await {
            error!("Failed to create directory: {}", e);
            return HttpResponse::InternalServerError().body("Failed to create directory");
        }
    }

    // Write the artifact
    if let Err(e) = fs::write(&file_path, &body).await {
        error!("Failed to write artifact: {}", e);
        return HttpResponse::InternalServerError().body("Failed to write artifact");
    }

    // If this is not a checksum file, generate checksums
    if !artifact_path.ends_with(".sha1")
        && !artifact_path.ends_with(".sha256")
        && !artifact_path.ends_with(".md5")
    {
        // Generate SHA1
        let sha1 = hex::encode(Sha1::digest(&body));
        let sha1_path = format!("{}.sha1", file_path.display());
        if let Err(e) = fs::write(&sha1_path, &sha1).await {
            error!("Failed to write SHA1: {}", e);
        }

        // Generate SHA256
        let sha256 = hex::encode(Sha256::digest(&body));
        let sha256_path = format!("{}.sha256", file_path.display());
        if let Err(e) = fs::write(&sha256_path, &sha256).await {
            error!("Failed to write SHA256: {}", e);
        }

        // Update maven-metadata.xml if this is an artifact (not pom)
        if artifact_path.ends_with(".jar") || artifact_path.ends_with(".pom") {
            if let Err(e) = update_maven_metadata(&state.data_dir, &artifact_path).await {
                error!("Failed to update maven-metadata.xml: {}", e);
            }
        }
    }

    info!("Uploaded Maven artifact: {}", artifact_path);

    HttpResponse::Created().body("Artifact uploaded")
}

/// HEAD /maven/{path:.*} - Check if artifact exists
pub async fn head_artifact(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"Maven Repository\""))
            .finish();
    }

    let artifact_path = path.into_inner();
    let file_path = get_artifact_path(&state.data_dir, &artifact_path);

    match fs::metadata(&file_path).await {
        Ok(meta) => {
            HttpResponse::Ok()
                .insert_header(("Content-Length", meta.len().to_string()))
                .insert_header(("Content-Type", guess_content_type(&artifact_path)))
                .finish()
        }
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

fn guess_content_type(path: &str) -> &'static str {
    if path.ends_with(".pom") || path.ends_with(".xml") {
        "application/xml"
    } else if path.ends_with(".jar") {
        "application/java-archive"
    } else if path.ends_with(".sha1") || path.ends_with(".sha256") || path.ends_with(".md5") {
        "text/plain"
    } else if path.ends_with(".asc") {
        "application/pgp-signature"
    } else {
        "application/octet-stream"
    }
}

/// Update maven-metadata.xml when a new version is uploaded
async fn update_maven_metadata(data_dir: &str, artifact_path: &str) -> Result<(), String> {
    // Parse the path to extract groupId, artifactId, version
    // Path format: com/example/mylib/1.0.0/mylib-1.0.0.jar
    let parts: Vec<&str> = artifact_path.split('/').collect();
    if parts.len() < 4 {
        return Ok(()); // Not enough parts to determine structure
    }

    // Last part is filename, second to last is version, third to last is artifactId
    // Everything before that is groupId
    let _filename = parts[parts.len() - 1];
    let version = parts[parts.len() - 2];
    let artifact_id = parts[parts.len() - 3];
    let group_path = parts[..parts.len() - 3].join("/");
    let group_id = group_path.replace('/', ".");

    // Path to maven-metadata.xml
    let metadata_dir = get_artifact_path(data_dir, &format!("{}/{}", group_path, artifact_id));
    let metadata_path = metadata_dir.join("maven-metadata.xml");

    // Read existing metadata or create new
    let mut versions: Vec<String> = Vec::new();
    let mut latest = version.to_string();
    let mut release = version.to_string();

    if let Ok(content) = fs::read_to_string(&metadata_path).await {
        // Simple XML parsing to extract versions
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("<version>") && line.ends_with("</version>") {
                let ver = line
                    .trim_start_matches("<version>")
                    .trim_end_matches("</version>");
                if !versions.contains(&ver.to_string()) {
                    versions.push(ver.to_string());
                }
            }
            if line.starts_with("<latest>") && line.ends_with("</latest>") {
                latest = line
                    .trim_start_matches("<latest>")
                    .trim_end_matches("</latest>")
                    .to_string();
            }
            if line.starts_with("<release>") && line.ends_with("</release>") {
                release = line
                    .trim_start_matches("<release>")
                    .trim_end_matches("</release>")
                    .to_string();
            }
        }
    }

    // Add new version if not present
    if !versions.contains(&version.to_string()) {
        versions.push(version.to_string());
    }

    // Sort versions and update latest/release
    versions.sort_by(|a, b| version_compare(a, b));
    if let Some(last) = versions.last() {
        latest = last.clone();
        if !last.contains("-SNAPSHOT") {
            release = last.clone();
        }
    }

    // Generate metadata XML
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let versions_xml: String = versions
        .iter()
        .map(|v| format!("      <version>{}</version>", v))
        .collect::<Vec<_>>()
        .join("\n");

    let metadata_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>{}</groupId>
  <artifactId>{}</artifactId>
  <versioning>
    <latest>{}</latest>
    <release>{}</release>
    <versions>
{}
    </versions>
    <lastUpdated>{}</lastUpdated>
  </versioning>
</metadata>
"#,
        group_id, artifact_id, latest, release, versions_xml, timestamp
    );

    // Write metadata
    fs::write(&metadata_path, &metadata_xml)
        .await
        .map_err(|e| e.to_string())?;

    // Generate checksums for metadata
    let sha1 = hex::encode(Sha1::digest(metadata_xml.as_bytes()));
    fs::write(format!("{}.sha1", metadata_path.display()), &sha1)
        .await
        .map_err(|e| e.to_string())?;

    let sha256 = hex::encode(Sha256::digest(metadata_xml.as_bytes()));
    fs::write(format!("{}.sha256", metadata_path.display()), &sha256)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn version_compare(a: &str, b: &str) -> std::cmp::Ordering {
    version_compare_optimized(a, b)
}

/// GET /maven/ - Simple index page
pub async fn index(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) {
        return HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Basic realm=\"Maven Repository\""))
            .body("Authentication required");
    }

    HttpResponse::Ok()
        .content_type("text/html")
        .body(r#"<!DOCTYPE html>
<html>
<head><title>Maven Repository</title></head>
<body>
<h1>Maven Repository</h1>
<p>This is a private Maven repository.</p>
<p>Configure your <code>pom.xml</code> or <code>settings.xml</code> to use this repository.</p>
</body>
</html>"#)
}
