use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use package_repo_server::handlers::{cargo, docker, health, maven, npm, nuget, packages, pypi, setup, upload};
use package_repo_server::middleware::{RequestId, SecurityHeaders};
use package_repo_server::storage::Storage;
use package_repo_server::sso_config::SsoConfig;
use package_repo_server::sso_handlers::{SsoState, configure_routes as configure_sso_routes};
use package_repo_server::sso_session::JwtManager;
use package_repo_server::sso_state::StatelessStateManager;
use package_repo_server::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration from environment
    let data_dir = std::env::var("REPO_DATA_DIR").unwrap_or_else(|_| "/data/packages".to_string());
    let gpg_dir = std::env::var("REPO_GPG_DIR").unwrap_or_else(|_| "/data/gpg".to_string());
    let api_port: u16 = std::env::var("REPO_API_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080);

    // Parse API keys
    let api_keys: Vec<String> = std::env::var("API_KEYS")
        .unwrap_or_else(|_| "default-change-me".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Startup validation
    if api_keys.iter().any(|k| k == "default-change-me") {
        warn!("Using default API key - this is insecure for production!");
        warn!("Generate a secure key with: openssl rand -hex 32");
    }

    // Ensure directories exist
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        warn!("Could not create data directory {}: {}", data_dir, e);
    }
    if let Err(e) = std::fs::create_dir_all(&gpg_dir) {
        warn!("Could not create GPG directory {}: {}", gpg_dir, e);
    }

    // Initialize storage
    // Supports any S3-compatible service: AWS S3, MinIO, DigitalOcean Spaces,
    // Backblaze B2, Cloudflare R2, Wasabi, Ceph, LocalStack, etc.
    //
    // Environment variables:
    //   S3_ENABLED=true              Enable S3 storage (default: false)
    //   S3_ENDPOINT=<url>            Custom endpoint (required for non-AWS)
    //   S3_BUCKET=<name>             Bucket name (default: packages)
    //   S3_REGION=<region>           Region (default: us-east-1)
    //   S3_FORCE_PATH_STYLE=true     Use path-style URLs (auto-detected for MinIO, etc.)
    //   S3_ACCESS_KEY_ID=<key>       Access key (or use AWS_ACCESS_KEY_ID)
    //   S3_SECRET_ACCESS_KEY=<key>   Secret key (or use AWS_SECRET_ACCESS_KEY)
    let s3_enabled = std::env::var("S3_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    let storage = if s3_enabled {
        info!("Initializing S3-compatible storage backend");
        match Storage::new_s3_from_env().await {
            Ok(s) => s,
            Err(e) => {
                panic!("Failed to initialize S3 storage: {}. Check your S3_* environment variables.", e);
            }
        }
    } else {
        info!("Using local storage backend at {}", data_dir);
        Storage::new_local(data_dir.clone())
    };

    // Initialize SSO configuration
    let sso_config = SsoConfig::from_env();
    let sso_state = if sso_config.enabled {
        info!("SSO authentication is ENABLED (stateless)");
        info!("Configured SSO providers: {}", 
            sso_config.enabled_providers()
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        
        if !sso_config.allow_api_key_auth {
            info!("API key authentication is DISABLED - only SSO allowed");
        } else {
            info!("API key authentication is enabled alongside SSO");
        }
        
        let jwt_manager = JwtManager::new(&sso_config.jwt_secret);
        let state_manager = StatelessStateManager::new(&sso_config.jwt_secret);
        
        Some(Arc::new(SsoState {
            config: sso_config.clone(),
            jwt_manager,
            state_manager,
        }))
    } else {
        info!("SSO authentication is DISABLED - using API key authentication only");
        None
    };

    let app_state = web::Data::new(AppState {
        storage: Arc::new(storage),
        api_keys,
        data_dir,
        gpg_dir,
        sso: sso_state.clone(),
    });

    info!("Starting Package Repository API server on port {}", api_port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        let mut app = App::new()
            .app_data(app_state.clone())
            .wrap(cors)
            .wrap(SecurityHeaders)  // Security headers on all responses
            .wrap(RequestId)        // Request ID tracking for audit logs
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            // Health endpoints
            .route("/health", web::get().to(health::health_check))
            .route("/ready", web::get().to(health::readiness_check));

        // Add SSO routes if enabled
        if let Some(sso) = &sso_state {
            app = app.app_data(web::Data::new(sso.clone()))
                .configure(configure_sso_routes);
            info!("SSO routes configured");
        }

        app
            // Setup scripts (one-liner install)
            .route("/setup/apt", web::get().to(setup::apt_setup))
            .route("/setup/deb", web::get().to(setup::apt_setup))
            .route("/setup/rpm", web::get().to(setup::rpm_setup))
            .route("/setup/yum", web::get().to(setup::rpm_setup))
            .route("/setup/dnf", web::get().to(setup::rpm_setup))
            .route("/setup/arch", web::get().to(setup::arch_setup))
            .route("/setup/pacman", web::get().to(setup::arch_setup))
            .route("/setup/alpine", web::get().to(setup::alpine_setup))
            .route("/setup/apk", web::get().to(setup::alpine_setup))
            .route("/setup/cargo", web::get().to(setup::cargo_setup))
            .route("/setup/npm", web::get().to(setup::npm_setup))
            .route("/setup/pypi", web::get().to(setup::pypi_setup))
            .route("/setup/pip", web::get().to(setup::pypi_setup))
            .route("/setup/maven", web::get().to(setup::maven_setup))
            .route("/setup/gradle", web::get().to(setup::maven_setup))
            .route("/setup/docker", web::get().to(setup::docker_setup))
            .route("/setup/nuget", web::get().to(setup::nuget_setup))
            .route("/setup/dotnet", web::get().to(setup::nuget_setup))
            // API v1 routes
            .service(
                web::scope("/api/v1")
                    // Upload endpoints
                    .route("/upload/{pkg_type}", web::post().to(upload::upload_package))
                    // Package management
                    .route("/packages", web::get().to(packages::list_packages))
                    .route(
                        "/packages/{pkg_type}",
                        web::get().to(packages::list_packages_by_type),
                    )
                    .route(
                        "/packages/{pkg_type}/{name}",
                        web::delete().to(packages::delete_package),
                    )
                    // Repository management
                    .route("/repos/{pkg_type}/rebuild", web::post().to(packages::rebuild_repo)),
            )
            // Cargo Registry (sparse index protocol)
            .service(
                web::scope("/cargo")
                    // Index endpoints
                    .route("/index/config.json", web::get().to(cargo::config_json))
                    .route("/index/{path:.*}", web::get().to(cargo::crate_metadata))
                    // API endpoints
                    .route("/api/v1/crates/new", web::post().to(cargo::publish_crate))
                    .route("/api/v1/crates", web::get().to(cargo::list_crates))
                    .route(
                        "/api/v1/crates/{crate_name}/{version}/download",
                        web::get().to(cargo::download_crate),
                    )
                    .route(
                        "/api/v1/crates/{crate_name}/{version}/yank",
                        web::delete().to(cargo::yank_crate),
                    )
                    .route(
                        "/api/v1/crates/{crate_name}/{version}/unyank",
                        web::put().to(cargo::unyank_crate),
                    ),
            )
            // npm Registry
            .service(
                web::scope("/npm")
                    // Scoped package routes (must come before unscoped)
                    .route(
                        "/@{scope}/{package}/-/{tarball}",
                        web::get().to(npm::download_scoped_tarball),
                    )
                    .route("/@{scope}/{package}", web::get().to(npm::get_scoped_packument))
                    .route("/@{scope}/{package}", web::put().to(npm::publish_scoped_package))
                    // Unscoped package routes
                    .route("/-/all", web::get().to(npm::list_packages))
                    .route("/{package}/-/{tarball}", web::get().to(npm::download_tarball))
                    .route("/{package}", web::get().to(npm::get_packument))
                    .route("/{package}", web::put().to(npm::publish_package)),
            )
            // PyPI Registry (PEP 503 Simple API)
            .service(
                web::scope("/pypi")
                    // Simple API (pip install)
                    .route("/simple/", web::get().to(pypi::simple_index))
                    .route("/simple/{package}/", web::get().to(pypi::simple_package))
                    // JSON API
                    .route("/pypi/{package}/json", web::get().to(pypi::package_json))
                    .route("/pypi/{package}/{version}/json", web::get().to(pypi::version_json))
                    // Upload (twine upload)
                    .route("/", web::post().to(pypi::upload_package))
                    // Download
                    .route("/packages/{package}/{version}/{filename}", web::get().to(pypi::download_package)),
            )
            // Maven Repository
            .service(
                web::scope("/maven")
                    .route("/", web::get().to(maven::index))
                    .route("/{path:.*}", web::get().to(maven::get_artifact))
                    .route("/{path:.*}", web::put().to(maven::put_artifact))
                    .route("/{path:.*}", web::head().to(maven::head_artifact)),
            )
            // Docker/OCI Registry (Distribution API v2)
            .service(
                web::scope("/v2")
                    .route("/", web::get().to(docker::version_check))
                    .route("/_catalog", web::get().to(docker::catalog))
                    .route("/{name:.*}/tags/list", web::get().to(docker::list_tags))
                    .route("/{name:.*}/blobs/uploads/", web::post().to(docker::start_upload))
                    .route("/{name:.*}/blobs/uploads/{uuid}", web::patch().to(docker::patch_upload))
                    .route("/{name:.*}/blobs/uploads/{uuid}", web::put().to(docker::complete_upload))
                    .route("/{name:.*}/blobs/{digest}", web::head().to(docker::head_blob))
                    .route("/{name:.*}/blobs/{digest}", web::get().to(docker::get_blob))
                    .route("/{name:.*}/manifests/{reference}", web::head().to(docker::head_manifest))
                    .route("/{name:.*}/manifests/{reference}", web::get().to(docker::get_manifest))
                    .route("/{name:.*}/manifests/{reference}", web::put().to(docker::put_manifest))
                    .route("/{name:.*}/manifests/{reference}", web::delete().to(docker::delete_manifest)),
            )
            // NuGet Registry (V3 API)
            .service(
                web::scope("/nuget")
                    // Service index (entry point)
                    .route("/v3/index.json", web::get().to(nuget::service_index))
                    // Package content (flat container)
                    .route("/v3-flatcontainer/{id}/index.json", web::get().to(nuget::list_versions))
                    .route("/v3-flatcontainer/{id}/{version}/{filename}", web::get().to(nuget::download_content))
                    // Registration (metadata)
                    .route("/v3/registration/{id}/index.json", web::get().to(nuget::registration_index))
                    // Search
                    .route("/query", web::get().to(nuget::search))
                    // Push/delete
                    .route("/api/v2/package", web::put().to(nuget::push_package))
                    .route("/api/v2/package/{id}/{version}", web::delete().to(nuget::delete_package)),
            )
    })
    .bind(("0.0.0.0", api_port))?
    .run()
    .await
}
