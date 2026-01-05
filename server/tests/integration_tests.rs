use actix_web::{test, web, App};
use serde_json::Value;
use std::sync::Arc;

// Import from the main crate
use package_repo_server::handlers::{health, packages, setup};
use package_repo_server::storage::Storage;
use package_repo_server::AppState;

fn create_test_app_state(temp_dir: &tempfile::TempDir) -> web::Data<AppState> {
    let data_dir = temp_dir.path().join("packages");
    let gpg_dir = temp_dir.path().join("gpg");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&gpg_dir).unwrap();

    web::Data::new(AppState {
        storage: Arc::new(Storage::new_local(data_dir.to_string_lossy().to_string())),
        api_keys: vec!["test-api-key".to_string(), "another-key".to_string()],
        data_dir: data_dir.to_string_lossy().to_string(),
        gpg_dir: gpg_dir.to_string_lossy().to_string(),
    })
}

#[actix_rt::test]
async fn test_health_check() {
    let app = test::init_service(
        App::new().route("/health", web::get().to(health::health_check)),
    )
    .await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "healthy");
    assert!(body["version"].is_string());
}

#[actix_rt::test]
async fn test_readiness_check() {
    let app = test::init_service(
        App::new().route("/ready", web::get().to(health::readiness_check)),
    )
    .await;

    let req = test::TestRequest::get().uri("/ready").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ready");
    assert_eq!(body["services"]["storage"], "ok");
    assert_eq!(body["services"]["processor"], "ok");
}

#[actix_rt::test]
async fn test_list_packages_empty() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_state = create_test_app_state(&temp_dir);

    let app = test::init_service(
        App::new()
            .app_data(app_state)
            .route("/api/v1/packages", web::get().to(packages::list_packages)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/packages")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 0);
    assert!(body["packages"].as_array().unwrap().is_empty());
}

#[actix_rt::test]
async fn test_list_packages_by_type_empty() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_state = create_test_app_state(&temp_dir);

    let app = test::init_service(
        App::new()
            .app_data(app_state)
            .route(
                "/api/v1/packages/{pkg_type}",
                web::get().to(packages::list_packages_by_type),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/packages/deb")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 0);
}

#[actix_rt::test]
async fn test_list_packages_with_deb_files() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_state = create_test_app_state(&temp_dir);

    // Create mock deb files
    let pool_dir = temp_dir.path().join("packages/deb/pool");
    std::fs::create_dir_all(&pool_dir).unwrap();
    std::fs::write(
        pool_dir.join("test-package_1.0.0_amd64.deb"),
        "fake deb content",
    )
    .unwrap();
    std::fs::write(
        pool_dir.join("another-pkg_2.0.0_arm64.deb"),
        "fake deb content 2",
    )
    .unwrap();

    let app = test::init_service(
        App::new()
            .app_data(app_state)
            .route(
                "/api/v1/packages/{pkg_type}",
                web::get().to(packages::list_packages_by_type),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/packages/deb")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 2);

    let packages = body["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 2);
}

#[actix_rt::test]
async fn test_list_packages_pagination() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_state = create_test_app_state(&temp_dir);

    // Create multiple mock deb files
    let pool_dir = temp_dir.path().join("packages/deb/pool");
    std::fs::create_dir_all(&pool_dir).unwrap();
    for i in 0..10 {
        std::fs::write(
            pool_dir.join(format!("package-{}_1.0.0_amd64.deb", i)),
            format!("fake deb content {}", i),
        )
        .unwrap();
    }

    let app = test::init_service(
        App::new()
            .app_data(app_state)
            .route(
                "/api/v1/packages/{pkg_type}",
                web::get().to(packages::list_packages_by_type),
            ),
    )
    .await;

    // Test pagination with limit and offset
    let req = test::TestRequest::get()
        .uri("/api/v1/packages/deb?limit=3&offset=2")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 10); // Total count remains 10
    let packages = body["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 3); // But only 3 returned due to limit
}

#[actix_rt::test]
async fn test_apt_setup_script() {
    let app = test::init_service(
        App::new().route("/setup/apt", web::get().to(setup::apt_setup)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/setup/apt")
        .insert_header(("Host", "packages.example.com"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body = test::read_body(resp).await;
    let script = String::from_utf8(body.to_vec()).unwrap();

    // Verify script contains expected content
    assert!(script.contains("#!/bin/bash"));
    assert!(script.contains("apt-get update"));
    assert!(script.contains("gpg"));
}

#[actix_rt::test]
async fn test_rpm_setup_script() {
    let app = test::init_service(
        App::new().route("/setup/rpm", web::get().to(setup::rpm_setup)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/setup/rpm")
        .insert_header(("Host", "packages.example.com"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body = test::read_body(resp).await;
    let script = String::from_utf8(body.to_vec()).unwrap();

    assert!(script.contains("#!/bin/bash"));
    assert!(script.contains("yum") || script.contains("dnf") || script.contains(".repo"));
}

#[actix_rt::test]
async fn test_arch_setup_script() {
    let app = test::init_service(
        App::new().route("/setup/arch", web::get().to(setup::arch_setup)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/setup/arch")
        .insert_header(("Host", "packages.example.com"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body = test::read_body(resp).await;
    let script = String::from_utf8(body.to_vec()).unwrap();

    assert!(script.contains("#!/bin/bash"));
    assert!(script.contains("pacman"));
}

#[actix_rt::test]
async fn test_alpine_setup_script() {
    let app = test::init_service(
        App::new().route("/setup/alpine", web::get().to(setup::alpine_setup)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/setup/alpine")
        .insert_header(("Host", "packages.example.com"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body = test::read_body(resp).await;
    let script = String::from_utf8(body.to_vec()).unwrap();

    assert!(script.contains("#!/bin/sh"));
    assert!(script.contains("apk") || script.contains("/etc/apk"));
}

#[actix_rt::test]
async fn test_list_packages_with_arch_filter() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let app_state = create_test_app_state(&temp_dir);

    // Create mock deb files with different architectures
    let pool_dir = temp_dir.path().join("packages/deb/pool");
    std::fs::create_dir_all(&pool_dir).unwrap();
    std::fs::write(
        pool_dir.join("pkg1_1.0.0_amd64.deb"),
        "amd64 content",
    )
    .unwrap();
    std::fs::write(
        pool_dir.join("pkg2_1.0.0_arm64.deb"),
        "arm64 content",
    )
    .unwrap();
    std::fs::write(
        pool_dir.join("pkg3_1.0.0_all.deb"),
        "all content",
    )
    .unwrap();

    let app = test::init_service(
        App::new()
            .app_data(app_state)
            .route(
                "/api/v1/packages/{pkg_type}",
                web::get().to(packages::list_packages_by_type),
            ),
    )
    .await;

    // Filter by amd64
    let req = test::TestRequest::get()
        .uri("/api/v1/packages/deb?arch=amd64")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    // Should get amd64 and "all" packages
    let packages = body["packages"].as_array().unwrap();
    assert!(packages.len() >= 1);
}
