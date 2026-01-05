use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use package_repo_server::utils;

// Sample data for benchmarks
const CRATE_NAMES: &[&str] = &[
    "a",
    "ab",
    "abc",
    "serde",
    "tokio",
    "actix-web",
    "serde_json",
    "my-super-long-crate-name-here",
];

const VERSIONS: &[(&str, &str)] = &[
    ("1.0.0", "1.0.0"),
    ("1.0.0", "2.0.0"),
    ("1.0.0", "1.0.1"),
    ("1.10.0", "1.2.0"),
    ("0.1.0-alpha", "0.1.0-beta"),
    ("1.0.0", "1.0.0-rc.1"),
];

const SAMPLE_NUSPEC: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>MyPackage.Core</id>
    <version>1.2.3</version>
    <title>My Package Core</title>
    <authors>John Doe</authors>
    <owners>MyCompany</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <license type="expression">MIT</license>
    <projectUrl>https://github.com/mycompany/mypackage</projectUrl>
    <description>A sample package for benchmarking purposes with a reasonably long description that mimics real-world packages.</description>
    <releaseNotes>Initial release with core functionality.</releaseNotes>
    <copyright>Copyright 2024 MyCompany</copyright>
    <tags>benchmark test sample</tags>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="13.0.3" />
      </group>
    </dependencies>
  </metadata>
</package>"#;

fn bench_cargo_index_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("cargo_index_path");

    for name in CRATE_NAMES {
        group.bench_with_input(BenchmarkId::new("original", name), name, |b, name| {
            b.iter(|| utils::cargo_index_path(black_box(name)))
        });

        group.bench_with_input(BenchmarkId::new("optimized", name), name, |b, name| {
            b.iter(|| utils::cargo_index_path_optimized(black_box(name)))
        });
    }

    group.finish();
}

fn bench_version_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_compare");

    for (a, b) in VERSIONS {
        let id = format!("{} vs {}", a, b);
        group.bench_with_input(BenchmarkId::new("original", &id), &(a, b), |bench, (a, b)| {
            bench.iter(|| utils::version_compare(black_box(a), black_box(b)))
        });

        group.bench_with_input(BenchmarkId::new("optimized", &id), &(a, b), |bench, (a, b)| {
            bench.iter(|| utils::version_compare_optimized(black_box(a), black_box(b)))
        });
    }

    group.finish();
}

fn bench_xml_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("xml_extraction");

    let tags = ["id", "version", "description", "authors"];

    for tag in tags {
        group.bench_with_input(BenchmarkId::new("original", tag), &tag, |b, tag| {
            b.iter(|| utils::extract_xml_value(black_box(SAMPLE_NUSPEC), black_box(tag)))
        });

        group.bench_with_input(BenchmarkId::new("optimized", tag), &tag, |b, tag| {
            b.iter(|| utils::extract_xml_value_optimized(black_box(SAMPLE_NUSPEC), black_box(tag)))
        });
    }

    group.finish();
}

fn bench_crate_name_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("crate_name_validation");

    let names = ["serde", "my-crate", "my_crate", "invalid name", "crate123"];

    for name in names {
        group.bench_with_input(BenchmarkId::new("original", name), &name, |b, name| {
            b.iter(|| utils::is_valid_crate_name(black_box(name)))
        });

        group.bench_with_input(BenchmarkId::new("optimized", name), &name, |b, name| {
            b.iter(|| utils::is_valid_crate_name_optimized(black_box(name)))
        });
    }

    group.finish();
}

fn bench_pypi_normalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("pypi_normalize");

    let names = ["MyPackage", "my-package", "my_package", "my.package", "Django"];

    for name in names {
        group.bench_with_input(BenchmarkId::new("original", name), &name, |b, name| {
            b.iter(|| utils::normalize_pypi_name(black_box(name)))
        });

        group.bench_with_input(BenchmarkId::new("optimized", name), &name, |b, name| {
            b.iter(|| utils::normalize_pypi_name_optimized(black_box(name)))
        });
    }

    group.finish();
}

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    // Test with different data sizes
    let sizes = [64, 1024, 16384, 65536, 1048576]; // 64B, 1KB, 16KB, 64KB, 1MB

    for size in sizes {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("sha256", size), &data, |b, data| {
            b.iter(|| utils::sha256_hex(black_box(data)))
        });

        group.bench_with_input(BenchmarkId::new("sha1", size), &data, |b, data| {
            b.iter(|| utils::sha1_hex(black_box(data)))
        });
    }

    group.finish();
}

fn bench_json_serialization(c: &mut Criterion) {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone)]
    struct CargoIndexEntry {
        name: String,
        vers: String,
        deps: Vec<CargoDep>,
        cksum: String,
        features: std::collections::HashMap<String, Vec<String>>,
        yanked: bool,
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct CargoDep {
        name: String,
        req: String,
        features: Vec<String>,
        optional: bool,
        default_features: bool,
        target: Option<String>,
        kind: Option<String>,
    }

    let mut features = std::collections::HashMap::new();
    features.insert("default".to_string(), vec!["std".to_string()]);
    features.insert("std".to_string(), vec![]);
    features.insert("alloc".to_string(), vec![]);

    let entry = CargoIndexEntry {
        name: "serde".to_string(),
        vers: "1.0.193".to_string(),
        deps: vec![
            CargoDep {
                name: "serde_derive".to_string(),
                req: "^1.0".to_string(),
                features: vec![],
                optional: true,
                default_features: true,
                target: None,
                kind: None,
            },
        ],
        cksum: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        features,
        yanked: false,
    };

    let json_str = serde_json::to_string(&entry).unwrap();

    let mut group = c.benchmark_group("json");

    group.bench_function("serialize", |b| {
        b.iter(|| serde_json::to_string(black_box(&entry)))
    });

    group.bench_function("deserialize", |b| {
        b.iter(|| serde_json::from_str::<CargoIndexEntry>(black_box(&json_str)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cargo_index_path,
    bench_version_compare,
    bench_xml_extraction,
    bench_crate_name_validation,
    bench_pypi_normalize,
    bench_hashing,
    bench_json_serialization,
);

criterion_main!(benches);
