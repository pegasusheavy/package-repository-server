use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::Client as S3Client;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("S3 error: {0}")]
    S3(String),

    #[error("File not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Configuration for S3-compatible storage backends
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Custom endpoint URL (required for non-AWS S3-compatible services)
    /// Examples:
    /// - MinIO: "http://localhost:9000"
    /// - DigitalOcean Spaces: "https://nyc3.digitaloceanspaces.com"
    /// - Backblaze B2: "https://s3.us-west-000.backblazeb2.com"
    /// - Cloudflare R2: "https://<account-id>.r2.cloudflarestorage.com"
    /// - Wasabi: "https://s3.us-east-1.wasabisys.com"
    /// - Ceph: "http://ceph-gateway:7480"
    /// - LocalStack: "http://localhost:4566"
    pub endpoint: Option<String>,

    /// S3 bucket name
    pub bucket: String,

    /// AWS region (use "auto" or "us-east-1" for most S3-compatible services)
    pub region: String,

    /// Force path-style addressing instead of virtual-hosted style
    /// REQUIRED for: MinIO, Ceph, LocalStack, and most self-hosted solutions
    /// AWS S3 uses virtual-hosted style by default (bucket.s3.region.amazonaws.com)
    /// Path style uses: endpoint/bucket/key
    pub force_path_style: bool,

    /// Optional access key ID (falls back to AWS_ACCESS_KEY_ID env var)
    pub access_key_id: Option<String>,

    /// Optional secret access key (falls back to AWS_SECRET_ACCESS_KEY env var)
    pub secret_access_key: Option<String>,
}

impl Default for S3Config {
    fn default() -> Self {
        S3Config {
            endpoint: None,
            bucket: "packages".to_string(),
            region: "us-east-1".to_string(),
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
        }
    }
}

impl S3Config {
    /// Create config for MinIO
    pub fn minio(endpoint: &str, bucket: &str, access_key: &str, secret_key: &str) -> Self {
        S3Config {
            endpoint: Some(endpoint.to_string()),
            bucket: bucket.to_string(),
            region: "us-east-1".to_string(), // MinIO doesn't care about region
            force_path_style: true,          // Required for MinIO
            access_key_id: Some(access_key.to_string()),
            secret_access_key: Some(secret_key.to_string()),
        }
    }

    /// Create config for DigitalOcean Spaces
    pub fn digitalocean_spaces(region: &str, bucket: &str) -> Self {
        S3Config {
            endpoint: Some(format!("https://{}.digitaloceanspaces.com", region)),
            bucket: bucket.to_string(),
            region: region.to_string(),
            force_path_style: false, // DO Spaces supports virtual-hosted style
            access_key_id: None,     // Use env vars
            secret_access_key: None,
        }
    }

    /// Create config for Backblaze B2
    pub fn backblaze_b2(region: &str, bucket: &str) -> Self {
        S3Config {
            endpoint: Some(format!("https://s3.{}.backblazeb2.com", region)),
            bucket: bucket.to_string(),
            region: region.to_string(),
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
        }
    }

    /// Create config for Cloudflare R2
    pub fn cloudflare_r2(account_id: &str, bucket: &str) -> Self {
        S3Config {
            endpoint: Some(format!("https://{}.r2.cloudflarestorage.com", account_id)),
            bucket: bucket.to_string(),
            region: "auto".to_string(), // R2 uses "auto" region
            force_path_style: true,
            access_key_id: None,
            secret_access_key: None,
        }
    }

    /// Create config for Wasabi
    pub fn wasabi(region: &str, bucket: &str) -> Self {
        S3Config {
            endpoint: Some(format!("https://s3.{}.wasabisys.com", region)),
            bucket: bucket.to_string(),
            region: region.to_string(),
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
        }
    }

    /// Create config for LocalStack (local testing)
    pub fn localstack(bucket: &str) -> Self {
        S3Config {
            endpoint: Some("http://localhost:4566".to_string()),
            bucket: bucket.to_string(),
            region: "us-east-1".to_string(),
            force_path_style: true,
            access_key_id: Some("test".to_string()),
            secret_access_key: Some("test".to_string()),
        }
    }

    /// Create generic S3-compatible config
    pub fn generic(endpoint: &str, bucket: &str, region: &str, force_path_style: bool) -> Self {
        S3Config {
            endpoint: Some(endpoint.to_string()),
            bucket: bucket.to_string(),
            region: region.to_string(),
            force_path_style,
            access_key_id: None,
            secret_access_key: None,
        }
    }
}

pub enum StorageBackend {
    Local { base_path: PathBuf },
    S3 { client: S3Client, bucket: String },
}

pub struct Storage {
    backend: StorageBackend,
}

impl Storage {
    pub fn new_local(base_path: String) -> Self {
        Storage {
            backend: StorageBackend::Local {
                base_path: PathBuf::from(base_path),
            },
        }
    }

    /// Create new S3-compatible storage with full configuration
    /// This method supports all S3-compatible services including:
    /// - AWS S3
    /// - MinIO
    /// - DigitalOcean Spaces
    /// - Backblaze B2
    /// - Cloudflare R2
    /// - Wasabi
    /// - Ceph/RadosGW
    /// - LocalStack
    /// - Any S3-compatible service
    pub async fn new_s3_with_config(config: S3Config) -> Result<Self, StorageError> {
        info!(
            "Initializing S3-compatible storage: bucket={}, region={}, endpoint={:?}, path_style={}",
            config.bucket, config.region, config.endpoint, config.force_path_style
        );

        // Start building the S3 config
        let mut s3_config_builder = aws_sdk_s3::Config::builder()
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .force_path_style(config.force_path_style);

        // Set custom endpoint if provided
        if let Some(ref endpoint) = config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        // Set credentials if explicitly provided, otherwise use default credential chain
        if let (Some(access_key), Some(secret_key)) =
            (&config.access_key_id, &config.secret_access_key)
        {
            let credentials = Credentials::new(
                access_key,
                secret_key,
                None, // session token
                None, // expiry
                "package-repo-server",
            );
            s3_config_builder = s3_config_builder.credentials_provider(credentials);
        } else {
            // Use default AWS credential chain (env vars, IAM role, etc.)
            let aws_config = aws_config::defaults(BehaviorVersion::latest())
                .region(aws_sdk_s3::config::Region::new(config.region.clone()))
                .load()
                .await;

            if let Some(credentials_provider) = aws_config.credentials_provider() {
                s3_config_builder = s3_config_builder
                    .credentials_provider(credentials_provider.clone());
            }
        }

        let s3_config = s3_config_builder.build();
        let client = S3Client::from_conf(s3_config);

        Ok(Storage {
            backend: StorageBackend::S3 {
                client,
                bucket: config.bucket,
            },
        })
    }

    /// Legacy method for backwards compatibility
    /// Prefer using new_s3_with_config() for full control
    pub async fn new_s3(endpoint: Option<String>, bucket: String, region: String) -> Self {
        // Detect if we need path-style based on endpoint
        let force_path_style = endpoint.as_ref().map_or(false, |ep| {
            // Common indicators that path-style is needed
            ep.contains("localhost")
                || ep.contains("127.0.0.1")
                || ep.contains("minio")
                || ep.contains("localstack")
                || ep.contains(":9000") // MinIO default port
                || ep.contains(":4566") // LocalStack port
                || ep.contains("r2.cloudflarestorage.com")
        });

        let config = S3Config {
            endpoint,
            bucket,
            region,
            force_path_style,
            access_key_id: None,
            secret_access_key: None,
        };

        Self::new_s3_with_config(config)
            .await
            .expect("Failed to initialize S3 storage")
    }

    /// Create storage from environment variables
    /// Reads the following env vars:
    /// - S3_ENDPOINT: Custom endpoint URL (optional for AWS)
    /// - S3_BUCKET: Bucket name (default: "packages")
    /// - S3_REGION: Region (default: "us-east-1")
    /// - S3_FORCE_PATH_STYLE: "true" or "false" (auto-detected if not set)
    /// - S3_ACCESS_KEY_ID: Access key (optional, falls back to AWS_ACCESS_KEY_ID)
    /// - S3_SECRET_ACCESS_KEY: Secret key (optional, falls back to AWS_SECRET_ACCESS_KEY)
    pub async fn new_s3_from_env() -> Result<Self, StorageError> {
        let endpoint = std::env::var("S3_ENDPOINT").ok();
        let bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "packages".to_string());
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        // Determine path style
        let force_path_style = match std::env::var("S3_FORCE_PATH_STYLE") {
            Ok(val) => val.eq_ignore_ascii_case("true") || val == "1",
            Err(_) => {
                // Auto-detect based on endpoint
                endpoint.as_ref().map_or(false, |ep| {
                    ep.contains("localhost")
                        || ep.contains("127.0.0.1")
                        || ep.contains("minio")
                        || ep.contains("localstack")
                        || ep.contains(":9000")
                        || ep.contains(":4566")
                        || ep.contains("r2.cloudflarestorage.com")
                })
            }
        };

        // Check for explicit credentials
        let access_key_id = std::env::var("S3_ACCESS_KEY_ID").ok();
        let secret_access_key = std::env::var("S3_SECRET_ACCESS_KEY").ok();

        let config = S3Config {
            endpoint,
            bucket,
            region,
            force_path_style,
            access_key_id,
            secret_access_key,
        };

        Self::new_s3_with_config(config).await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        match &self.backend {
            StorageBackend::Local { base_path } => {
                let full_path = base_path.join(path);

                // Ensure parent directory exists
                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent).await?;
                }

                fs::write(&full_path, data).await?;
                debug!("Wrote {} bytes to {:?}", data.len(), full_path);
                Ok(())
            }
            StorageBackend::S3 { client, bucket } => {
                client
                    .put_object()
                    .bucket(bucket)
                    .key(path)
                    .body(data.to_vec().into())
                    .send()
                    .await
                    .map_err(|e| StorageError::S3(e.to_string()))?;

                debug!("Wrote {} bytes to s3://{}/{}", data.len(), bucket, path);
                Ok(())
            }
        }
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        match &self.backend {
            StorageBackend::Local { base_path } => {
                let full_path = base_path.join(path);

                if !full_path.exists() {
                    return Err(StorageError::NotFound(path.to_string()));
                }

                let data = fs::read(&full_path).await?;
                debug!("Read {} bytes from {:?}", data.len(), full_path);
                Ok(data)
            }
            StorageBackend::S3 { client, bucket } => {
                let response = client
                    .get_object()
                    .bucket(bucket)
                    .key(path)
                    .send()
                    .await
                    .map_err(|e| StorageError::S3(e.to_string()))?;

                let data = response
                    .body
                    .collect()
                    .await
                    .map_err(|e| StorageError::S3(e.to_string()))?
                    .into_bytes()
                    .to_vec();

                debug!("Read {} bytes from s3://{}/{}", data.len(), bucket, path);
                Ok(data)
            }
        }
    }

    pub async fn delete(&self, path: &str) -> Result<(), StorageError> {
        match &self.backend {
            StorageBackend::Local { base_path } => {
                let full_path = base_path.join(path);

                if full_path.exists() {
                    if full_path.is_dir() {
                        fs::remove_dir_all(&full_path).await?;
                    } else {
                        fs::remove_file(&full_path).await?;
                    }
                    debug!("Deleted {:?}", full_path);
                }
                Ok(())
            }
            StorageBackend::S3 { client, bucket } => {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(path)
                    .send()
                    .await
                    .map_err(|e| StorageError::S3(e.to_string()))?;

                debug!("Deleted s3://{}/{}", bucket, path);
                Ok(())
            }
        }
    }

    pub async fn exists(&self, path: &str) -> bool {
        match &self.backend {
            StorageBackend::Local { base_path } => base_path.join(path).exists(),
            StorageBackend::S3 { client, bucket } => client
                .head_object()
                .bucket(bucket)
                .key(path)
                .send()
                .await
                .is_ok(),
        }
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        match &self.backend {
            StorageBackend::Local { base_path } => {
                let full_path = base_path.join(prefix);
                let mut files = Vec::new();

                if full_path.exists() && full_path.is_dir() {
                    collect_files(&full_path, base_path, &mut files)?;
                }

                Ok(files)
            }
            StorageBackend::S3 { client, bucket } => {
                let response = client
                    .list_objects_v2()
                    .bucket(bucket)
                    .prefix(prefix)
                    .send()
                    .await
                    .map_err(|e| StorageError::S3(e.to_string()))?;

                let files = response
                    .contents()
                    .iter()
                    .filter_map(|obj| obj.key().map(String::from))
                    .collect();

                Ok(files)
            }
        }
    }
}

fn collect_files(
    dir: &Path,
    base: &Path,
    files: &mut Vec<String>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            collect_files(&path, base, files)?;
        } else {
            if let Ok(relative) = path.strip_prefix(base) {
                files.push(relative.to_string_lossy().to_string());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_local_storage_write_read() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        let test_data = b"Hello, World!";
        let path = "test/file.txt";

        // Write data
        storage.write(path, test_data).await.unwrap();

        // Read data back
        let read_data = storage.read(path).await.unwrap();
        assert_eq!(read_data, test_data);
    }

    #[tokio::test]
    async fn test_local_storage_exists() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        let path = "test/exists.txt";

        // File should not exist initially
        assert!(!storage.exists(path).await);

        // Write file
        storage.write(path, b"test").await.unwrap();

        // File should now exist
        assert!(storage.exists(path).await);
    }

    #[tokio::test]
    async fn test_local_storage_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        let path = "test/delete.txt";

        // Write file
        storage.write(path, b"to be deleted").await.unwrap();
        assert!(storage.exists(path).await);

        // Delete file
        storage.delete(path).await.unwrap();
        assert!(!storage.exists(path).await);
    }

    #[tokio::test]
    async fn test_local_storage_read_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        let result = storage.read("nonexistent/file.txt").await;
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_local_storage_list() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        // Create some files
        storage.write("packages/file1.deb", b"deb1").await.unwrap();
        storage.write("packages/file2.deb", b"deb2").await.unwrap();
        storage.write("packages/subdir/file3.deb", b"deb3").await.unwrap();

        let files = storage.list("packages").await.unwrap();
        assert_eq!(files.len(), 3);
    }

    #[tokio::test]
    async fn test_local_storage_nested_directories() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        let path = "deeply/nested/directory/structure/file.txt";
        storage.write(path, b"nested content").await.unwrap();

        let data = storage.read(path).await.unwrap();
        assert_eq!(data, b"nested content");
    }

    #[tokio::test]
    async fn test_local_storage_binary_data() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        // Binary data with various byte values
        let binary_data: Vec<u8> = (0..=255).collect();
        let path = "binary/data.bin";

        storage.write(path, &binary_data).await.unwrap();
        let read_data = storage.read(path).await.unwrap();
        assert_eq!(read_data, binary_data);
    }

    #[tokio::test]
    async fn test_local_storage_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        let path = "overwrite/file.txt";

        storage.write(path, b"original").await.unwrap();
        storage.write(path, b"overwritten").await.unwrap();

        let data = storage.read(path).await.unwrap();
        assert_eq!(data, b"overwritten");
    }

    #[tokio::test]
    async fn test_local_storage_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        let path = "empty/file.txt";
        storage.write(path, b"").await.unwrap();

        let data = storage.read(path).await.unwrap();
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn test_local_storage_delete_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_string_lossy().to_string());

        // Deleting a non-existent file should not error
        let result = storage.delete("nonexistent/file.txt").await;
        assert!(result.is_ok());
    }
}
