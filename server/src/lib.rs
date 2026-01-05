pub mod handlers;
pub mod middleware;
pub mod processor;
pub mod security;
pub mod storage;
pub mod utils;
pub mod sso_config;
pub mod sso_session;
pub mod sso_handlers;
pub mod sso_state;

use std::sync::Arc;
use storage::Storage;
use sso_config::SsoConfig;
use sso_handlers::SsoState;

pub struct AppState {
    pub storage: Arc<Storage>,
    pub api_keys: Vec<String>,
    pub data_dir: String,
    pub gpg_dir: String,
    pub sso: Option<Arc<SsoState>>,
}
