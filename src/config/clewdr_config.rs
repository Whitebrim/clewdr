use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::Duration,
};

use ipnet::IpNet;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::http::{Uri, uri::Scheme};
use clap::Parser;
use colored::Colorize;
use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use http::uri::Authority;
use moka::sync::Cache;
use passwords::PasswordGenerator;
use serde::{Deserialize, Serialize};
use tokio::spawn;
use tracing::error;
use url::Url;
use wreq::Proxy;

use super::{CONFIG_PATH, ENDPOINT_URL};
use crate::{
    Args,
    config::{
        CC_CLIENT_ID, CookieStatus, UselessCookie, default_check_update, default_ip,
        default_max_retries, default_port, default_skip_cool_down, default_use_real_roles,
    },
    error::ClewdrError,
    utils::enabled,
};

pub const HASHED_PLACEHOLDER: &str = "[hashed]";

fn is_argon2_hash(s: &str) -> bool {
    s.starts_with("$argon2")
}

/// Whether `validate()` will rewrite this password field (empty -> generated,
/// or plaintext -> hashed), meaning the change must be persisted once.
fn password_needs_persist(s: &str) -> bool {
    s.trim().is_empty() || !is_argon2_hash(s)
}

fn hash_password_argon2(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(65536, 3, 4, None).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

fn verify_password_argon2(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

static AUTH_CACHE: LazyLock<Cache<String, String>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(3600))
        .build()
});

fn cached_verify(token: &str, current_hash: &str) -> bool {
    let cache_key = token.to_string();
    if let Some(cached_hash) = AUTH_CACHE.get(&cache_key) {
        if cached_hash.as_str() == current_hash {
            return true;
        }
    }
    if verify_password_argon2(token, current_hash) {
        AUTH_CACHE.insert(cache_key, current_hash.to_string());
        true
    } else {
        false
    }
}

pub fn invalidate_auth_cache() {
    AUTH_CACHE.invalidate_all();
}

fn generate_password() -> String {
    let pg = PasswordGenerator {
        length: 64,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: false,
        spaces: false,
        exclude_similar_characters: true,
        strict: true,
    };

    println!("{}", "Generating random password......".green());
    pg.generate_one().unwrap()
}

/// Default list of model identifiers advertised by `/openai/v1/models` and
/// `/anthropic/v1/models`.
///
/// Besides the real Anthropic model ids this includes ClewdR's synthetic
/// `-thinking` and `-1M` variants, which the request layer interprets to
/// toggle extended thinking and the 1M-token context window respectively.
/// The list lives in `clewdr.toml` (`models = [...]`) and can be edited freely.
pub fn default_models() -> Vec<String> {
    [
        "claude-opus-4-8",
        "claude-opus-4-8-thinking",
        "claude-opus-4-8-1M",
        "claude-opus-4-8-1M-thinking",
        "claude-opus-4-7",
        "claude-opus-4-7-thinking",
        "claude-opus-4-7-1M",
        "claude-opus-4-7-1M-thinking",
        "claude-sonnet-4-6",
        "claude-sonnet-4-6-thinking",
        "claude-sonnet-4-6-1M",
        "claude-sonnet-4-6-1M-thinking",
        "claude-haiku-4-5-20251001",
        "claude-haiku-4-5-20251001-thinking",
        "claude-opus-4-6",
        "claude-opus-4-6-thinking",
        "claude-opus-4-6-1M",
        "claude-opus-4-6-1M-thinking",
        "claude-opus-4-5-20251101",
        "claude-opus-4-5-20251101-thinking",
        "claude-opus-4-5",
        "claude-opus-4-5-thinking",
        "claude-sonnet-4-5-20250929",
        "claude-sonnet-4-5-20250929-thinking",
        "claude-sonnet-4-5-20250929-1M",
        "claude-sonnet-4-5-20250929-1M-thinking",
        "claude-opus-4-1-20250805",
        "claude-opus-4-1-20250805-thinking",
        "claude-sonnet-4-20250514",
        "claude-sonnet-4-20250514-thinking",
        "claude-sonnet-4-20250514-1M",
        "claude-sonnet-4-20250514-1M-thinking",
        "claude-opus-4-20250514",
        "claude-opus-4-20250514-thinking",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Current on-disk config schema version. Bumped when a breaking layout change
/// needs migration logic in [`ClewdrConfig::new`].
pub fn default_config_version() -> u32 {
    1
}

/// Networks whose `X-Forwarded-For` / `X-Real-IP` headers are trusted when
/// determining the real client IP. Defaults to loopback plus the RFC1918 /
/// ULA private ranges, which covers the usual "nginx in front on the same
/// host / in the same Docker network" deployment. A request whose TCP peer is
/// outside these ranges is treated as a direct (untrusted) connection and its
/// forwarding headers are ignored — see [`crate::security::extract_client_ip`].
pub fn default_trusted_proxies() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]
    .iter()
    .map(|s| s.parse().expect("valid default CIDR"))
    .collect()
}

/// A struct representing the configuration of the application
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClewdrConfig {
    // key configurations
    #[serde(default)]
    pub cookie_array: HashSet<CookieStatus>,
    #[serde(default)]
    pub wasted_cookie: HashSet<UselessCookie>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_array_enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasted_cookie_enc: Option<String>,

    // Server settings, cannot hot reload
    #[serde(default = "default_ip")]
    ip: IpAddr,
    #[serde(default = "default_port")]
    port: u16,

    // App settings, can hot reload, but meaningless
    #[serde(default = "default_check_update")]
    pub check_update: bool,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default)]
    pub no_fs: bool,
    #[serde(default)]
    pub log_to_file: bool,

    // Network settings, can hot reload
    #[serde(default)]
    password: String,
    #[serde(default)]
    admin_password: String,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub rproxy: Option<Url>,

    // Api settings, can hot reload
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    #[serde(default)]
    pub preserve_chats: bool,
    #[serde(default)]
    pub web_search: bool,
    #[serde(default)]
    pub enable_web_count_tokens: bool,
    #[serde(default)]
    pub sanitize_messages: bool,

    // Cookie settings, can hot reload
    #[serde(default)]
    pub skip_first_warning: bool,
    #[serde(default)]
    pub skip_second_warning: bool,
    #[serde(default)]
    pub skip_restricted: bool,
    #[serde(default)]
    pub skip_non_pro: bool,
    #[serde(default = "default_skip_cool_down")]
    pub skip_rate_limit: bool,
    #[serde(default)]
    pub skip_normal_pro: bool,

    // Prompt configurations, can hot reload
    #[serde(default = "default_use_real_roles")]
    pub use_real_roles: bool,
    #[serde(default)]
    pub custom_h: Option<String>,
    #[serde(default)]
    pub custom_a: Option<String>,
    #[serde(default)]
    pub custom_prompt: String,

    // Claude Code settings, can hot reload
    #[serde(default)]
    pub claude_code_client_id: Option<String>,
    #[serde(default)]
    pub custom_system: Option<String>,

    // Security settings
    #[serde(default)]
    pub admin_ip_allowlist: Vec<IpNet>,
    #[serde(default)]
    pub api_ip_allowlist: Vec<IpNet>,
    /// Reverse proxies whose forwarding headers are trusted (see Bug C).
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<IpNet>,

    // Models advertised by the model-list endpoints, can hot reload
    #[serde(default = "default_models")]
    pub models: Vec<String>,

    // On-disk schema version, used for future config migrations
    #[serde(default = "default_config_version")]
    pub config_version: u32,

    // Skip field, can hot reload
    #[serde(skip)]
    pub wreq_proxy: Option<Proxy>,
}

impl Default for ClewdrConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            check_update: default_check_update(),
            auto_update: false,
            cookie_array: HashSet::new(),
            wasted_cookie: HashSet::new(),
            cookie_array_enc: None,
            wasted_cookie_enc: None,
            password: String::new(),
            admin_password: String::new(),
            proxy: None,
            ip: default_ip(),
            port: default_port(),
            rproxy: None,
            use_real_roles: default_use_real_roles(),
            custom_prompt: String::new(),
            custom_h: None,
            custom_a: None,
            wreq_proxy: None,
            preserve_chats: false,
            web_search: false,
            enable_web_count_tokens: false,
            sanitize_messages: false,
            skip_first_warning: false,
            skip_second_warning: false,
            skip_restricted: false,
            skip_non_pro: false,
            skip_rate_limit: default_skip_cool_down(),
            skip_normal_pro: false,
            claude_code_client_id: None,
            custom_system: None,
            no_fs: false,
            log_to_file: false,
            admin_ip_allowlist: Vec::new(),
            api_ip_allowlist: Vec::new(),
            trusted_proxies: default_trusted_proxies(),
            models: default_models(),
            config_version: default_config_version(),
        }
    }
}

impl Display for ClewdrConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // one line per field
        let authority = self.address();
        let authority: Authority = authority.to_string().parse().map_err(|_| std::fmt::Error)?;
        let web_url = Uri::builder()
            .scheme(Scheme::HTTP)
            .authority(authority.to_string())
            .path_and_query("")
            .build()
            .map_err(|_| std::fmt::Error)?;
        let pw_display = if is_argon2_hash(&self.password) {
            "[hashed]".dimmed()
        } else {
            self.password.as_str().yellow()
        };
        let apw_display = if is_argon2_hash(&self.admin_password) {
            "[hashed]".dimmed()
        } else {
            self.admin_password.as_str().yellow()
        };
        let base = web_url.to_string();
        write!(
            f,
            "Anthropic-native Endpoint:  {}  (Claude Code: {})\n\
            OpenAI-compatible Endpoint: {}  (Claude Code: {})\n\
            API Password: {}\n\
            Web Admin Endpoint: {}\n\
            Web Admin Password: {}\n",
            (base.clone() + "anthropic/v1").green().underline(),
            (base.clone() + "anthropic/code/v1").green().underline(),
            (base.clone() + "openai/v1").green().underline(),
            (base.clone() + "openai/code/v1").green().underline(),
            pw_display,
            web_url.to_string().green().underline(),
            apw_display,
        )?;
        if let Some(ref proxy) = self.proxy {
            writeln!(f, "Proxy: {}", proxy.to_string().blue())?;
        }
        if let Some(ref rproxy) = self.rproxy {
            writeln!(f, "Reverse Proxy: {}", rproxy.to_string().blue())?;
        }
        writeln!(f, "Skip Free: {}", enabled(self.skip_non_pro))?;
        writeln!(f, "Skip restricted: {}", enabled(self.skip_restricted))?;
        writeln!(
            f,
            "Skip second warning: {}",
            enabled(self.skip_second_warning)
        )?;
        writeln!(
            f,
            "Skip first warning: {}",
            enabled(self.skip_first_warning)
        )?;
        writeln!(f, "Skip normal Pro: {}", enabled(self.skip_normal_pro))?;
        writeln!(f, "Skip rate limit: {}", enabled(self.skip_rate_limit))?;
        writeln!(
            f,
            "Web count_tokens: {}",
            enabled(self.enable_web_count_tokens)
        )?;
        Ok(())
    }
}

impl From<&ClewdrConfig> for clewdr_types::ConfigApi {
    fn from(c: &ClewdrConfig) -> Self {
        Self {
            ip: c.ip.to_string(),
            port: c.port,
            check_update: c.check_update,
            auto_update: c.auto_update,
            password: if is_argon2_hash(&c.password) {
                HASHED_PLACEHOLDER.to_string()
            } else {
                c.password.clone()
            },
            admin_password: if is_argon2_hash(&c.admin_password) {
                HASHED_PLACEHOLDER.to_string()
            } else {
                c.admin_password.clone()
            },
            proxy: c.proxy.clone(),
            rproxy: c.rproxy.as_ref().map(|u| u.to_string()),
            max_retries: c.max_retries,
            preserve_chats: c.preserve_chats,
            web_search: c.web_search,
            enable_web_count_tokens: c.enable_web_count_tokens,
            sanitize_messages: c.sanitize_messages,
            skip_first_warning: c.skip_first_warning,
            skip_second_warning: c.skip_second_warning,
            skip_restricted: c.skip_restricted,
            skip_non_pro: c.skip_non_pro,
            skip_rate_limit: c.skip_rate_limit,
            skip_normal_pro: c.skip_normal_pro,
            use_real_roles: c.use_real_roles,
            custom_h: c.custom_h.clone(),
            custom_a: c.custom_a.clone(),
            custom_prompt: c.custom_prompt.clone(),
            claude_code_client_id: c.claude_code_client_id.clone(),
            custom_system: c.custom_system.clone(),
        }
    }
}

impl From<clewdr_types::ConfigApi> for ClewdrConfig {
    fn from(c: clewdr_types::ConfigApi) -> Self {
        Self {
            ip: c.ip.parse().unwrap_or(default_ip()),
            port: c.port,
            check_update: c.check_update,
            auto_update: c.auto_update,
            password: c.password,
            admin_password: c.admin_password,
            proxy: c.proxy,
            rproxy: c.rproxy.and_then(|s| Url::parse(&s).ok()),
            max_retries: c.max_retries,
            preserve_chats: c.preserve_chats,
            web_search: c.web_search,
            enable_web_count_tokens: c.enable_web_count_tokens,
            sanitize_messages: c.sanitize_messages,
            skip_first_warning: c.skip_first_warning,
            skip_second_warning: c.skip_second_warning,
            skip_restricted: c.skip_restricted,
            skip_non_pro: c.skip_non_pro,
            skip_rate_limit: c.skip_rate_limit,
            skip_normal_pro: c.skip_normal_pro,
            use_real_roles: c.use_real_roles,
            custom_h: c.custom_h,
            custom_a: c.custom_a,
            custom_prompt: c.custom_prompt,
            claude_code_client_id: c.claude_code_client_id,
            custom_system: c.custom_system,
            ..Default::default()
        }
    }
}

impl ClewdrConfig {
    pub fn user_auth(&self, key: &str) -> bool {
        if is_argon2_hash(&self.password) {
            cached_verify(key, &self.password)
        } else {
            key == self.password
        }
    }

    pub fn admin_auth(&self, key: &str) -> bool {
        if is_argon2_hash(&self.admin_password) {
            cached_verify(key, &self.admin_password)
        } else {
            key == self.admin_password
        }
    }

    pub fn cc_client_id(&self) -> String {
        self.claude_code_client_id
            .as_deref()
            .unwrap_or(CC_CLIENT_ID)
            .to_string()
    }

    /// Loads configuration from files and environment variables
    /// Combines settings from config.toml, clewdr.toml, and environment variables
    /// Also loads cookies from a file if specified
    ///
    /// # Returns
    /// * Config instance
    pub fn new() -> Self {
        // Load config from TOML then override with environment variables.
        // Use double underscore "__" to map nested keys.
        let config_existed = CONFIG_PATH.exists();
        let mut config: ClewdrConfig = match Figment::from(Toml::file(CONFIG_PATH.as_path()))
            .admerge(Env::prefixed("CLEWDR_").split("__"))
            .extract_lossy()
        {
            Ok(c) => c,
            Err(e) => {
                if config_existed {
                    // The file is there but won't parse. Overwriting it with
                    // defaults would destroy passwords, allowlists and encrypted
                    // cookies (Bug A/E), so refuse to start instead.
                    eprintln!(
                        "FATAL: failed to parse config at {}: {e}",
                        CONFIG_PATH.display()
                    );
                    eprintln!(
                        "Refusing to start so the existing config is not overwritten. \
                         Fix the file or move it aside, then restart."
                    );
                    std::process::exit(1);
                }
                error!("Failed to load config: {e}");
                ClewdrConfig::default()
            }
        };

        // Decrypt encrypted cookies. The encrypted blobs are only cleared from
        // the in-memory config when decryption fully succeeds; on failure they
        // are kept and `decrypt_failed` is set so we never persist over them.
        let mut decrypt_failed = false;
        let key_path = CONFIG_PATH.with_extension("key");
        let has_encrypted = config.cookie_array_enc.is_some() || config.wasted_cookie_enc.is_some();
        if has_encrypted {
            match crate::security::get_data_key(&key_path, false) {
                Ok(key) => {
                    let mut ok = true;
                    if let Some(ref enc) = config.cookie_array_enc {
                        match crate::security::decrypt_data(&key, enc) {
                            Some(plain) => match serde_json::from_slice::<HashSet<CookieStatus>>(
                                &plain,
                            ) {
                                Ok(cookies) => config.cookie_array.extend(cookies),
                                Err(e) => {
                                    error!("Failed to deserialize decrypted cookies: {e}");
                                    ok = false;
                                }
                            },
                            None => {
                                error!(
                                    "Failed to decrypt cookie_array_enc — wrong clewdr.key or \
                                     corrupted data. Encrypted cookies left intact on disk; \
                                     manual re-import may be required."
                                );
                                ok = false;
                            }
                        }
                    }
                    if let Some(ref enc) = config.wasted_cookie_enc {
                        match crate::security::decrypt_data(&key, enc) {
                            Some(plain) => {
                                match serde_json::from_slice::<HashSet<UselessCookie>>(&plain) {
                                    Ok(cookies) => config.wasted_cookie.extend(cookies),
                                    Err(e) => {
                                        error!("Failed to deserialize decrypted wasted cookies: {e}");
                                        ok = false;
                                    }
                                }
                            }
                            None => {
                                error!("Failed to decrypt wasted_cookie_enc — left intact on disk.");
                                ok = false;
                            }
                        }
                    }
                    if ok {
                        config.cookie_array_enc = None;
                        config.wasted_cookie_enc = None;
                    } else {
                        decrypt_failed = true;
                    }
                }
                Err(msg) => {
                    eprintln!("FATAL: {msg}");
                    std::process::exit(1);
                }
            }
        }

        let mut cookie_file_loaded = false;
        if let Some(ref f) = Args::try_parse().ok().and_then(|a| a.file) {
            // load cookies from file
            if f.exists() {
                if let Ok(cookies) = std::fs::read_to_string(f) {
                    let cookies = cookies
                        .lines()
                        .filter_map(|line| CookieStatus::new(line, None).ok());
                    config.cookie_array.extend(cookies);
                    cookie_file_loaded = true;
                } else {
                    error!("Failed to read cookie file: {}", f.display());
                }
            } else {
                error!("Cookie file not found: {}", f.display());
            }
        }

        // `validate()` rewrites the password fields when they are empty (first
        // run) or still plaintext (migration); both need to be persisted once.
        let password_needs_persist =
            password_needs_persist(&config.password) || password_needs_persist(&config.admin_password);

        let config = config.validate();

        // Only write the config back to disk when there is an actual reason to:
        // a fresh first run, a password that was just generated/migrated, or
        // cookies imported from a file. A clean restart of an already-persisted
        // config no longer rewrites the file (Bug A), and a failed cookie
        // decrypt never triggers a save that would wipe the blob (Bug E).
        let should_save = !config.no_fs
            && !decrypt_failed
            && (!config_existed || password_needs_persist || cookie_file_loaded);
        if should_save {
            let config_clone = config.to_owned();
            spawn(async move {
                config_clone.save().await.unwrap_or_else(|e| {
                    error!("Failed to save config: {}", e);
                });
            });
        }
        config
    }

    /// Gets the API endpoint for the Claude service
    /// Returns the reverse proxy URL if configured, otherwise the default endpoint
    ///
    /// # Returns
    /// The URL for the API endpoint
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn admin_password(&self) -> &str {
        &self.admin_password
    }

    pub fn endpoint(&self) -> Url {
        if let Some(ref proxy) = self.rproxy {
            return proxy.to_owned();
        }
        ENDPOINT_URL.to_owned()
    }

    /// address of proxy
    pub fn address(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    /// Save the configuration to a file
    pub async fn save(&self) -> Result<(), ClewdrError> {
        if self.no_fs {
            return Ok(());
        }
        if let Some(parent) = CONFIG_PATH.parent()
            && !parent.exists()
        {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut save_config = self.clone();

        // Encrypt cookies before saving
        let key_path = CONFIG_PATH.with_extension("key");
        if let Ok(key) = crate::security::get_data_key(&key_path, true) {
            if !save_config.cookie_array.is_empty() {
                if let Ok(json) = serde_json::to_vec(&save_config.cookie_array) {
                    save_config.cookie_array_enc =
                        Some(crate::security::encrypt_data(&key, &json));
                }
                save_config.cookie_array = HashSet::new();
            }
            if !save_config.wasted_cookie.is_empty() {
                if let Ok(json) = serde_json::to_vec(&save_config.wasted_cookie) {
                    save_config.wasted_cookie_enc =
                        Some(crate::security::encrypt_data(&key, &json));
                }
                save_config.wasted_cookie = HashSet::new();
            }
        }

        let path = CONFIG_PATH.as_path();
        let data = toml::ser::to_string_pretty(&save_config)?;
        tokio::fs::write(path, data).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(path, perms).await?;
        }
        Ok(())
    }

    /// Validate the configuration
    pub fn validate(mut self) -> Self {
        if self.password.trim().is_empty() {
            let plain = generate_password();
            println!("{}: {}", "API Password".green(), plain.yellow());
            self.password = hash_password_argon2(&plain);
        } else if !is_argon2_hash(&self.password) {
            self.password = hash_password_argon2(&self.password);
        }
        if self.admin_password.trim().is_empty() {
            let plain = generate_password();
            println!("{}: {}", "Admin Password".green(), plain.yellow());
            self.admin_password = hash_password_argon2(&plain);
        } else if !is_argon2_hash(&self.admin_password) {
            self.admin_password = hash_password_argon2(&self.admin_password);
        }
        invalidate_auth_cache();
        self.cookie_array = self.cookie_array.into_iter().map(|x| x.reset()).collect();
        self.wreq_proxy = self.proxy.to_owned().and_then(|p| {
            Proxy::all(p)
                .inspect_err(|e| {
                    self.proxy = None;
                    error!("Failed to parse proxy: {}", e);
                })
                .ok()
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test_password_12345";
        let hash = hash_password_argon2(password);
        assert!(is_argon2_hash(&hash));
        assert!(verify_password_argon2(password, &hash));
        assert!(!verify_password_argon2("wrong_password", &hash));
    }

    #[test]
    fn test_is_argon2_hash() {
        assert!(is_argon2_hash("$argon2id$v=19$m=65536,t=3,p=4$salt$hash"));
        assert!(!is_argon2_hash("plaintext_password"));
        assert!(!is_argon2_hash(""));
        assert!(!is_argon2_hash("[hashed]"));
    }

    #[test]
    fn test_cached_verify() {
        let password = "cached_test_pw";
        let hash = hash_password_argon2(password);
        assert!(cached_verify(password, &hash));
        // second call should hit cache
        assert!(cached_verify(password, &hash));
        assert!(!cached_verify("wrong", &hash));
    }

    #[test]
    fn test_validate_hashes_plaintext() {
        let mut config = ClewdrConfig::default();
        config.password = "my_plain_password".to_string();
        config.admin_password = "my_admin_password".to_string();
        let validated = config.validate();
        assert!(is_argon2_hash(&validated.password));
        assert!(is_argon2_hash(&validated.admin_password));
        assert!(validated.user_auth("my_plain_password"));
        assert!(validated.admin_auth("my_admin_password"));
    }

    #[test]
    fn test_validate_preserves_existing_hash() {
        let hash = hash_password_argon2("original");
        let mut config = ClewdrConfig::default();
        config.password = hash.clone();
        config.admin_password = hash.clone();
        let validated = config.validate();
        assert_eq!(validated.password, hash);
        assert_eq!(validated.admin_password, hash);
    }

    #[test]
    fn test_validate_generates_when_empty() {
        let config = ClewdrConfig::default();
        let validated = config.validate();
        assert!(is_argon2_hash(&validated.password));
        assert!(is_argon2_hash(&validated.admin_password));
    }

    #[test]
    fn test_cache_invalidation_on_password_change() {
        let password = "old_password";
        let old_hash = hash_password_argon2(password);
        assert!(cached_verify(password, &old_hash));

        let new_hash = hash_password_argon2("new_password");
        // old token should fail against new hash (cache entry hash won't match)
        assert!(!cached_verify(password, &new_hash));
    }

    #[test]
    fn test_hashed_placeholder_in_config_api() {
        let hash = hash_password_argon2("secret");
        let mut config = ClewdrConfig::default();
        config.password = hash;
        config.admin_password = hash_password_argon2("admin_secret");
        let api: clewdr_types::ConfigApi = (&config).into();
        assert_eq!(api.password, HASHED_PLACEHOLDER);
        assert_eq!(api.admin_password, HASHED_PLACEHOLDER);
    }
}
