//! 配置模块 - 处理 JSON 配置文件的加载和解析

use crate::error::CnsError;
use serde::Deserialize;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

/// 加密模式
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMode {
    /// ChaCha20-Poly1305 加密 (推荐)
    #[default]
    Chacha20,
    /// XOR 加密 (仅用于向后兼容,不安全)
    Xor,
    /// 无加密
    None,
}

/// TLS 服务器配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TlsConfig {
    /// TLS 监听地址列表
    #[serde(default, alias = "listen_addr")]
    pub listen_addr: Vec<String>,

    /// 自动生成证书的主机名列表
    #[serde(default, alias = "AutoCertHosts")]
    pub auto_cert_hosts: Vec<String>,

    /// 证书文件路径
    #[serde(default, alias = "cert_file")]
    pub cert_file: Option<String>,

    /// 密钥文件路径
    #[serde(default, alias = "key_file")]
    pub key_file: Option<String>,
}

/// 主配置结构
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// TLS 配置
    #[serde(default, alias = "Tls")]
    pub tls: TlsConfig,

    /// HTTP 隧道监听地址列表
    #[serde(default, alias = "Listen_addr", alias = "listen_addr")]
    pub listen_addr: Vec<String>,

    /// 代理 Host 头的 key
    #[serde(default = "default_proxy_key", alias = "Proxy_key", alias = "proxy_key")]
    pub proxy_key: String,

    /// UDP 标识
    #[serde(default = "default_udp_flag", alias = "Udp_flag", alias = "udp_flag")]
    pub udp_flag: String,

    /// 加密密码 (可通过环境变量 CNS_ENCRYPT_PASSWORD 覆盖)
    #[serde(default, alias = "Encrypt_password", alias = "encrypt_password")]
    pub encrypt_password: String,

    /// 加密模式 (chacha20 | xor | none)
    #[serde(default, alias = "Encryption_mode", alias = "encryption_mode")]
    pub encryption_mode: EncryptionMode,

    /// PID 文件路径
    #[serde(default, alias = "Pid_path", alias = "pid_path")]
    pub pid_path: Option<String>,

    /// TCP 超时时间（秒）
    #[serde(default = "default_tcp_timeout", alias = "Tcp_timeout")]
    tcp_timeout: u64,

    /// UDP 超时时间（秒）
    #[serde(default = "default_udp_timeout", alias = "Udp_timeout")]
    udp_timeout: u64,

    /// 启用 TCP DNS over UDP
    #[serde(default, alias = "Enable_dns_tcpOverUdp")]
    pub enable_dns_tcp_over_udp: bool,

    /// 启用 HTTP DNS
    #[serde(default, alias = "Enable_httpDNS")]
    pub enable_http_dns: bool,

    /// 启用 TCP Fast Open
    #[serde(default, alias = "Enable_TFO")]
    pub enable_tfo: bool,
}

fn default_proxy_key() -> String {
    "Host".to_string()
}

fn default_udp_flag() -> String {
    "httpUDP".to_string()
}

fn default_tcp_timeout() -> u64 {
    600
}

fn default_udp_timeout() -> u64 {
    30
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tls: TlsConfig::default(),
            listen_addr: vec![],
            proxy_key: default_proxy_key(),
            udp_flag: default_udp_flag(),
            encrypt_password: String::new(),
            encryption_mode: EncryptionMode::default(),
            pid_path: None,
            tcp_timeout: default_tcp_timeout(),
            udp_timeout: default_udp_timeout(),
            enable_dns_tcp_over_udp: false,
            enable_http_dns: false,
            enable_tfo: false,
        }
    }
}

impl Config {
    /// 从 JSON 文件加载配置
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CnsError> {
        let content = fs::read_to_string(&path)?;
        let mut config: Config = serde_json::from_str(&content)
            .map_err(|e| CnsError::Config(format!("JSON parse error: {}", e)))?;
        
        // 从环境变量读取密码 (优先级高于配置文件)
        config.load_env_overrides();
        
        Ok(config)
    }

    /// 从环境变量加载配置覆盖
    fn load_env_overrides(&mut self) {
        // 密码
        if let Ok(password) = env::var("CNS_ENCRYPT_PASSWORD") {
            if !password.is_empty() {
                log::info!("Using encrypt password from environment variable CNS_ENCRYPT_PASSWORD");
                self.encrypt_password = password;
            }
        }

        // 加密模式
        if let Ok(mode) = env::var("CNS_ENCRYPTION_MODE") {
            match mode.to_lowercase().as_str() {
                "chacha20" => self.encryption_mode = EncryptionMode::Chacha20,
                "xor" => self.encryption_mode = EncryptionMode::Xor,
                "none" => self.encryption_mode = EncryptionMode::None,
                _ => log::warn!("Unknown CNS_ENCRYPTION_MODE: {}, using default", mode),
            }
        }
    }

    /// 验证配置合法性
    pub fn validate(&self) -> Result<(), CnsError> {
        // 检查至少有一个监听地址
        if self.listen_addr.is_empty() && self.tls.listen_addr.is_empty() {
            return Err(CnsError::Config(
                "至少需要配置一个监听地址 (listen_addr 或 tls.listen_addr)".to_string()
            ));
        }

        // 验证 HTTP 监听地址格式
        for addr in &self.listen_addr {
            self.validate_address(addr)?;
        }

        // 验证 TLS 监听地址格式
        for addr in &self.tls.listen_addr {
            self.validate_address(addr)?;
        }

        // 检查超时时间
        if self.tcp_timeout == 0 {
            return Err(CnsError::Config(
                "TCP 超时时间必须大于 0".to_string()
            ));
        }
        if self.udp_timeout == 0 {
            return Err(CnsError::Config(
                "UDP 超时时间必须大于 0".to_string()
            ));
        }

        // 检查 TLS 证书文件
        if let Some(ref cert_file) = self.tls.cert_file {
            if !Path::new(cert_file).exists() {
                return Err(CnsError::Config(
                    format!("TLS 证书文件不存在: {}", cert_file)
                ));
            }
        }
        if let Some(ref key_file) = self.tls.key_file {
            if !Path::new(key_file).exists() {
                return Err(CnsError::Config(
                    format!("TLS 密钥文件不存在: {}", key_file)
                ));
            }
        }

        // 检查加密配置
        if self.encryption_mode == EncryptionMode::Xor {
            log::warn!("⚠️  使用 XOR 加密模式,这是不安全的!建议切换到 ChaCha20");
        }

        // 检查密码配置
        if !self.encrypt_password.is_empty() && self.encryption_mode == EncryptionMode::None {
            log::warn!("配置了密码但加密模式为 none,密码将被忽略");
        }

        Ok(())
    }

    /// 验证地址格式
    fn validate_address(&self, addr: &str) -> Result<(), CnsError> {
        // 处理省略 IP 的情况 (如 ":8080")
        let addr_to_parse = if addr.starts_with(':') {
            format!("0.0.0.0{}", addr)
        } else if addr.starts_with("[::]:") || addr.starts_with("[::1]:") {
            addr.to_string()
        } else {
            addr.to_string()
        };

        // 尝试解析为 SocketAddr
        addr_to_parse.parse::<SocketAddr>().map_err(|e| {
            CnsError::Config(format!("无效的监听地址 '{}': {}", addr, e))
        })?;

        Ok(())
    }

    /// 获取 TCP 超时时间
    pub fn tcp_timeout(&self) -> Duration {
        Duration::from_secs(self.tcp_timeout)
    }

    /// 获取 UDP 超时时间
    pub fn udp_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_timeout)
    }

    /// 获取格式化后的代理 key（用于在 HTTP 头中查找）
    pub fn formatted_proxy_key(&self) -> String {
        format!("\n{}: ", self.proxy_key)
    }

    /// 是否使用 ChaCha20 加密
    pub fn use_chacha20(&self) -> bool {
        self.encryption_mode == EncryptionMode::Chacha20 && !self.encrypt_password.is_empty()
    }

    /// 是否使用 XOR 加密
    pub fn use_xor(&self) -> bool {
        self.encryption_mode == EncryptionMode::Xor && !self.encrypt_password.is_empty()
    }

    /// 是否启用加密
    pub fn encryption_enabled(&self) -> bool {
        self.encryption_mode != EncryptionMode::None && !self.encrypt_password.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.proxy_key, "Host");
        assert_eq!(config.udp_flag, "httpUDP");
        assert_eq!(config.tcp_timeout, 600);
        assert_eq!(config.udp_timeout, 30);
        assert_eq!(config.encryption_mode, EncryptionMode::Chacha20);
    }

    #[test]
    fn test_validate_empty_listen_addr() {
        let config = Config::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_valid_config() {
        let mut config = Config::default();
        config.listen_addr = vec!["0.0.0.0:8080".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_port_only_address() {
        let mut config = Config::default();
        config.listen_addr = vec![":8080".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_address() {
        let mut config = Config::default();
        config.listen_addr = vec!["invalid:address:format".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_timeout() {
        let mut config = Config::default();
        config.listen_addr = vec!["0.0.0.0:8080".to_string()];
        config.tcp_timeout = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_encryption_mode_detection() {
        let mut config = Config::default();
        config.encrypt_password = "secret".to_string();
        
        config.encryption_mode = EncryptionMode::Chacha20;
        assert!(config.use_chacha20());
        assert!(!config.use_xor());
        
        config.encryption_mode = EncryptionMode::Xor;
        assert!(!config.use_chacha20());
        assert!(config.use_xor());
        
        config.encryption_mode = EncryptionMode::None;
        assert!(!config.encryption_enabled());
    }
}

