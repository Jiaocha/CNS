//! 配置模块 - 处理 JSON 配置文件的加载和解析

use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

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

    /// 加密密码
    #[serde(default, alias = "Encrypt_password", alias = "encrypt_password")]
    pub encrypt_password: String,

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
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        // 移除 JSON 中的注释（以 "//" 开头的键）
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
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
}
