//! 错误类型定义 - 统一的错误处理

use std::fmt;
use thiserror::Error;

/// CNS 统一错误类型
#[derive(Error, Debug)]
pub enum CnsError {
    /// IO 错误
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// 配置错误
    #[error("Config error: {0}")]
    Config(String),

    /// 加密/解密错误
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// DNS 解析错误
    #[error("DNS resolution error: {0}")]
    Dns(String),

    /// 网络错误
    #[error("Network error: {0}")]
    Network(String),

    /// 地址解析错误
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// 超时错误
    #[error("Operation timed out")]
    Timeout,

    /// 无效的请求头
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// 无效的主机名
    #[error("Invalid hostname: {0}")]
    InvalidHost(String),
}

/// 加密相关错误
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Base64 解码错误
    Base64Error,
    
    /// 数据为空
    EmptyData,
    
    /// 解密失败
    DecryptFailed,
    
    /// 加密失败
    EncryptFailed,
    
    /// 密钥长度错误
    InvalidKeyLength,
    
    /// Nonce 生成失败
    NonceGenerationFailed,
    
    /// AEAD 认证失败
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Base64Error => write!(f, "Base64 decode error"),
            CryptoError::EmptyData => write!(f, "Empty data"),
            CryptoError::DecryptFailed => write!(f, "Decryption failed"),
            CryptoError::EncryptFailed => write!(f, "Encryption failed"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::NonceGenerationFailed => write!(f, "Nonce generation failed"),
            CryptoError::AuthenticationFailed => write!(f, "AEAD authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// CNS Result 类型别名
pub type Result<T> = std::result::Result<T, CnsError>;

/// 加密模块 Result 类型别名
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
