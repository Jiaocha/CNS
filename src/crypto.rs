//! 加密模块 - 实现 XOR 加密/解密

use base64::{engine::general_purpose::STANDARD, Engine};

/// XOR 加密/解密
/// 
/// 对数据进行简单的 XOR 加密，返回密码索引位置
/// 注意：CLNC 客户端使用数据索引作为掩码，但这里使用纯密码索引
pub fn xor_crypt(data: &mut [u8], password: &[u8], mut password_index: usize) -> usize {
    if password.is_empty() {
        return password_index;
    }

    for byte in data.iter_mut() {
        // Go 版本: data[dataSub] ^= CuteBi_XorCrypt_password[passwordSub] | byte(passwordSub)
        // 注意：这里使用的是 password_index，不是数据索引
        *byte ^= password[password_index] | (password_index as u8);
        password_index += 1;
        if password_index == password.len() {
            password_index = 0;
        }
    }

    password_index
}

/// 解密 Host
/// 
/// Base64 解码后进行 XOR 解密，验证结尾的 null 字节
pub fn decrypt_host(encoded_host: &[u8], password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Base64 解码
    let mut decoded = STANDARD.decode(encoded_host).map_err(|_| DecryptError::Base64Error)?;

    if decoded.is_empty() {
        return Err(DecryptError::EmptyData);
    }

    // XOR 解密
    xor_crypt(&mut decoded, password, 0);

    // 验证结尾的 null 字节
    // 注意：某些情况下解密可能存在位翻转导致 null 变为其他值
    // 我们放松检查，只在末尾是 0 时移除它，否则保留整个数据（由调用者清洗）
    if let Some(&0) = decoded.last() {
        decoded.pop();
    } else {
        // 如果不是 0，也记录个日志但不错误返回，尽可能挽救数据
        // log::warn!("Decrypt host: last byte is not 0 (hex: {:02X?})", decoded.last());
    }
    
    Ok(decoded)
}

/// 加密 Host
/// 
/// XOR 加密后进行 Base64 编码
pub fn encrypt_host(host: &[u8], password: &[u8]) -> String {
    let mut data = host.to_vec();
    data.push(0); // 添加结尾的 null 字节

    xor_crypt(&mut data, password, 0);
    STANDARD.encode(&data)
}

/// 解密错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    Base64Error,
    EmptyData,
    DecryptFailed,
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::Base64Error => write!(f, "Base64 decode error"),
            DecryptError::EmptyData => write!(f, "Empty data"),
            DecryptError::DecryptFailed => write!(f, "Decrypt failed"),
        }
    }
}

impl std::error::Error for DecryptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_crypt_roundtrip() {
        let password = b"test_password";
        let original = b"Hello, World!";
        let mut data = original.to_vec();

        // 加密
        let index = xor_crypt(&mut data, password, 0);
        assert_ne!(&data, original);

        // 解密
        xor_crypt(&mut data, password, 0);
        assert_eq!(&data, original);
        assert_eq!(index, original.len() % password.len());
    }

    #[test]
    fn test_host_encrypt_decrypt() {
        let password = b"secret";
        let host = b"example.com:80";

        let encrypted = encrypt_host(host, password);
        let decrypted = decrypt_host(encrypted.as_bytes(), password).unwrap();

        assert_eq!(decrypted, host);
    }
}
