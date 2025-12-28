//! 加密模块 - 实现 XOR 加密/解密

use base64::{engine::general_purpose::STANDARD, Engine};

/// XOR 加密/解密
/// 
/// 对数据进行 XOR 加密，返回新的密码索引
/// 算法: byte ^= password[pwd_idx] | (pwd_idx as u8)
/// 
/// 注意：原始 Go 客户端使用 password_index 作为掩码，不是 stream_offset！
/// Go 代码: data[dataSub] ^= CuteBi_XorCrypt_password[passwordSub] | byte(passwordSub)
pub fn xor_crypt(data: &mut [u8], password: &[u8], mut password_index: usize, _stream_offset: usize) -> usize {
    if password.is_empty() {
        return password_index;
    }

    for byte in data.iter_mut() {
        // 使用密码索引(mod 256)作为掩码的一部分，与原始 Go 客户端保持一致
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
/// 
/// 算法与原始 Go 客户端完全匹配：
/// 1. Base64 解码
/// 2. XOR 解密 (byte ^= password[pwd_idx] | pwd_idx)
/// 3. 验证并移除结尾的 null 字节
pub fn decrypt_host(encoded_host: &[u8], password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Base64 解码
    let decoded = STANDARD.decode(encoded_host).map_err(|_| DecryptError::Base64Error)?;

    if decoded.is_empty() {
        return Err(DecryptError::EmptyData);
    }

    // XOR 解密
    let mut decrypted = decoded;
    xor_crypt(&mut decrypted, password, 0, 0);

    // 验证结尾 null 字节 (与 Go 客户端一致的验证逻辑)
    if decrypted.last() != Some(&0) {
        log::warn!("Decrypt failed: no trailing null byte, data={:?}", decrypted);
        return Err(DecryptError::DecryptFailed);
    }
    
    // 移除结尾 null 字节
    decrypted.pop();

    log::debug!("Decrypted host: {:?}", String::from_utf8_lossy(&decrypted));
    Ok(decrypted)
}

/// 加密 Host
/// 
/// XOR 加密后进行 Base64 编码
/// 目前使用标准流式索引算法 (Algo 1)
pub fn encrypt_host(host: &[u8], password: &[u8]) -> String {
    let mut data = host.to_vec();
    data.push(0); // 添加结尾的 null 字节

    // 使用标准算法: byte ^= password[idx] | (i as u8)
    // 对应 xor_crypt(..., 0, 0)
    xor_crypt(&mut data, password, 0, 0);
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
        let index = xor_crypt(&mut data, password, 0, 0);
        assert_ne!(&data, original);

        // 解密
        xor_crypt(&mut data, password, 0, 0);
        assert_eq!(&data, original);
        
        let expected_pidx = original.len() % password.len();
        assert_eq!(index, expected_pidx);
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
