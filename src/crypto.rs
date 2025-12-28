//! 加密模块 - 实现 XOR 加密/解密

use base64::{engine::general_purpose::STANDARD, Engine};

/// XOR 加密/解密
/// 
/// 对数据进行 XOR 加密，返回新的密码索引
/// 算法: byte ^= password[pwd_idx] | (stream_idx as u8)
pub fn xor_crypt(data: &mut [u8], password: &[u8], mut password_index: usize, stream_offset: usize) -> usize {
    if password.is_empty() {
        return password_index;
    }

    for (i, byte) in data.iter_mut().enumerate() {
        let stream_idx = stream_offset.wrapping_add(i);
        // 使用流的绝对位置(mod 256)作为掩码的一部分
        *byte ^= password[password_index] | (stream_idx as u8);
        
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
    let decoded_origin = STANDARD.decode(encoded_host).map_err(|_| DecryptError::Base64Error)?;

    if decoded_origin.is_empty() {
        return Err(DecryptError::EmptyData);
    }

    // 辅助函数：检查是否是有效的 Host 字符串
    let is_valid_host = |data: &[u8]| -> bool {
        if data.is_empty() { return false; }
        // 允许的字符：字母、数字、点、横杠、冒号
        // 必须以字母或数字开头 (排除掉解密完全错误产生的随机控制字符)
        if !data[0].is_ascii_alphanumeric() { return false; }
        
        data.iter().all(|&b| {
            b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':' || b == 0
        })
    };

    // 算法 1: 标准流式索引 (UDP 验证通过的算法)
    // byte ^= password[idx] | (stream_offset + i)
    {
        let mut attempt = decoded_origin.clone();
        xor_crypt(&mut attempt, password, 0, 0);
        
        // 处理 null 结尾
        if let Some(&0) = attempt.last() { attempt.pop(); }
        
        if is_valid_host(&attempt) {
            // log::info!("Decrypt host strategy: Stream Index (Standard)");
            return Ok(attempt);
        }
    }

    // 算法 2: 简单 XOR
    // byte ^= password[idx]
    {
        let mut attempt = decoded_origin.clone();
        let mut pwd_idx = 0;
        for byte in attempt.iter_mut() {
            *byte ^= password[pwd_idx];
            pwd_idx = (pwd_idx + 1) % password.len();
        }
        
        // 处理 null 结尾
        if let Some(&0) = attempt.last() { attempt.pop(); }

        if is_valid_host(&attempt) {
            log::info!("Decrypt host strategy: Simple XOR");
            return Ok(attempt);
        }
    }

    // 算法 3: 这里的 mask 使用 password_index (即 0..len-1)
    // byte ^= password[idx] | idx
    {
        let mut attempt = decoded_origin.clone();
        let mut pwd_idx = 0;
        for byte in attempt.iter_mut() {
            *byte ^= password[pwd_idx] | (pwd_idx as u8);
            pwd_idx = (pwd_idx + 1) % password.len();
        }

        // 处理 null 结尾
        if let Some(&0) = attempt.last() { attempt.pop(); }

        if is_valid_host(&attempt) {
            log::info!("Decrypt host strategy: PwdIdx Mask");
            return Ok(attempt);
        }
    }
    
    // 如果都失败，回退到算法 1 (Stream Index)，并依靠外部的模糊修复 (Sanitize)
    let mut final_attempt = decoded_origin;
    xor_crypt(&mut final_attempt, password, 0, 0);
    if let Some(&0) = final_attempt.last() { final_attempt.pop(); }
    
    Ok(final_attempt)
}

/// 加密 Host
/// 
/// XOR 加密后进行 Base64 编码
pub fn encrypt_host(host: &[u8], password: &[u8]) -> String {
    let mut data = host.to_vec();
    data.push(0); // 添加结尾的 null 字节

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
