//! 加密模块 - 实现 ChaCha20-Poly1305 和 XOR 加密/解密
//!
//! 新版本使用 ChaCha20-Poly1305 AEAD 加密算法，同时保留 XOR 作为兼容模式

use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use crate::error::CryptoError;

// ============================================================================
// ChaCha20-Poly1305 加密 (推荐使用)
// ============================================================================

/// 使用 ChaCha20-Poly1305 加密数据
/// 
/// 密钥会被填充或截断到 32 字节
/// 返回格式: nonce (12 bytes) + ciphertext + tag (16 bytes)
pub fn encrypt_chacha20(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::EmptyData);
    }

    // 生成 32 字节密钥
    let key = derive_key_32(password);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    // 生成随机 nonce (12 bytes)
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 加密
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptFailed)?;

    // 返回 nonce + ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

/// 使用 ChaCha20-Poly1305 解密数据
/// 
/// 输入格式: nonce (12 bytes) + ciphertext + tag (16 bytes)
pub fn decrypt_chacha20(ciphertext: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // 最小长度: 12 (nonce) + 16 (tag) = 28
    if ciphertext.len() < 28 {
        return Err(CryptoError::EmptyData);
    }

    // 生成 32 字节密钥
    let key = derive_key_32(password);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    // 分离 nonce 和密文
    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // 解密
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// 使用 ChaCha20 加密 Host 并 Base64 编码
pub fn encrypt_host_chacha20(host: &[u8], password: &[u8]) -> Result<String, CryptoError> {
    let encrypted = encrypt_chacha20(host, password)?;
    Ok(STANDARD.encode(&encrypted))
}

/// Base64 解码并使用 ChaCha20 解密 Host
pub fn decrypt_host_chacha20(encoded_host: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let decoded = STANDARD.decode(encoded_host).map_err(|_| CryptoError::Base64Error)?;
    decrypt_chacha20(&decoded, password)
}

/// 从密码派生 32 字节密钥 (简单填充/截断方式)
fn derive_key_32(password: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    if password.is_empty() {
        return key;
    }
    
    // 循环填充密码到 32 字节
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = password[i % password.len()];
    }
    key
}

/// 生成 12 字节随机 nonce
fn generate_nonce() -> [u8; 12] {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let mut nonce = [0u8; 12];
    
    // 使用时间戳和进程信息生成伪随机 nonce
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    let nanos = now.as_nanos();
    let pid = std::process::id();
    
    // 混合时间戳和 PID
    for (i, byte) in nonce.iter_mut().enumerate() {
        let shift = (i * 8) % 64;
        *byte = ((nanos >> shift) as u8) ^ ((pid >> (i % 4 * 8)) as u8);
    }
    
    nonce
}

// ============================================================================
// XOR 加密 (兼容模式 - 已弃用,仅用于向后兼容)
// ============================================================================

/// XOR 加密/解密 (已弃用)
/// 
/// 对数据进行 XOR 加密，返回新的密码索引
/// 算法: byte ^= password[pwd_idx] | (data_idx as u8)
/// 
/// # 安全警告
/// XOR 加密极不安全,请使用 ChaCha20 替代
#[deprecated(since = "0.6.0", note = "使用 encrypt_chacha20/decrypt_chacha20 替代")]
pub fn xor_crypt(data: &mut [u8], password: &[u8], mut password_index: usize, _stream_offset: usize) -> usize {
    if password.is_empty() {
        return password_index;
    }

    for byte in data.iter_mut() {
        *byte ^= password[password_index] | (password_index as u8);
        
        password_index += 1;
        if password_index == password.len() {
            password_index = 0;
        }
    }

    password_index
}

/// 解密 Host (XOR 兼容模式)
/// 
/// Base64 解码后尝试多种 XOR 算法解密
/// 使用评分系统选择最佳结果
/// 
/// # 安全警告
/// XOR 加密极不安全,请使用 decrypt_host_chacha20 替代
#[deprecated(since = "0.6.0", note = "使用 decrypt_host_chacha20 替代")]
pub fn decrypt_host(encoded_host: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Base64 解码
    let decoded = STANDARD.decode(encoded_host).map_err(|_| CryptoError::Base64Error)?;

    if decoded.is_empty() {
        return Err(CryptoError::EmptyData);
    }

    // 空密码时直接返回解码后的数据
    if password.is_empty() {
        log::warn!("Empty password, returning decoded data as-is");
        let mut result = decoded;
        if result.last() == Some(&0) {
            result.pop();
        }
        return Ok(result);
    }

    // 尝试多种算法，选择评分最高的结果
    let mut best_result: Option<(Vec<u8>, i32, &str)> = None;

    // 算法 1: byte ^= password[pwd_idx] | pwd_idx (原始 Go 服务器)
    {
        let mut attempt = decoded.clone();
        decrypt_with_pwd_idx(&mut attempt, password);
        let score = score_host_result(&attempt);
        if score > best_result.as_ref().map(|(_, s, _)| *s).unwrap_or(-1) {
            best_result = Some((attempt, score, "pwd_idx"));
        }
    }

    // 算法 2: byte ^= password[pwd_idx] | data_idx
    {
        let mut attempt = decoded.clone();
        decrypt_with_data_idx(&mut attempt, password);
        let score = score_host_result(&attempt);
        if score > best_result.as_ref().map(|(_, s, _)| *s).unwrap_or(-1) {
            best_result = Some((attempt, score, "data_idx"));
        }
    }

    // 算法 3: byte ^= password[pwd_idx] (纯 XOR)
    {
        let mut attempt = decoded.clone();
        decrypt_with_pure_xor(&mut attempt, password);
        let score = score_host_result(&attempt);
        if score > best_result.as_ref().map(|(_, s, _)| *s).unwrap_or(-1) {
            best_result = Some((attempt, score, "pure_xor"));
        }
    }

    match best_result {
        Some((mut result, score, algo_name)) => {
            // 移除结尾 null
            if result.last() == Some(&0) {
                result.pop();
            }
            
            let text = String::from_utf8_lossy(&result);
            
            // 如果评分太低，记录警告
            if score < 50 {
                log::warn!("Low confidence decrypt (score: {}) using {}: {:?}", score, algo_name, text);
            } else {
                log::debug!("Decrypted host using {} (score: {}): {:?}", algo_name, score, text);
            }
            
            // 只要评分大于 0 就返回结果
            if score > 0 {
                Ok(result)
            } else {
                log::warn!("All decrypt algorithms failed for host: {:02X?}", decoded);
                Err(CryptoError::DecryptFailed)
            }
        }
        None => {
            log::warn!("No decrypt result for host: {:02X?}", decoded);
            Err(CryptoError::DecryptFailed)
        }
    }
}

/// 算法 1: byte ^= password[pwd_idx] | pwd_idx
fn decrypt_with_pwd_idx(data: &mut [u8], password: &[u8]) {
    if password.is_empty() { return; }
    let mut pwd_idx = 0;
    for byte in data.iter_mut() {
        *byte ^= password[pwd_idx] | (pwd_idx as u8);
        pwd_idx = (pwd_idx + 1) % password.len();
    }
}

/// 算法 2: byte ^= password[pwd_idx] | data_idx
fn decrypt_with_data_idx(data: &mut [u8], password: &[u8]) {
    if password.is_empty() { return; }
    let mut pwd_idx = 0;
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= password[pwd_idx] | (i as u8);
        pwd_idx = (pwd_idx + 1) % password.len();
    }
}

/// 算法 3: byte ^= password[pwd_idx]
fn decrypt_with_pure_xor(data: &mut [u8], password: &[u8]) {
    if password.is_empty() { return; }
    let mut pwd_idx = 0;
    for byte in data.iter_mut() {
        *byte ^= password[pwd_idx];
        pwd_idx = (pwd_idx + 1) % password.len();
    }
}

/// 评估解密结果的可能性（分数越高越可能是正确结果）
fn score_host_result(data: &[u8]) -> i32 {
    let mut score = 0i32;
    
    // 检查结尾 null 字节
    if data.last() == Some(&0) {
        score += 30;
    }
    
    // 去掉 null 后转为字符串
    let end = if data.last() == Some(&0) { data.len() - 1 } else { data.len() };
    let s = match std::str::from_utf8(&data[..end]) {
        Ok(s) => s,
        Err(_) => return score, // 不是有效 UTF-8，低分
    };
    
    if s.is_empty() {
        return 0;
    }
    
    // 统计有效字符（数字、点、冒号、字母、连字符）
    let valid_chars = s.chars().filter(|c| {
        c.is_ascii_digit() || *c == '.' || *c == ':' || c.is_ascii_alphabetic() || *c == '-'
    }).count();
    
    let valid_ratio = valid_chars as f32 / s.len() as f32;
    score += (valid_ratio * 50.0) as i32;
    
    // 检查是否以数字开头（可能是 IP）
    if s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        score += 10;
    }
    
    // 检查是否包含点（IP 或域名）
    let dot_count = s.chars().filter(|c| *c == '.').count();
    if dot_count >= 1 && dot_count <= 10 {
        score += 10;
    }
    
    // 检查 IP 格式
    let colon_pos = s.rfind(':');
    let host_part = colon_pos.map(|p| &s[..p]).unwrap_or(s);
    
    // 验证 IP 格式
    let parts: Vec<&str> = host_part.split('.').collect();
    if parts.len() == 4 {
        let valid_ip_parts = parts.iter().filter(|p| {
            p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        }).count();
        score += valid_ip_parts as i32 * 10;
    }
    
    // 检查端口部分
    if let Some(pos) = colon_pos {
        let port_str = &s[pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            if port > 0 {
                score += 20;
            }
        }
    }
    
    score
}

/// 加密 Host (XOR 兼容模式)
/// 
/// XOR 加密后进行 Base64 编码
/// 
/// # 安全警告
/// XOR 加密极不安全,请使用 encrypt_host_chacha20 替代
#[deprecated(since = "0.6.0", note = "使用 encrypt_host_chacha20 替代")]
pub fn encrypt_host(host: &[u8], password: &[u8]) -> String {
    let mut data = host.to_vec();
    data.push(0); // 添加结尾的 null 字节

    // 使用 pwd_idx 算法
    decrypt_with_pwd_idx(&mut data, password);
    STANDARD.encode(&data)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let password = b"test_password";
        let plaintext = b"Hello, World!";
        
        let encrypted = encrypt_chacha20(plaintext, password).unwrap();
        let decrypted = decrypt_chacha20(&encrypted, password).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_host_encrypt_decrypt() {
        let password = b"secret_password";
        let host = b"192.168.1.1:8080";
        
        let encrypted = encrypt_host_chacha20(host, password).unwrap();
        let decrypted = decrypt_host_chacha20(encrypted.as_bytes(), password).unwrap();
        
        assert_eq!(decrypted, host);
    }

    #[test]
    fn test_chacha20_different_passwords_fail() {
        let password1 = b"password1";
        let password2 = b"password2";
        let plaintext = b"secret data";
        
        let encrypted = encrypt_chacha20(plaintext, password1).unwrap();
        let result = decrypt_chacha20(&encrypted, password2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20_tampered_data_fail() {
        let password = b"test_password";
        let plaintext = b"Hello, World!";
        
        let mut encrypted = encrypt_chacha20(plaintext, password).unwrap();
        // 篡改数据
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }
        
        let result = decrypt_chacha20(&encrypted, password);
        assert!(result.is_err());
    }

    #[test]
    #[allow(deprecated)]
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
    #[allow(deprecated)]
    fn test_xor_host_encrypt_decrypt() {
        let password = b"secret";
        let host = b"example.com:80";

        let encrypted = encrypt_host(host, password);
        let decrypted = decrypt_host(encrypted.as_bytes(), password).unwrap();

        assert_eq!(decrypted, host);
    }
    
    #[test]
    #[allow(deprecated)]
    fn test_empty_password() {
        let password = b"";
        let host = b"test";
        // 不应该 panic
        let _ = decrypt_host(host, password);
    }

    #[test]
    fn test_derive_key() {
        let short_password = b"abc";
        let key = derive_key_32(short_password);
        assert_eq!(key.len(), 32);
        // 验证循环填充
        assert_eq!(key[0], b'a');
        assert_eq!(key[1], b'b');
        assert_eq!(key[2], b'c');
        assert_eq!(key[3], b'a');
    }
}
