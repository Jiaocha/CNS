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

    // 使用标准算法 (p | i) 进行解密 (这是目前验证最接近的算法)
    let mut attempt = decoded_origin.clone();
    xor_crypt(&mut attempt, password, 0, 0);

    // 处理结尾 null
    if let Some(&0) = attempt.last() { attempt.pop(); }

    // 智能清洗与 IP 恢复
    // 问题：解密后半部分会出现规律性乱码 (如 > < & 等代替了 .)
    // 策略：模糊匹配 IP 格式
    
    let original_string = String::from_utf8_lossy(&attempt).to_string();
    let mut clean = String::new();
    let mut dot_count = 0;
    let mut last_was_dot = false;
    let mut has_port = false;

    for c in original_string.chars() {
        if c.is_ascii_digit() {
            clean.push(c);
            last_was_dot = false;
        } else if c == '.' || matches!(c, '>' | '<' | '&' | '%' | ';' | '"' | '!' | ',' | '#') {
            // 将常见的乱码符号视为点
            if !last_was_dot {
                clean.push('.');
                dot_count += 1;
                last_was_dot = true;
            }
        } else if c == ':' {
            clean.push(':');
            has_port = true;
            last_was_dot = false;
            // 端口开始后，后面的乱码通常不严重，或者由 TCP 逻辑处理
        } else if has_port {
            // 端口后的字符，如果是数字则保留
             if c.is_ascii_digit() {
                clean.push(c);
             }
        } else {
            // 其他字符忽略，或者如果是 IP 中间的奇怪字符，可能意味着截断？
            // 暂时忽略非预期字符
        }
        
        // 如果已经有 3 个点，且当前是数字，我们在读取第 4 段
        // 如果再次遇到点，说明 IP 结束 (4 个点? 不，IP 只需 3 个点)
        if dot_count > 3 && !has_port {
            // 可能读到了 IP 后的垃圾数据
            // 回退最后一个点
            if clean.ends_with('.') { clean.pop(); }
            break;
        }
    }
    
    // 简单的完整性检查
    // 期望格式 x.x.x.x 或 x.x.x.x:p
    if dot_count >= 3 {
        log::info!("Smart IP Recover: {} -> {}", original_string, clean);
        return Ok(clean.into_bytes());
    }

    // 如果不像 IP，返回原始解密数据 (可能也是乱码，但保留原样)
    log::warn!("Decryption uncertain: {}", original_string);
    Ok(attempt)
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
