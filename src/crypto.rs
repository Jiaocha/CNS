//! 加密模块 - 实现 XOR 加密/解密

use base64::{engine::general_purpose::STANDARD, Engine};

/// XOR 加密/解密
/// 
/// 对数据进行 XOR 加密，返回新的密码索引
/// 算法: byte ^= password[pwd_idx] | (data_idx as u8)
/// 
/// 注意：clnc 客户端使用数据索引 (data_idx) 作为掩码！
/// 这与原始 Go 服务器代码 (passwordSub) 不同！
/// clnc 的实际行为是: data[i] ^= password[pwd_idx] | byte(i)
pub fn xor_crypt(data: &mut [u8], password: &[u8], mut password_index: usize, stream_offset: usize) -> usize {
    if password.is_empty() {
        return password_index;
    }

    for (i, byte) in data.iter_mut().enumerate() {
        let data_idx = stream_offset.wrapping_add(i);
        // 使用数据索引(mod 256)作为掩码的一部分，与 clnc 客户端保持一致
        *byte ^= password[password_index] | (data_idx as u8);
        
        password_index += 1;
        if password_index == password.len() {
            password_index = 0;
        }
    }

    password_index
}

/// 解密 Host
/// 
/// Base64 解码后尝试多种 XOR 算法解密，自动选择能解密出有效主机名的算法
/// 
/// 支持的算法:
/// 1. 原始 Go 服务器算法: byte ^= password[pwd_idx] | pwd_idx
/// 2. clnc 客户端算法: byte ^= password[pwd_idx] | data_idx  
/// 3. 纯 XOR 算法: byte ^= password[pwd_idx]
pub fn decrypt_host(encoded_host: &[u8], password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Base64 解码
    let decoded = STANDARD.decode(encoded_host).map_err(|_| DecryptError::Base64Error)?;

    if decoded.is_empty() {
        return Err(DecryptError::EmptyData);
    }

    // 定义多种解密算法
    let algorithms: [(&str, fn(&mut [u8], &[u8])); 3] = [
        ("pwd_idx", decrypt_algo_pwd_idx),
        ("data_idx", decrypt_algo_data_idx),
        ("pure_xor", decrypt_algo_pure_xor),
    ];
    
    // 尝试每种算法
    for (algo_name, algo_fn) in &algorithms {
        let mut attempt = decoded.clone();
        algo_fn(&mut attempt, password);
        
        // 验证结尾 null 字节
        if attempt.last() == Some(&0) {
            attempt.pop(); // 移除 null
            
            // 验证是否是有效的主机名（IP 或域名格式）
            if is_valid_host(&attempt) {
                log::debug!("Decrypted host using {}: {:?}", algo_name, String::from_utf8_lossy(&attempt));
                return Ok(attempt);
            }
        }
    }
    
    // 所有算法都失败，记录调试信息
    log::warn!("All decrypt algorithms failed for host: {:02X?}", decoded);
    Err(DecryptError::DecryptFailed)
}

/// 算法 1: byte ^= password[pwd_idx] | pwd_idx (原始 Go 服务器)
fn decrypt_algo_pwd_idx(data: &mut [u8], password: &[u8]) {
    let mut pwd_idx = 0;
    for byte in data.iter_mut() {
        *byte ^= password[pwd_idx] | (pwd_idx as u8);
        pwd_idx = (pwd_idx + 1) % password.len();
    }
}

/// 算法 2: byte ^= password[pwd_idx] | data_idx (clnc 风格)
fn decrypt_algo_data_idx(data: &mut [u8], password: &[u8]) {
    let mut pwd_idx = 0;
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= password[pwd_idx] | (i as u8);
        pwd_idx = (pwd_idx + 1) % password.len();
    }
}

/// 算法 3: byte ^= password[pwd_idx] (纯 XOR)
fn decrypt_algo_pure_xor(data: &mut [u8], password: &[u8]) {
    let mut pwd_idx = 0;
    for byte in data.iter_mut() {
        *byte ^= password[pwd_idx];
        pwd_idx = (pwd_idx + 1) % password.len();
    }
}

/// 检查解密后的数据是否是有效的主机名格式
fn is_valid_host(data: &[u8]) -> bool {
    // 必须是有效的 UTF-8
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    // 空字符串无效
    if s.is_empty() {
        return false;
    }
    
    // 分离主机名和端口
    let (host, port_part) = if let Some(colon_pos) = s.rfind(':') {
        let potential_port = &s[colon_pos + 1..];
        // 确保冒号后都是数字（端口号）
        if potential_port.chars().all(|c| c.is_ascii_digit()) && !potential_port.is_empty() {
            (&s[..colon_pos], Some(potential_port))
        } else {
            (s, None)
        }
    } else {
        (s, None)
    };
    
    // 验证端口在有效范围内
    if let Some(port_str) = port_part {
        if let Ok(port) = port_str.parse::<u32>() {
            if port == 0 || port > 65535 {
                return false;
            }
        } else {
            return false;
        }
    }
    
    // 验证主机名格式
    // IP 地址: 数字和点
    let is_ip_like = host.chars().all(|c| c.is_ascii_digit() || c == '.');
    if is_ip_like {
        // 验证 IP 格式: 需要正好 3 个点
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            // 验证每个部分是 0-255 的数字
            return parts.iter().all(|p| {
                if p.is_empty() { return false; }
                if let Ok(n) = p.parse::<u16>() {
                    n <= 255
                } else {
                    false
                }
            });
        }
        return false;
    }
    
    // 域名: 字母、数字、点、连字符
    host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
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
