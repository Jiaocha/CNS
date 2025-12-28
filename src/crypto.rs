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

    // 暴力尝试多种算法并记录所有结果，以便远程调试
    let strategies: Vec<(&str, Box<dyn Fn(usize, usize, u8, u8) -> u8>)> = vec![
        ("Standard (| i)", Box::new(|i, _, p, _| p | (i as u8))),
        ("WrapIdx (| i%len)", Box::new(|_, pi, p, _| p | (pi as u8))), 
        ("XorIdx (^ i)", Box::new(|i, _, p, _| p ^ (i as u8))),
        ("PlusIdx (+ i)", Box::new(|i, _, p, _| p.wrapping_add(i as u8))),
        ("Simple (^ 0)", Box::new(|_, _, p, _| p)),
        ("Offset1 (| i+1)", Box::new(|i, _, p, _| p | ((i + 1) as u8))),
        ("XorOffset1 (^ i+1)", Box::new(|i, _, p, _| p ^ ((i + 1) as u8))),
        ("Reverse (| len-i)", Box::new(|i, _, p, len| p | ((len as u8).wrapping_sub(i as u8)))),
    ];

    let mut best_candidate = decoded_origin.clone();
    let mut best_score = 0;
    
    // 只在第一次调用或 debug 开启时打印所有尝试
    let show_debug = true; 

    for (name, func) in strategies {
        let mut attempt = decoded_origin.clone();
        for (i, byte) in attempt.iter_mut().enumerate() {
            let pwd_char = password[i % password.len()];
            let mask = func(i, i % password.len(), pwd_char, password.len() as u8);
            *byte ^= mask;
        }

        // 处理结尾 null
        if let Some(&0) = attempt.last() { attempt.pop(); }
        
        // 评分：字母数字点号越多越好
        let valid_chars = attempt.iter().filter(|&&b| b.is_ascii_alphanumeric() || b == b'.' || b == b':' || b == b'-').count();
        let score = valid_chars * 100 / attempt.len();
        
        let s = String::from_utf8_lossy(&attempt).to_string();
        if show_debug {
            log::info!("Algo [{}]: {}", name, s);
        }

        if score > best_score {
            best_score = score;
            best_candidate = attempt.clone();
        }
        
        // 完美匹配？
        if is_valid_host(&attempt) {
            log::info!("Match found with Algo [{}]", name);
            return Ok(attempt);
        }
    }
    
    // 没找到完美匹配，返回最高分的，并记录
    log::warn!("No perfect match. Returning best candidate (score {}): {:?}", best_score, String::from_utf8_lossy(&best_candidate));
    Ok(best_candidate)
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
