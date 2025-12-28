// 最终确认：Algo 3 是正确算法
use base64::{engine::general_purpose::STANDARD, Engine};

fn main() {
    let password = b"123456";
    
    // 样本 2 的 Base64
    let sample2_b64 = "AAcLGQQECgkaAh0CDwANDRUaAzM=";
    
    println!("=== 确认 Algo 3 (pwd | data_idx) ===\n");
    
    if let Ok(decoded) = STANDARD.decode(sample2_b64) {
        // Algo 3 解密
        let mut decrypted = decoded.clone();
        for (i, byte) in decrypted.iter_mut().enumerate() {
            let pwd_idx = i % password.len();
            *byte ^= password[pwd_idx] | (i as u8);
        }
        
        println!("解密结果: {:?}", String::from_utf8_lossy(&decrypted));
        println!("最后一个字节: 0x{:02X} (应该是 0x00)", decrypted.last().unwrap());
        
        // 检查 null 结尾
        if decrypted.last() == Some(&0) {
            println!("✓ 最后一个字节是 null，验证成功！");
            decrypted.pop();
            println!("去掉 null 后: {:?}", String::from_utf8_lossy(&decrypted));
        }
    }
    
    println!("\n\n=== 暴力搜索所有可能的 IP:PORT (Algo 3) ===\n");
    
    let sample2_decoded: Vec<u8> = STANDARD.decode(sample2_b64).unwrap();
    
    // 尝试 148.13.x.x:port 格式，19 字符 + null = 20 bytes
    // 格式: "148.13.XXX.YYY:PPPPP" 可能太长
    // 格式: "148.13.XX.YY:PPPP" 刚好 18 字符
    // 搜索 148.13.x.x:xxxx
    
    for a in 0..=99u8 {
        for b_val in 0..=99u8 {
            for port in [80, 443, 8080, 8443, 8000, 3000] {
                let ip = format!("148.13.{}.{}:{}", a, b_val, port);
                if ip.len() + 1 != sample2_decoded.len() {
                    continue;
                }
                
                let mut data = ip.as_bytes().to_vec();
                data.push(0);
                
                // 加密 (Algo 3)
                for (i, byte) in data.iter_mut().enumerate() {
                    let pwd_idx = i % password.len();
                    *byte ^= password[pwd_idx] | (i as u8);
                }
                
                if data == sample2_decoded {
                    println!("✓ 找到匹配: {}", ip);
                }
            }
        }
    }
    
    // 也尝试 3 位数的最后一段
    for a in 0..=255u8 {
        for b_val in 0..=99u8 {
            for port in [80, 443, 8080] {
                let ip = format!("148.13.{}.{}:{}", a, b_val, port);
                if ip.len() + 1 != sample2_decoded.len() {
                    continue;
                }
                
                let mut data = ip.as_bytes().to_vec();
                data.push(0);
                
                for (i, byte) in data.iter_mut().enumerate() {
                    let pwd_idx = i % password.len();
                    *byte ^= password[pwd_idx] | (i as u8);
                }
                
                if data == sample2_decoded {
                    println!("✓ 找到匹配: {}", ip);
                }
            }
        }
    }
    
    println!("\n暴力搜索完成。如果没找到，说明 IP 格式或密码不对。");
    
    // 尝试用不同密码测试
    println!("\n\n=== 测试其他可能的密码 ===\n");
    
    let test_passwords = vec![
        b"123456".to_vec(),
        b"1234567890".to_vec(),
        b"password".to_vec(),
        b"test".to_vec(),
    ];
    
    for pwd in &test_passwords {
        let mut decrypted = sample2_decoded.clone();
        for (i, byte) in decrypted.iter_mut().enumerate() {
            let pwd_idx = i % pwd.len();
            *byte ^= pwd[pwd_idx] | (i as u8);
        }
        
        if decrypted.last() == Some(&0) {
            let text = String::from_utf8_lossy(&decrypted[..decrypted.len()-1]);
            let valid = text.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':');
            println!("密码 {:?}: \"{}\" (valid: {})", 
                     String::from_utf8_lossy(pwd), text, valid);
        } else {
            println!("密码 {:?}: 无效 (no null)", String::from_utf8_lossy(pwd));
        }
    }
}
