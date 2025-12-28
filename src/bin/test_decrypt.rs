// 深入分析加密算法差异
use base64::{engine::general_purpose::STANDARD, Engine};

fn main() {
    // 样本 1 的前几个字节
    let sample = vec![0x00u8, 0x07, 0x03, 0x19, 0x07, 0x03, 0x06, 0x09, 0x1E, 0x05, 0x1D, 0x04, 0x06, 0x0F, 0x05, 0x0C, 0x1F, 0x1E, 0x00, 0x33];
    let password = b"123456";
    
    println!("=== 深入分析加密算法 ===\n");
    println!("密码: {:?} (bytes: {:02X?})", String::from_utf8_lossy(password), password);
    println!("样本: {:02X?} ({} bytes)\n", sample, sample.len());
    
    // 假设解密后应该是类似 140.247.x.x:xxxx 或 148.x.x.x:xx 的格式
    // 从 pwd_idx 解密结果 "140.247:-2(37<6;*)1" 来看，前面几个字符是对的
    
    // 逐字节分析，看看哪种掩码模式能产生合理的结果
    println!("逐字节分析:\n");
    println!("{:>4} {:>6} {:>6} {:>6} {:>6} {:>6}", 
             "idx", "enc", "pwd_i", "p|pi", "p|di", "纯p");
    println!("{}", "-".repeat(50));
    
    for i in 0..sample.len() {
        let enc = sample[i];
        let pwd_idx = i % password.len();
        let pwd_char = password[pwd_idx];
        
        let mask_pwd_idx = pwd_char | (pwd_idx as u8);
        let mask_data_idx = pwd_char | (i as u8);
        let mask_pure = pwd_char;
        
        let dec_pwd_idx = enc ^ mask_pwd_idx;
        let dec_data_idx = enc ^ mask_data_idx;
        let dec_pure = enc ^ mask_pure;
        
        let c_pwd_idx = if dec_pwd_idx.is_ascii_graphic() || dec_pwd_idx == b' ' { 
            format!("'{}'", dec_pwd_idx as char) 
        } else { 
            format!("0x{:02X}", dec_pwd_idx) 
        };
        let c_data_idx = if dec_data_idx.is_ascii_graphic() || dec_data_idx == b' ' { 
            format!("'{}'", dec_data_idx as char) 
        } else { 
            format!("0x{:02X}", dec_data_idx) 
        };
        let c_pure = if dec_pure.is_ascii_graphic() || dec_pure == b' ' { 
            format!("'{}'", dec_pure as char) 
        } else { 
            format!("0x{:02X}", dec_pure) 
        };
        
        println!("{:>4} 0x{:02X}   {}    {} {} {}", 
                 i, enc, pwd_idx, c_pwd_idx, c_data_idx, c_pure);
    }
    
    // 尝试暴力破解 - 假设前几个字符应该是数字或点
    println!("\n\n=== 暴力破解每个位置的字符 ===\n");
    
    // 假设解密后是 IP:PORT 格式，每个位置应该是: 数字(0-9), 点(.), 冒号(:)
    let valid_chars: Vec<u8> = (b'0'..=b'9').chain([b'.', b':']).collect();
    
    for i in 0..std::cmp::min(12, sample.len()) {
        let enc = sample[i];
        print!("位置 {}: ", i);
        
        let mut found = Vec::new();
        for &expected in &valid_chars {
            let required_mask = enc ^ expected;
            found.push((expected as char, required_mask));
        }
        
        // 只显示几个可能性
        for (ch, mask) in found.iter().take(4) {
            print!("'{}'=>0x{:02X}  ", ch, mask);
        }
        println!();
    }
    
    // 检查 clnc 是否可能使用了不同的密码编码
    println!("\n\n=== 检查密码变体 ===\n");
    
    // 可能的变体：
    // 1. 密码重复或填充
    // 2. 密码被某种方式处理
    
    // 测试：如果位置 2 需要掩码 0x3B，而不是 0x33
    // 0x3B = ';'
    // 需要 password[2] | 2 = 0x3B
    // password[2] 需要是 0x3B 或 0x39
    // 0x39 = '9', 0x3B = ';'
    
    // 如果密码是 "12;456" 或 "129456"?
    let test_passwords = vec![
        b"123456".to_vec(),
        b"12;456".to_vec(),
        b"129456".to_vec(),
        b"1234567890".to_vec(),
        b"12345678".to_vec(),
    ];
    
    let expected = b"148.";
    
    for pwd in &test_passwords {
        let mut match_count = 0;
        for i in 0..4 {
            let enc = sample[i];
            let pwd_idx = i % pwd.len();
            let mask = pwd[pwd_idx] | (pwd_idx as u8);
            let dec = enc ^ mask;
            if dec == expected[i] {
                match_count += 1;
            }
        }
        println!("密码 {:?}: 匹配 {}/4 字节", String::from_utf8_lossy(pwd), match_count);
    }
}
