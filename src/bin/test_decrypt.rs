// 测试新假设：clnc 可能使用 password[pwd_idx] | running_idx (不循环 pwd_idx 在掩码计算中)

fn main() {
    let sample = vec![0x00u8, 0x07, 0x0B, 0x19, 0x04, 0x04, 0x0A, 0x09, 0x1A, 0x02, 0x1D, 0x02, 0x0F, 0x00, 0x0D, 0x0D, 0x15, 0x1A, 0x03, 0x33];
    let password = b"123456";
    
    println!("=== 测试新算法假设 ===\n");
    
    // 假设 1: password[i % len] | i (数据索引持续累加)
    println!("算法 A: password[i % len] | i (数据索引持续):");
    test_algo(&sample, password, |i, p| p[i % p.len()] | (i as u8));
    
    // 假设 2: password[(i/len) % len] | (i % len) - 不太对
    
    // 假设 3: 检查位置 6 应该解密为什么
    println!("\n位置 6-11 应该是什么？");
    println!("  如果 IP 是 148.13.X.X:port 格式：");
    println!("  位置 6 = '.' (0x2E)");
    println!("  位置 7,8,9 = 三位数字");
    println!("  位置 10 = '.' (0x2E)");
    
    // 反推位置 6 需要的密码/掩码
    let pos6_enc = sample[6]; // 0x0A
    let pos6_expected_dot = b'.'; // 0x2E
    let required_mask = pos6_enc ^ pos6_expected_dot; // 0x0A ^ 0x2E = 0x24
    
    println!("\n位置 6 分析:");
    println!("  加密字节: 0x{:02X}", pos6_enc);
    println!("  期望 '.': 0x{:02X}", pos6_expected_dot);
    println!("  需要掩码: 0x{:02X} = 0b{:08b}", required_mask, required_mask);
    println!("  当前 pwd[0]='1' = 0x31 = 0b{:08b}", password[0]);
    
    // 0x24 = 0b00100100 = '$'
    // 这不太像是从密码 '1'(0x31) 经过任何简单 OR/XOR 操作得到的
    
    // 让我尝试另一种可能：position 6 不是 '.'，而是数字
    println!("\n假设位置 6 是数字而不是点：");
    for d in b'0'..=b'9' {
        let mask = pos6_enc ^ d;
        println!("  如果是 '{}': 需要掩码 0x{:02X}", d as char, mask);
    }
    
    // 检查日志中的实际结果
    // "148.13.:)5(5.3.: -2" <- 这是 pwd_idx 的结果
    // 如果第 7 个字符是 '.'，第 8 个是 ':'...
    // 等等，日志格式 "148.13." 表示位置 0-6 是 "148.13."，这不对
    
    // 让我重新理解日志格式
    println!("\n\n=== 重新理解日志 ===");
    println!("日志: \"148.13.:)5(5.3.: -2\"");
    println!("位置:  0123456789...");
    println!();
    
    // 也许 IP 格式更短？比如 148.13.5.3:80?
    // 长度 = "148.13.5.3:80" = 13 + null = 14，但样本是 20 bytes
    // 或者类似 "148.135.75.102:80" = 18 + null = 19，接近!
    
    println!("假设 IP 是 '148.135.75.102:80' (18 + null = 19 bytes):");
    let expected = b"148.135.75.102:80\0";
    for (i, (&enc, &exp)) in sample.iter().zip(expected.iter()).enumerate() {
        let mask = enc ^ exp;
        let pwd_idx = i % password.len();
        let cur_mask = password[pwd_idx] | (pwd_idx as u8);
        let match_str = if mask == cur_mask { "✓" } else { "" };
        println!("  [{:2}] 0x{:02X} ^ 0x{:02X} ('{}') = 0x{:02X}, pwd_idx掩码=0x{:02X} {}", 
                 i, enc, exp, exp as char, mask, cur_mask, match_str);
    }
}

fn test_algo(sample: &[u8], password: &[u8], mask_fn: impl Fn(usize, &[u8]) -> u8) {
    let mut result = String::new();
    for i in 0..sample.len() {
        let mask = mask_fn(i, password);
        let dec = sample[i] ^ mask;
        if dec == 0 {
            result.push_str("\\0");
            break;
        }
        if dec.is_ascii_graphic() || dec == b' ' {
            result.push(dec as char);
        } else {
            result.push_str(&format!("?{:02X}", dec));
        }
    }
    println!("  结果: \"{}\"", result);
}
