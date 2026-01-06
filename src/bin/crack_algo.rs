use std::io::Write;
use base64::{Engine as _, engine::general_purpose};

fn main() {
    let password = b"123456";
    // Log sample: AAQAGG33OCwkaAQEdBg0PBRIaAwsz
    // Hex: 41 41 51 41 47 51 51 4F 43 77 6B 61 41 51 45 64 42 67 30 50 42 52 49 61 41 77 73 7A
    // Decoded string in log: 173.19::)64*7><2'-28
    
    let b64_input = "AAQAGG33OCwkaAQEdBg0PBRIaAwsz"; // Approximation based on hex
    // Wait, let's use the EXACT hex bytes from the log to be 100% sure.
    // [41, 41, 51, 41, 47, 51, 51, 4F, 43, 77, 6B, 61, 41, 51, 45, 64, 42, 67, 30, 50, 42, 52, 49, 61, 41, 77, 73, 7A]
    let hex_bytes = vec![0x41, 0x41, 0x51, 0x41, 0x47, 0x51, 0x51, 0x4F, 0x43, 0x77, 0x6B, 0x61, 0x41, 0x51, 0x45, 0x64, 0x42, 0x67, 0x30, 0x50, 0x42, 0x52, 0x49, 0x61, 0x41, 0x77, 0x73, 0x7A];
    let b64_str = String::from_utf8(hex_bytes).unwrap();
    println!("Base64 Input: {}", b64_str);
    
    let decoded = general_purpose::STANDARD.decode(&b64_str).expect("Base64 decode failed");
    println!("Decoded Bytes (Hex): {:02X?}", decoded);
    
    // Attempt 1: pwd_idx (Current Implementation)
    // Mask = P[i%len] | (i%len as u8)
    println!("\n--- Attempt 1: pwd_idx (Current) ---");
    let mut attempt1 = decoded.clone();
    for (i, byte) in attempt1.iter_mut().enumerate() {
        let pwd_idx = i % password.len();
        let mask = password[pwd_idx] | (pwd_idx as u8);
        *byte ^= mask;
    }
    println!("Result 1: {}", String::from_utf8_lossy(&attempt1));
    
    // Attempt 2: data_idx (P[idx] | data_idx)
    // Mask = P[i%len] | (i as u8)
    println!("\n--- Attempt 2: data_idx ---");
    let mut attempt2 = decoded.clone();
    for (i, byte) in attempt2.iter_mut().enumerate() {
        let pwd_idx = i % password.len();
        let mask = password[pwd_idx] | (i as u8);
        *byte ^= mask;
    }
    println!("Result 2: {}", String::from_utf8_lossy(&attempt2));
    
    // Attempt 3: Go Compat (P[idx] | idx)
    // Note: Go's idx wraps at len. So this IS Attempt 1.
    
    // Attempt 4: Offset Mask?
    // Mask = P[i%len] | ((i + Offset) % 256 as u8)
    // Try offsets 0..255
    println!("\n--- Attempt 4: Brute Force Offset ---");
    for offset in 0..256 {
        let mut attempt = decoded.clone();
        for (i, byte) in attempt.iter_mut().enumerate() {
             let pwd_idx = i % password.len();
             let mask_idx = (i + offset) & 0xFF;
             let mask = password[pwd_idx] | (mask_idx as u8);
             *byte ^= mask;
        }
        let s = String::from_utf8_lossy(&attempt);
        // Heuristic: Must contain only digits, dots, colon
        if s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':' || c == '\0') {
            println!("MATCH Offset {}: {}", offset, s);
        } else {
            // Print close matches
             if s.contains("173.19") && s.len() < 30 {
                 println!("CLOSE Offset {}: {}", offset, s);
             }
        }
    }
    
    // Attempt 5: Brute Force Password Index Offset?
    // Mask = P[(i + Offset) % len] | (i%len as u8)
    println!("\n--- Attempt 5: Brute Force Pwd Index Offset ---");
    for offset in 0..6 {
        let mut attempt = decoded.clone();
        for (i, byte) in attempt.iter_mut().enumerate() {
             let pwd_idx = (i + offset) % password.len();
             let mask = password[pwd_idx] | (pwd_idx as u8); // Mask index uses pwd_idx? Or i?
             // Current impl uses pwd_idx for both.
             *byte ^= mask;
        }
        let s = String::from_utf8_lossy(&attempt);
         if s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':' || c == '\0') {
            println!("MATCH PwdOffset {}: {}", offset, s);
        }
    }

    // Attempt 6: Reverse Engineering from Known Plaintext
    // We expect "173.19.64.7:2" (Based on user log inference "Cleaned host 173.19.64.7:2")
    // Or close to it.
    // Plaintext: "173.19.64.7:2"
    // Ciphertext: decoded
    // Mask = Plain ^ Cipher
    println!("\n--- Attempt 6: Reverse Engineer Mask ---");
    let target = b"173.19.64.7:2";
    let mut derived_masks = Vec::new();
    for (i, &b) in decoded.iter().enumerate() {
        if i >= target.len() { break; }
        let mask = b ^ target[i];
        derived_masks.push(mask);
        // Print analysis
        // Expected Mask = P[idx] | X.
        // We know P[idx].
        let pwd_idx = i % password.len();
        let p = password[pwd_idx];
        println!("Pos {}: Target '{}'({:02X}) ^ Byte {:02X} = Mask {:02X}. P[{}]={:02X}. Mask|P = {:02X}. X = ?", 
            i, target[i] as char, target[i], b, mask, pwd_idx, p, mask | p);
    }
}

