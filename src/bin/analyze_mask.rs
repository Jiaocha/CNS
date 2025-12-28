use base64::{engine::general_purpose::STANDARD, Engine};

fn main() {
    let host_bytes_hex: Vec<u8> = vec![
        0x41, 0x41, 0x63, 0x44, 0x47, 0x51, 0x63, 0x44, 0x42, 0x67, 0x6B, 0x65, 0x42, 0x52, 0x30, 0x45, 0x42, 0x67, 0x38, 0x44, 0x44, 0x42, 0x38, 0x65, 0x41, 0x44, 0x4D, 0x3D
    ];
    // Decrypted garbage from log: "140.241>%8\";;0<3*)3"
    // Password: [49, 50, 51, 52, 53, 54] ("123456")
    
    // 1. Decode Base64
    let cipher = STANDARD.decode(&host_bytes_hex).unwrap();
    println!("Ciphertext (hex): {:02X?}", cipher);
    println!("Ciphertext len: {}", cipher.len());

    // 2. Known Plaintext (First 7 chars confirmed)
    let known_start = b"140.241"; 
    // Guessing what follows... likely a dot? "140.241."
    
    // 3. Analyze Mask
    // Cipher ^ Plain = Mask
    // Mask ^ Password = KeyModifier?
    
    let password = b"123456";
    
    println!("\nAnalysis:");
    for (i, &c) in cipher.iter().enumerate() {
        if i < known_start.len() {
            let p = known_start[i];
            let mask = c ^ p;
            let pwd_char = password[i % password.len()];
            let modifier = mask ^ pwd_char;
            
            println!("Idx {}: Cipher={:02X} Plain={:02X}('{}') -> Mask={:02X}. Pwd={:02X}. Modifier={:02X}", 
                i, c, p, p as char, mask, pwd_char, modifier);
        } else {
            // Analyze the garbage
            // Logged Result: "140.241>%8\";;0<3*)3"
            // This result came from Algo 1: Mask = Pwd | i
            // So: c ^ (Pwd | i) = Garbage
            // We want: c ^ CorrectMask = '.' (2E)
            
            let garbage_char = if i == 7 { '>' as u8 } else { 0 }; // Just looking at index 7 for now
            
            if i == 7 {
                let intended = b'.';
                let actual_mask = c ^ intended;
                let pwd_char = password[i % password.len()]; // '2' = 0x32
                let modifier = actual_mask ^ pwd_char;
                println!("Idx {} (Target='.'): Cipher={:02X} -> Needed Mask={:02X}. Pwd={:02X}. Modifier={:02X}",
                    i, c, actual_mask, pwd_char, modifier);
            }
        }
    }
}
