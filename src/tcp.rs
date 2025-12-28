//! TCP 模块 - 处理 TCP 连接转发

use crate::config::Config;
use crate::crypto::{decrypt_host, xor_crypt};
use crate::dns::dns_tcp_over_udp;
use log::{error, debug, info};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::time::timeout;

// 优化：使用更大的缓冲区提高吞吐量
const BUFFER_SIZE: usize = 32768; // 32KB

/// 从 HTTP 头中获取代理目标 Host
pub fn get_proxy_host(header: &[u8], proxy_key: &str, password: &[u8]) -> Option<String> {
    let key = format!("\n{}: ", proxy_key);
    let key_bytes = key.as_bytes();

    // 查找 key 位置
    let key_pos = header
        .windows(key_bytes.len())
        .position(|window| window == key_bytes)?;

    let host_start = key_pos + key_bytes.len();

    // 查找 \r 结束位置
    let host_end = header[host_start..]
        .iter()
        .position(|&b| b == b'\r')
        .map(|pos| host_start + pos)?;

    let host_bytes = &header[host_start..host_end];

    // 如果有密码，需要解密
    if !password.is_empty() {
        info!("Host bytes (hex): {:02X?}", host_bytes);
        match decrypt_host(host_bytes, password) {
            Ok(decrypted) => {
                let raw = String::from_utf8_lossy(&decrypted).to_string();
                info!("Decrypted host (raw): {:?}", raw);
                
                // 智能清理和恢复 IP 地址
                // clnc 的加密与服务器不完全兼容，解密后可能包含乱码
                // 但前几个字符通常是正确的 IP 开头
                let cleaned = smart_clean_host(&raw);
                if cleaned != raw {
                    info!("Cleaned host: {:?} -> {:?}", raw, cleaned);
                }
                
                Some(cleaned)
            },
            Err(e) => {
                error!("Decrypt host failed: {}", e);
                None
            }
        }
    } else {
        String::from_utf8(host_bytes.to_vec()).ok()
    }
}

/// 智能清理解密后的主机名
/// 处理部分正确的解密结果，提取有效的 IP:PORT 格式
fn smart_clean_host(raw: &str) -> String {
    // 先尝试提取看起来像 IP:PORT 格式的内容
    // 策略：收集所有数字段，用常见乱码字符作为分隔符
    
    let mut numbers: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut colon_after_idx: Option<usize> = None;  // 冒号出现在第几个数字之后
    
    for ch in raw.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else {
            // 非数字字符
            if !current.is_empty() {
                numbers.push(current.clone());
                current.clear();
            }
            // 记录冒号位置（作为端口分隔符的候选）
            if ch == ':' && colon_after_idx.is_none() {
                colon_after_idx = Some(numbers.len());
            }
        }
    }
    // 处理最后一个数字
    if !current.is_empty() {
        numbers.push(current);
    }
    
    // 尝试构建 IP:PORT
    // 常见格式:
    // - 4 个 IP 段 + 端口 (冒号在第 4 个数字后)
    // - 4 个 IP 段无端口
    // - 可能有额外的乱码数字
    
    if numbers.len() >= 4 {
        // 尝试找到 4 个有效的 IP 段（0-255）
        let mut ip_segments: Vec<&str> = Vec::new();
        let mut port: Option<&str> = None;
        let mut ip_end_idx = 0;
        
        for (i, num) in numbers.iter().enumerate() {
            if ip_segments.len() < 4 {
                // 尝试作为 IP 段
                if let Ok(n) = num.parse::<u16>() {
                    if n <= 255 {
                        ip_segments.push(num);
                        ip_end_idx = i;
                        continue;
                    }
                }
                // 如果数字太大，可能是端口或乱码
                if ip_segments.len() == 4 {
                    // 已经有 4 个 IP 段，这个可能是端口
                    if let Ok(p) = num.parse::<u16>() {
                        if p > 0 {
                            port = Some(num);
                        }
                    }
                    break;
                }
            } else {
                // 已经有 4 个 IP 段，后面的数字可能是端口
                if let Ok(p) = num.parse::<u16>() {
                    if p > 0 && p <= 65535 {
                        port = Some(num);
                        break;
                    }
                }
            }
        }
        
        if ip_segments.len() == 4 {
            let ip = ip_segments.join(".");
            
            // 如果没找到端口，尝试用冒号后的第一个数字
            if port.is_none() {
                if let Some(colon_idx) = colon_after_idx {
                    if colon_idx >= 4 && colon_idx < numbers.len() {
                        if let Ok(p) = numbers[colon_idx].parse::<u16>() {
                            if p > 0 && p <= 65535 {
                                port = Some(&numbers[colon_idx]);
                            }
                        }
                    }
                }
            }
            
            match port {
                Some(p) => return format!("{}:{}", ip, p),
                None => return format!("{}:80", ip),  // 默认端口 80
            }
        }
    }
    
    // 如果无法提取完整 IP，尝试部分清理
    // 至少返回可读的内容
    let cleaned: String = raw.chars()
        .map(|c| match c {
            '>' | '<' | '&' | '%' | ';' | '=' | '!' | '"' | '(' | ')' | '*' | '\'' => '.',
            _ if c.is_ascii_alphanumeric() || c == '.' || c == ':' || c == '-' => c,
            ' ' | '\t' => ' ',
            _ => '?',
        })
        .collect();
    
    // 尝试修复多余的点
    let cleaned = cleaned.replace("..", ".").replace(". ", " ");
    
    cleaned
}

/// TCP 双向转发（单方向）- 带加密支持
async fn forward_one_direction_encrypted(
    from: &mut tokio::io::ReadHalf<TcpStream>,
    to: &mut tokio::io::WriteHalf<TcpStream>,
    config: &Config,
    password: &[u8],
) {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut password_index = 0usize;
    let mut stream_offset = 0usize;

    loop {
        let read_result = timeout(config.tcp_timeout(), from.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                // 解密
                if !password.is_empty() {
                    password_index = xor_crypt(&mut buffer[..n], password, password_index, stream_offset);
                    stream_offset = stream_offset.wrapping_add(n);
                }

                // 写入目标
                if let Err(e) = to.write_all(&buffer[..n]).await {
                    debug!("Write error: {}", e);
                    break;
                }
            }
            Ok(Err(e)) => {
                debug!("Read error: {}", e);
                break;
            }
            Err(_) => {
                debug!("Timeout");
                break;
            }
        }
    }
}

/// TCP 双向转发（单方向）- 无加密，直接转发
async fn forward_one_direction_plain(
    from: &mut tokio::io::ReadHalf<TcpStream>,
    to: &mut tokio::io::WriteHalf<TcpStream>,
    config: &Config,
) {
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let read_result = timeout(config.tcp_timeout(), from.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if let Err(e) = to.write_all(&buffer[..n]).await {
                    debug!("Write error: {}", e);
                    break;
                }
            }
            Ok(Err(e)) => {
                debug!("Read error: {}", e);
                break;
            }
            Err(_) => {
                debug!("Timeout");
                break;
            }
        }
    }
}

/// 处理 TCP 会话
pub async fn handle_tcp_session(
    client: TcpStream,
    header: Vec<u8>,
    extra_data: Option<Vec<u8>>,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    // 获取代理目标 Host
    let host = match get_proxy_host(&header, &config.proxy_key, &password) {
        Some(h) => h,
        None => {
            error!("No proxy host in header");
            if let Ok(mut client) = client.into_std() {
                let _ = std::io::Write::write_all(&mut client, b"No proxy host");
            }
            return;
        }
    };

    // TCP DNS over UDP DNS
    if config.enable_dns_tcp_over_udp && host.ends_with(":53") {
        dns_tcp_over_udp(client, &host, header, extra_data, config, password).await;
        return;
    }

    // 补全端口
    let host = if !host.contains(':') {
        format!("{}:80", host)
    } else {
        host
    };

    debug!("Connecting to: {}", host);

    // 连接目标服务器
    let mut server = match TcpStream::connect(&host).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to {}: {}", host, e);
            if let Ok(mut client) = client.into_std() {
                let _ = std::io::Write::write_all(
                    &mut client,
                    format!("Proxy address [{}] DialTCP() error", host).as_bytes(),
                );
            }
            return;
        }
    };

    // 优化：设置 TCP_NODELAY 减少延迟
    let _ = server.set_nodelay(true);

    // 如果有额外的初始数据，先发送给服务器
    if let Some(data) = extra_data {
        if let Err(e) = server.write_all(&data).await {
            error!("Failed to write initial data to server: {}", e);
            return;
        }
    }

    // 使用 tokio::io::split 分割流
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // 根据是否有密码选择不同的转发方式
    if password.is_empty() {
        // 无加密：使用 tokio 内置的高效双向复制
        let config_clone = config.clone();
        tokio::select! {
            _ = forward_one_direction_plain(&mut client_read, &mut server_write, &config) => {}
            _ = forward_one_direction_plain(&mut server_read, &mut client_write, &config_clone) => {}
        }
    } else {
        // 有加密：使用自定义转发
        let config_clone = config.clone();
        let _password_clone = password.clone();
        tokio::select! {
            _ = forward_one_direction_encrypted(&mut client_read, &mut server_write, &config, &password) => {}
            _ = forward_one_direction_plain(&mut server_read, &mut client_write, &config_clone) => {}
        }
    }
}

/// 处理 TCP 会话（无加密，使用高效双向复制）
pub async fn handle_tcp_session_fast(
    mut client: TcpStream,
    mut server: TcpStream,
) {
    let _ = copy_bidirectional(&mut client, &mut server).await;
}
