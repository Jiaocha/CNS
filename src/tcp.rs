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
                let mut s = String::from_utf8_lossy(&decrypted).to_string();
                info!("Decrypted host (raw): {:?}", s);
                
                // 模糊修复 IP 地址中的常见位翻转乱码
                // 已知乱码: > (62) -> . (46)
                //           : (58) -> . (46)
                //           < (60) -> . (46)
                //           & (38) -> . (46)
                //           ; (59) -> . (46)
                //           % (37) -> . (46)
                // 仅当字符串看起来像 IP 时才替换 (包含数字)
                if s.chars().any(|c| c.is_ascii_digit()) {
                    let original = s.clone();
                    // 替换常见的错误字符为点
                    // 只有当它们出现在数字之间时才安全？或者直接暴力替换
                    // 考虑到 host 肯定是 IP 或域名，域名用点，IP 用点。
                    // 这些符号在正常域名中也不常见（除了端口前的冒号）
                    
                    // 策略：如果包含 > < & %，大概率是乱码的点
                    if s.contains(|c| matches!(c, '>' | '<' | '&' | '%' | ';')) {
                        s = s.chars().map(|c| match c {
                            '>' | '<' | '&' | '%' | ';' => '.',
                            _ => c
                        }).collect();
                        info!("Sanitized host: {:?} -> {:?}", original, s);
                    }
                    
                    // 修复端口冒号可能变成其他字符的情况? 
                    // 暂时先只修复点，因为点是 IP 的核心
                }
                
                Some(s)
            },
            Err(e) => {
                error!("Decrypt host failed: {}", e);
                // 尝试用空密码解密看看（排除密码错误）
                // 仅用于调试
                if let Ok(d) = decrypt_host(host_bytes, &[]) {
                     info!("Decrypted with empty password: {:?}", String::from_utf8_lossy(&d));
                }
                None
            }
        }
    } else {
        String::from_utf8(host_bytes.to_vec()).ok()
    }
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
