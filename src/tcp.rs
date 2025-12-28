//! TCP 模块 - 处理 TCP 连接转发

use crate::config::Config;
use crate::crypto::{decrypt_host, xor_crypt};
use crate::dns::dns_tcp_over_udp;
use log::{error, debug};
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
        match decrypt_host(host_bytes, password) {
            Ok(decrypted) => String::from_utf8(decrypted).ok(),
            Err(e) => {
                error!("Decrypt host failed: {}", e);
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

    loop {
        let read_result = timeout(config.tcp_timeout(), from.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                // 解密
                if !password.is_empty() {
                    password_index = xor_crypt(&mut buffer[..n], password, password_index);
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
        dns_tcp_over_udp(client, &host, header, config, password).await;
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
    let server = match TcpStream::connect(&host).await {
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
