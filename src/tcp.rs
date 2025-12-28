//! TCP 模块 - 处理 TCP 连接转发

use crate::config::Config;
use crate::crypto::{decrypt_host, xor_crypt};
use crate::dns::dns_tcp_over_udp;
use log::{error, info};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

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

/// TCP 双向转发（单方向）
async fn forward_one_direction(
    from: &mut tokio::io::ReadHalf<TcpStream>,
    to: &mut tokio::io::WriteHalf<TcpStream>,
    config: &Config,
    password: &[u8],
    decrypt: bool,
) {
    let mut buffer = vec![0u8; 8192];
    let mut password_index = 0usize;

    loop {
        let read_result = timeout(config.tcp_timeout(), from.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(0)) => break, // 连接关闭
            Ok(Ok(n)) => {
                // 如果需要解密
                if decrypt && !password.is_empty() {
                    password_index = xor_crypt(&mut buffer[..n], password, password_index);
                }

                // 写入目标
                if let Err(e) = timeout(config.tcp_timeout(), to.write_all(&buffer[..n])).await {
                    error!("Write error: {}", e);
                    break;
                }
            }
            Ok(Err(e)) => {
                error!("Read error: {}", e);
                break;
            }
            Err(_) => {
                error!("Timeout");
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

    info!("Connecting to: {}", host);

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

    // 使用 tokio::io::split 分割流
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let config2 = config.clone();
    let password2 = password.clone();

    // 双向转发
    tokio::select! {
        _ = forward_one_direction(&mut client_read, &mut server_write, &config, &password, true) => {}
        _ = forward_one_direction(&mut server_read, &mut client_write, &config2, &password2, false) => {}
    }
}
