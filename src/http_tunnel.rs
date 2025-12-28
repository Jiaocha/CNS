//! HTTP 隧道模块 - 处理 HTTP 隧道连接

use crate::config::Config;
use crate::dns::respond_http_dns;
use crate::tcp::handle_tcp_session;
use crate::udp::handle_udp_session;
use log::{error, info};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;

/// 检查是否是 HTTP 请求头
pub fn is_http_header(header: &[u8]) -> bool {
    const HTTP_METHODS: &[&[u8]] = &[
        b"CONNECT",
        b"GET",
        b"POST",
        b"HEAD",
        b"PUT",
        b"COPY",
        b"DELETE",
        b"MOVE",
        b"OPTIONS",
        b"LINK",
        b"UNLINK",
        b"TRACE",
        b"PATCH",
        b"WRAPPED",
    ];

    for method in HTTP_METHODS {
        if header.starts_with(method) {
            return true;
        }
    }
    false
}

/// 生成 HTTP 响应头
pub fn generate_response_header(header: &[u8]) -> &'static [u8] {
    if find_subsequence(header, b"WebSocket").is_some() {
        b"HTTP/1.1 101 Switching Protocols\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Accept: CuteBi Network Tunnel, (%>w<%)\r\n\r\n"
    } else if header.starts_with(b"CON") {
        b"HTTP/1.1 200 Connection established\r\n\
          Server: CuteBi Network Tunnel, (%>w<%)\r\n\
          Connection: keep-alive\r\n\r\n"
    } else {
        b"HTTP/1.1 200 OK\r\n\
          Transfer-Encoding: chunked\r\n\
          Server: CuteBi Network Tunnel, (%>w<%)\r\n\
          Connection: keep-alive\r\n\r\n"
    }
}

/// 在数据中查找子序列
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// 处理隧道连接
pub async fn handle_tunnel(
    mut client: TcpStream,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    let mut buffer = vec![0u8; 8192];
    let mut payload_len = 0usize;

    // 读取请求头
    loop {
        let read_result = timeout(config.tcp_timeout(), client.read(&mut buffer[payload_len..])).await;

        match read_result {
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => {
                payload_len += n;

                // 如果不是 HTTP 头或者已经读取到完整的 HTTP 头
                if !is_http_header(&buffer[..payload_len])
                    || buffer[..payload_len].ends_with(b"\n\r\n")
                    || buffer[..payload_len].ends_with(b"\r\n\r\n")
                {
                    break;
                }
            }
            Ok(Err(e)) => {
                error!("Read error: {}", e);
                return;
            }
            Err(_) => {
                error!("Read timeout");
                return;
            }
        }
    }

    let header = buffer[..payload_len].to_vec();

    if !is_http_header(&header) {
        // 非 HTTP 头，当作 UDP 会话处理
        handle_udp_session(client, Some(header), config, password).await;
    } else {
        // HTTP 头处理
        
        // 优先处理 HTTP DNS 请求
        if config.enable_http_dns && header.windows(3).any(|w| w == b"dn=") {
            if respond_http_dns(client, &header).await {
                return;
            }
            // HTTP DNS 处理失败意味着已经消费了 client，直接返回
            return;
        }

        // 发送响应头
        let response = generate_response_header(&header);
        if let Err(e) = client.write_all(response).await {
            error!("Write response header error: {}", e);
            return;
        }

        // 检查是否是 UDP 隧道
        if find_subsequence(&header, config.udp_flag.as_bytes()).is_some() {
            handle_udp_session(client, None, config, password).await;
        } else {
            handle_tcp_session(client, buffer, config, password).await;
        }
    }
}

/// 处理 TLS 隧道连接
pub async fn handle_tls_tunnel(
    client: TlsStream<TcpStream>,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    let mut buffer = vec![0u8; 8192];
    let mut payload_len = 0usize;

    let (mut read_half, mut write_half) = tokio::io::split(client);

    // 读取请求头
    loop {
        let read_result = timeout(config.tcp_timeout(), read_half.read(&mut buffer[payload_len..])).await;

        match read_result {
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => {
                payload_len += n;

                if !is_http_header(&buffer[..payload_len])
                    || buffer[..payload_len].ends_with(b"\n\r\n")
                    || buffer[..payload_len].ends_with(b"\r\n\r\n")
                {
                    break;
                }
            }
            Ok(Err(e)) => {
                error!("TLS read error: {}", e);
                return;
            }
            Err(_) => {
                error!("TLS read timeout");
                return;
            }
        }
    }

    let header = buffer[..payload_len].to_vec();

    // TLS 连接需要特殊处理
    if is_http_header(&header) {
        // 发送响应头
        let response = generate_response_header(&header);
        if let Err(e) = write_half.write_all(response).await {
            error!("TLS write response header error: {}", e);
            return;
        }

        // 重新组合流并获取底层 TCP 流
        let tls_stream = read_half.unsplit(write_half);
        let (tcp_stream, _) = tls_stream.into_inner();

        // 检查是否是 UDP 隧道
        if find_subsequence(&header, config.udp_flag.as_bytes()).is_some() {
            handle_udp_session(tcp_stream, None, config, password).await;
        } else {
            handle_tcp_session(tcp_stream, buffer, config, password).await;
        }
    }
}

/// 启动 HTTP 隧道服务器
pub async fn start_http_tunnel(addr: &str, config: Arc<Config>, password: Arc<Vec<u8>>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind {}: {}", addr, e);
            return;
        }
    };

    info!("HTTP tunnel listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New connection from {}", peer_addr);

                // 设置 keep-alive
                if let Err(e) = stream.set_nodelay(true) {
                    error!("Set nodelay failed: {}", e);
                }

                let config = config.clone();
                let password = password.clone();

                tokio::spawn(async move {
                    handle_tunnel(stream, config, password).await;
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    }
}
