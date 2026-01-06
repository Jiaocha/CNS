//! DNS 模块 - 处理 DNS 相关功能

use crate::config::Config;
#[allow(deprecated)]
use crate::crypto::xor_crypt;
use log::error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// TCP DNS over UDP DNS
/// 
/// 将 TCP DNS 请求转发到 UDP DNS 服务器
/// TCP DNS over UDP DNS
/// 
/// 将 TCP DNS 请求转发到 UDP DNS 服务器
pub async fn dns_tcp_over_udp(
    mut client: TcpStream,
    host: &str,
    _header: Vec<u8>, // 忽略 HTTP 手握头
    extra_data: Option<Vec<u8>>,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    // 使用 extra_data 初始化缓冲区，如果为空则创建新缓冲区
    let mut buffer = if let Some(data) = extra_data {
        data
    } else {
        vec![0u8; 4096]
    };
    
    // 如果 buffer 是从 extra_data 来的，payload_len 就是它的长度
    // 如果是新建的，payload_len 初始为 0（需要扩展 buffer 来读取）
    let mut payload_len = if buffer.capacity() == 4096 && buffer.len() == 4096 {
        0 // 新建的 vec，长度为 4096 (vec![0; N])
    } else {
        buffer.len() // extra_data 的长度
    };
    
    // 如果是新建的 buffer，我们需要 resize 来容纳数据吗？
    // vec![0u8; 4096] 创建了长度为 4096 的 vec。
    // 如果我们用 payload_len = 0，后续 read(&mut buffer[0..]) 会覆盖。
    
    if payload_len == 0 {
        // 确保 buffer 有足够空间
        if buffer.len() < 4096 {
            buffer.resize(4096, 0);
        }
    } else {
        // 如果有 extra_data，确保有后续读取的空间
        if buffer.len() < 4096 {
            buffer.resize(4096, 0);
        }
    }

    let mut password_index = 0usize;

    // 读取完整的 DNS 请求包
    loop {
        if payload_len > 2 {
            // 前 2 字节是包长度（大端序）
            let pkg_len = ((buffer[0] as u16) << 8) | (buffer[1] as u16);
            let pkg_len = pkg_len as usize;

            // 防止访问非法数据
            if pkg_len + 2 > buffer.len() {
                error!("Invalid DNS packet length");
                return;
            }

            // 如果读取到了完整的包
            if pkg_len + 2 <= payload_len {
                break;
            }
        }

        // 继续读取
        let read_result = timeout(config.tcp_timeout(), client.read(&mut buffer[payload_len..])).await;

        match read_result {
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => {
                // 解密
                if !password.is_empty() {
                    password_index = xor_crypt(
                        &mut buffer[payload_len..payload_len + n],
                        &password,
                        password_index,
                        0,
                    );
                }
                payload_len += n;
            }
            Ok(Err(e)) => {
                error!("Read DNS request error: {}", e);
                return;
            }
            Err(_) => {
                error!("DNS request timeout");
                return;
            }
        }
    }

    // 连接 UDP DNS 服务器
    let udp_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            error!("Bind UDP socket failed: {}", e);
            let _ = client
                .write_all(format!("Proxy address [{}] DNS bind error", host).as_bytes())
                .await;
            return;
        }
    };

    if let Err(e) = udp_socket.connect(host).await {
        error!("Connect to DNS server {} failed: {}", host, e);
        let _ = client
            .write_all(format!("Proxy address [{}] DNS Dial() error", host).as_bytes())
            .await;
        return;
    }

    // 发送 DNS 请求（跳过前 2 字节的长度字段）
    if let Err(e) = udp_socket.send(&buffer[2..payload_len]).await {
        error!("Send DNS request error: {}", e);
        return;
    }

    // 接收 DNS 响应
    let recv_result = timeout(config.udp_timeout(), udp_socket.recv(&mut buffer[2..])).await;

    match recv_result {
        Ok(Ok(n)) => {
            // 设置响应长度（大端序）
            buffer[0] = (n >> 8) as u8;
            buffer[1] = (n & 0xFF) as u8;

// 加密
                if !password.is_empty() {
                    xor_crypt(&mut buffer[..2 + n], &password, 0, 0);
                }

            // 发送响应
            let _ = client.write_all(&buffer[..2 + n]).await;
        }
        Ok(Err(e)) => {
            error!("Recv DNS response error: {}", e);
        }
        Err(_) => {
            error!("DNS response timeout");
        }
    }
}

/// 响应 HTTP DNS 请求
/// 
/// 实现类似 114DNS / DNSPod 的 HTTP DNS 服务
pub async fn respond_http_dns(mut client: TcpStream, header: &[u8]) -> bool {
    // 查找 dn= 参数
    let dn_pos = match find_subsequence(header, b"dn=") {
        Some(pos) => pos + 3,
        None => return false,
    };

    // 提取域名
    let domain_end = header[dn_pos..]
        .iter()
        .position(|&b| b == b'&' || b == b' ' || b == b'\r' || b == b'\n')
        .unwrap_or(header.len() - dn_pos);

    let domain = match std::str::from_utf8(&header[dn_pos..dn_pos + domain_end]) {
        Ok(d) => d.to_string(),
        Err(_) => return false,
    };

    // 检查是否请求 IPv6
    let is_ipv6 = find_subsequence(header, b"type=AAAA").is_some();
    
    // 检查是否需要 TTL
    let with_ttl = find_subsequence(header, b"ttl=1").is_some();

    // 解析域名
    match tokio::net::lookup_host(format!("{}:0", domain)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            
            // 查找匹配的 IP
            for addr in addrs {
                let is_v6 = addr.ip().is_ipv6();
                if is_v6 == is_ipv6 {
                    let mut ip_str = addr.ip().to_string();
                    if with_ttl {
                        ip_str.push_str(",60");
                    }

                    let response = format!(
                        "HTTP/1.0 200 OK\r\n\
                         Connection: Close\r\n\
                         Server: CuteBi Linux Network httpDNS, (%>w<%)\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        ip_str.len(),
                        ip_str
                    );

                    let _ = client.write_all(response.as_bytes()).await;
                    return true;
                }
            }

            // 没有找到匹配的 IP
            let response = "HTTP/1.0 404 Not Found\r\n\
                           Connection: Close\r\n\
                           Server: CuteBi Linux Network httpDNS, (%>w<%)\r\n\
                           Content-type: charset=utf-8\r\n\r\n\
                           <html><head><title>HTTP DNS Server</title></head>\
                           <body>查询域名失败<br/><br/>\
                           By: 萌萌萌得不要不要哒<br/>\
                           E-mail: 915445800@qq.com</body></html>";

            let _ = client.write_all(response.as_bytes()).await;
            true
        }
        Err(_) => {
            let response = "HTTP/1.0 404 Not Found\r\n\
                           Connection: Close\r\n\
                           Server: CuteBi Linux Network httpDNS, (%>w<%)\r\n\
                           Content-type: charset=utf-8\r\n\r\n\
                           <html><head><title>HTTP DNS Server</title></head>\
                           <body>查询域名失败<br/><br/>\
                           By: 萌萌萌得不要不要哒<br/>\
                           E-mail: 915445800@qq.com</body></html>";

            let _ = client.write_all(response.as_bytes()).await;
            true
        }
    }
}

/// 在数据中查找子序列
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
