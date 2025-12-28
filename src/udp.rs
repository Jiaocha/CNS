//! UDP 模块 - 处理 UDP over HTTP Tunnel

use crate::config::Config;
use crate::crypto::xor_crypt;
use log::{error, debug, info};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// 写入数据到 UDP 服务器
/// 完全按照 Go 版本的逻辑实现
async fn write_to_server(udp_socket: &UdpSocket, data: &[u8]) -> i32 {
    let mut pkg_sub: usize = 0;
    
    while pkg_sub + 2 < data.len() {
        // 2字节储存包的长度（小端序），包括socks5头
        let pkg_len = (data[pkg_sub] as u16) | ((data[pkg_sub + 1] as u16) << 8);
        let pkg_len = pkg_len as usize;
        
        debug!("write_to_server: pkg_sub={}, pkg_len={}, data_len={}", pkg_sub, pkg_len, data.len());
        
        if pkg_sub + 2 + pkg_len > data.len() || pkg_len <= 10 {
            debug!("write_to_server: invalid packet, returning 0");
            return 0;
        }
        
        // 检查保留字段 [pkgSub+3:pkgSub+5] == {0, 0}
        // 注意：Go代码是 httpUDP_data[pkgSub+3:pkgSub+5]，即 [pkgSub+3] 和 [pkgSub+4]
        if data[pkg_sub + 3] != 0 || data[pkg_sub + 4] != 0 {
            debug!("write_to_server: reserved fields check failed, returning 1");
            return 1;
        }
        
        // Go 代码: if httpUDP_data[5] == 1
        // 注意：Go 代码使用的是固定偏移 5（相对于 pkgSub+2）
        let addr_type = data[pkg_sub + 5];
        
        let (addr, header_len) = if addr_type == 1 {
            // IPv4
            let ip = Ipv4Addr::new(
                data[pkg_sub + 6],
                data[pkg_sub + 7],
                data[pkg_sub + 8],
                data[pkg_sub + 9],
            );
            let port = ((data[pkg_sub + 10] as u16) << 8) | (data[pkg_sub + 11] as u16);
            debug!("write_to_server: IPv4 addr={}:{}", ip, port);
            (SocketAddr::new(IpAddr::V4(ip), port), 12)
        } else {
            // IPv6
            if pkg_len <= 24 {
                debug!("write_to_server: pkg_len too small for IPv6, returning 0");
                return 0;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[pkg_sub + 6..pkg_sub + 22]);
            let ip = Ipv6Addr::from(ip_bytes);
            let port = ((data[pkg_sub + 22] as u16) << 8) | (data[pkg_sub + 23] as u16);
            debug!("write_to_server: IPv6 addr={}:{}", ip, port);
            (SocketAddr::new(IpAddr::V6(ip), port), 24)
        };
        
        // 发送 payload: httpUDP_data[pkgSub+httpUDP_protocol_head_len : pkgSub+2+pkgLen]
        let payload_start = pkg_sub + header_len;
        let payload_end = pkg_sub + 2 + pkg_len;
        
        debug!("write_to_server: sending {} bytes to {}", payload_end - payload_start, addr);
        
        match udp_socket.send_to(&data[payload_start..payload_end], addr).await {
            Ok(_) => {}
            Err(e) => {
                error!("write_to_server: send error: {}", e);
                return -1;
            }
        }
        
        pkg_sub += 2 + pkg_len;
    }
    
    pkg_sub as i32
}

/// 初始化 UDP 数据（验证加密数据）
/// 返回 Ok((password_index, stream_offset)) 解密数据并返回密钥索引和流偏移
fn init_udp_data(data: &mut [u8], password: &[u8]) -> Result<(usize, usize), &'static str> {
    if !password.is_empty() && data.len() >= 5 {
        // 解密前5字节进行验证
        // 验证时 stream_offset 从 0 开始
        let mut test_data = [0u8; 5];
        test_data.copy_from_slice(&data[..5]);
        xor_crypt(&mut test_data, password, 0, 0);

        // 验证协议头: de[2] != 0 || de[3] != 0 || de[4] != 0
        if test_data[2] != 0 || test_data[3] != 0 || test_data[4] != 0 {
            info!("UDP Verify failed. Raw (hex): {:02X?}", &data[..std::cmp::min(data.len(), 16)]);
            info!("Decrypted header (hex): {:02X?}", test_data);
            return Err("Is not httpUDP protocol or Decrypt failed");
        }

        // 解密整个数据，返回密钥索引
        // 这里的 stream_offset 为 0，因为是整个流的开始
        Ok((xor_crypt(data, password, 0, 0), data.len()))
    } else {
        Ok((0, 0))
    }
}

/// 客户端到服务器转发
async fn client_to_server(
    client_read: &mut tokio::io::ReadHalf<TcpStream>,
    udp_socket: &UdpSocket,
    initial_data: Option<Vec<u8>>,
    initial_password_index: usize,
    initial_data_decrypted: bool, // 标记初始数据是否已解密
    initial_stream_offset: usize, // 初始流偏移
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    let mut buffer = vec![0u8; 65536];
    let mut payload_len = 0usize;
    // 从初始化返回的密钥索引开始
    let mut password_index = initial_password_index;
    let mut stream_offset = initial_stream_offset;
    
    // 跟踪是否已经解密（初始数据可能未解密）
    let mut has_decrypted = initial_data_decrypted;

    // 处理初始数据
    if let Some(data) = initial_data {
        debug!("client_to_server: processing initial data, len={}, decrypted={}", data.len(), initial_data_decrypted);
        
        // 如果初始数据未解密，先解密
        if !initial_data_decrypted && !password.is_empty() && data.len() >= 5 {
            // 尝试验证并解密
            let mut test_data = [0u8; 5];
            test_data.copy_from_slice(&data[..5]);
            xor_crypt(&mut test_data, &password, 0, 0); // initial offset 0
            
            // 验证协议头
            if test_data[2] == 0 && test_data[3] == 0 && test_data[4] == 0 {
                // 验证通过，解密整个数据
                buffer[..data.len()].copy_from_slice(&data);
                password_index = xor_crypt(&mut buffer[..data.len()], &password, 0, 0);
                stream_offset = data.len();
                payload_len = data.len();
                has_decrypted = true;
            } else {
                // 验证失败，可能是数据不完整，先不解密
                buffer[..data.len()].copy_from_slice(&data);
                payload_len = data.len();
            }
        } else if initial_data_decrypted {
            // 初始数据已解密，直接使用
            buffer[..data.len()].copy_from_slice(&data);
            payload_len = data.len();
            // 注意：如果已解密，stream_offset 应该由 adjust logic 处理
        } else {
            // 无密码或数据不足，直接使用
            buffer[..data.len()].copy_from_slice(&data);
            payload_len = data.len();
            if password.is_empty() {
                has_decrypted = true;
            }
        }
        
        // 尝试发送到服务器
        if payload_len >= 12 {
            let w_len = write_to_server(udp_socket, &buffer[..payload_len]).await;
            if w_len == -1 {
                return;
            }
            let w_len = w_len as usize;
            if w_len < payload_len {
                buffer.copy_within(w_len..payload_len, 0);
                payload_len -= w_len;
            } else {
                payload_len = 0;
            }
        }
    }

    loop {
        let read_result =
            timeout(config.udp_timeout(), client_read.read(&mut buffer[payload_len..])).await;

        match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                debug!("client_to_server: read {} bytes from client, payload_len={}, stream_offset={}", n, payload_len, stream_offset);
                
                // 如果还未解密，尝试验证并解密
                if !has_decrypted && !password.is_empty() && payload_len + n >= 5 {
                    // 尝试验证并解密
                    // 此时 stream_offset 应该还是 0，因为还没找到头
                    let mut test_data = [0u8; 5];
                    test_data.copy_from_slice(&buffer[..5]);
                    xor_crypt(&mut test_data, &password, 0, 0);
                    
                    // 验证协议头
                    if test_data[2] == 0 && test_data[3] == 0 && test_data[4] == 0 {
                        // 验证通过，解密整个数据
                        info!("UDP Header verified. Raw first 16 bytes: {:02X?}", &buffer[..std::cmp::min(16, payload_len + n)]);
                        
                        // 注意：这里我们是从头开始解密，所以 offset=0
                        password_index = xor_crypt(&mut buffer[..payload_len + n], &password, 0, 0);
                        
                        info!("Decrypted UDP data (first 32 bytes): {:02X?}", &buffer[..std::cmp::min(32, payload_len + n)]);
                        
                        stream_offset = payload_len + n;
                        has_decrypted = true;
                    } else {
                        info!("UDP Header verify failed. Decrypted header: {:02X?}", test_data);
                    }
                } else if has_decrypted && !password.is_empty() {
                    // 已解密，继续解密新数据
                    // 使用 current password_index 和 current stream_offset
                    password_index = xor_crypt(
                        &mut buffer[payload_len..payload_len + n],
                        &password,
                        password_index,
                        stream_offset,
                    );
                    stream_offset += n;
                }

                payload_len += n;

                let w_len = write_to_server(udp_socket, &buffer[..payload_len]).await;
                if w_len == -1 {
                    return;
                }
                let w_len = w_len as usize;
                if w_len < payload_len {
                    buffer.copy_within(w_len..payload_len, 0);
                    payload_len -= w_len;
                } else {
                    payload_len = 0;
                }
            }
            Ok(Err(e)) => {
                debug!("client_to_server: read error: {}", e);
                break;
            }
            Err(_) => {
                debug!("client_to_server: timeout");
                break;
            }
        }
    }
}

/// 服务器到客户端转发
async fn server_to_client(
    client_write: &mut tokio::io::WriteHalf<TcpStream>,
    udp_socket: &UdpSocket,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    let mut buffer = vec![0u8; 65536];
    let mut password_index = 0usize;
    let mut stream_offset = 0usize; // Maintenance of stream offset

    loop {
        // 从偏移 24 开始读取，留出协议头空间
        let recv_result = timeout(config.udp_timeout(), udp_socket.recv_from(&mut buffer[24..])).await;

        match recv_result {
            Ok(Ok((n, addr))) => {
                debug!("server_to_client: received {} bytes from {}", n, addr);
                
                // ... (header construction logic is same) ...
                // Duplicate header construction logic to keep context or just replace the inner part?
                // The logical block is large.
                // I will try to target the loop start and `xor_crypt` call.
                // But `header_start` and `total_len` are calculated inside match.
                
                // Let's use `multi_replace` or large chunk replace.
                // The tool call below replaces the variable init and loop structure.
                
                // 构建 httpUDP 协议头
                let (header_start, total_len) = match addr.ip() {
                    IpAddr::V4(ip) => {
                        buffer[12] = ((n + 10) & 0xFF) as u8;
                        buffer[13] = ((n + 10) >> 8) as u8;
                        buffer[14] = 0;
                        buffer[15] = 0;
                        buffer[16] = 0;
                        buffer[17] = 1; // addr type = IPv4
                        buffer[18..22].copy_from_slice(&ip.octets());
                        buffer[22] = (addr.port() >> 8) as u8;
                        buffer[23] = (addr.port() & 0xFF) as u8;
                        (12, 12 + n)
                    }
                    IpAddr::V6(ip) => {
                        buffer[0] = ((n + 22) & 0xFF) as u8;
                        buffer[1] = ((n + 22) >> 8) as u8;
                        buffer[2] = 0;
                        buffer[3] = 0;
                        buffer[4] = 0;
                        buffer[5] = 3; // addr type = IPv6
                        buffer[6..22].copy_from_slice(&ip.octets());
                        buffer[22] = (addr.port() >> 8) as u8;
                        buffer[23] = (addr.port() & 0xFF) as u8;
                        (0, 24 + n)
                    }
                };

                // 加密
                if !password.is_empty() {
                    password_index = xor_crypt(
                        &mut buffer[header_start..header_start + total_len],
                        &password,
                        password_index,
                        stream_offset,
                    );
                    stream_offset += total_len;
                }

                debug!("server_to_client: sending {} bytes to client", total_len);
                
                // 发送给客户端
                if let Err(e) = client_write
                    .write_all(&buffer[header_start..header_start + total_len])
                    .await
                {
                    error!("server_to_client: write error: {}", e);
                    break;
                }
            }
            Ok(Err(e)) => {
                debug!("server_to_client: recv error: {}", e);
                break;
            }
            Err(_) => {
                debug!("server_to_client: timeout");
                break;
            }
        }
    }
}

/// 处理 UDP 会话
// 处理 UDP 会话
pub async fn handle_udp_session(
    client: TcpStream,
    initial_data: Option<Vec<u8>>,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    debug!("handle_udp_session: starting");
    
    // 创建 UDP socket
    let udp_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to create UDP socket: {}", e);
            return;
        }
    };

    let (mut client_read, mut client_write) = tokio::io::split(client);
    
    // 1. 完整读取并剥离头部 (直到 \r\n\r\n)
    let mut buffer = Vec::new();
    if let Some(d) = initial_data {
        buffer.extend_from_slice(&d);
    }
    
    let flag_bytes = config.udp_flag.as_bytes();
    let mut read_buf = [0u8; 4096];

    // 如果缓冲区开头不是 flag，可能是直接的 UDP 包（如果 flag 已经在 http_tunnel 中被部分消耗？）
    // 但通常 http_tunnel 传递包含 header 的 extra_data
    // 我们先尝试查找 flag 或 httpUDP，如果找到了，就必须等待直到 \r\n\r\n
    
    // 简单的状态机：如果不以 flag 开头，假设没有 header 或 header 已被处理
    // 但为了鲁棒性，我们检查缓冲区是否以 flag 开头
    let starts_with_flag = buffer.starts_with(flag_bytes) || buffer.starts_with(b"httpUDP");
    
    if starts_with_flag {
        info!("UDP session starts with flag, waiting for full header...");
        loop {
            // 检查是否包含 \r\n\r\n
            if let Some(pos) = find_subsequence(&buffer, b"\r\n\r\n") {
                let header_len = pos + 4;
                info!("Stripped {} bytes header from UDP stream", header_len);
                buffer.drain(0..header_len);
                break;
            }
            
            // 如果堆积太多数据还没找到换行，可能是异常，强制中止 header 搜索
            if buffer.len() > 65536 {
                error!("UDP header too long, aborting header strip");
                break; 
            }

            // 读取更多数据
            match timeout(std::time::Duration::from_secs(5), client_read.read(&mut read_buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    buffer.extend_from_slice(&read_buf[..n]);
                }
                _ => {
                    // 读取失败或超时
                    error!("Timeout or EOF while waiting for UDP header");
                    break;
                }
            }
        }
    } else {
        // 不以 flag 开头，假设是纯数据
    }

    // 2. 初始化 UDP 数据 (验证)
    // 此时 buffer 应该包含 Encrypted Payload
    // 参考 Go 版本：只有当数据足够时才进行验证，否则允许继续读取
    let (initial_password_index, initial_data_decrypted) = if !buffer.is_empty() {
        // UDP 数据包最小长度为 12 字节（IPv4）或 24 字节（IPv6）
        // 如果数据不足，暂不验证，让后续读取补充完整
        if buffer.len() < 12 {
            debug!("Initial data too short ({} bytes), deferring validation", buffer.len());
            (0, false)
        } else {
            match init_udp_data(&mut buffer, &password) {
                Ok((idx, _offset)) => (idx, true), // offset is data.len()
                Err(e) => {
                    error!("Init UDP session failed: {}", e);
                    return;
                }
            }
        }
    } else {
        (0, false)
    };

    // 如果初始化解密成功，initial_stream_offset 应该是 buffer.len() ?
    // 不，`init_udp_data` return `(idx, len)`. But `client_to_server` handles `initial_data` separately.
    // In `client_to_server`, if `initial_data_decrypted` is true, it assumes data is plaintext.
    // But `client_to_server` logic for `stream_offset` logic: 
    // If we pass `initial_stream_offset`, it starts there.
    // If `initial_data` is decrypted, its length should contribute to offset?
    // In `client_to_server`:
    // if `initial_data` is sent, `stream_offset` isn't updated?
    // `client_to_server` signature was: `fn...(..., initial_stream_offset, ...)`
    // And logic: `let mut stream_offset = initial_stream_offset;`
    // If `initial_data` was decrypted in `handle_udp_session`, then effectively we consumed those bytes from the "encryption stream".
    // So `initial_stream_offset` passed to `client_to_server` should be `0`.
    // BUT `client_to_server` does NOT use `stream_offset` for `initial_data` if it is already decrypted.
    // It DOES increment `stream_offset` for loop reads.
    // So if we processed `N` bytes as initial data, the next read starts at offset `N`.
    // So `initial_stream_offset` passed to `client_to_server` should be `buffer.len()` if decrypted?
    // Wait. `client_to_server` logic:
    // `loop { read n; decrypt(..., stream_offset); stream_offset += n }`
    // If `initial_data` (len N) was processed before loop. The loop reads start at N.
    // So yes, `initial_stream_offset` should be `buffer.len()` if buffer was processed.
    
    let initial_stream_offset = if initial_data_decrypted { buffer.len() } else { 0 };

    // 传入剩余的 buffer 作为 initial_data
    let initial_payload = if buffer.is_empty() { None } else { Some(buffer) };
    
    let config2 = config.clone();
    let password2 = password.clone();
    let udp_socket2 = udp_socket.clone();

    // 双向转发
    tokio::select! {
        _ = client_to_server(&mut client_read, &udp_socket, initial_payload, initial_password_index, initial_data_decrypted, initial_stream_offset, config, password) => {}
        _ = server_to_client(&mut client_write, &udp_socket2, config2, password2) => {}
    }
    
    debug!("handle_udp_session: ended");
}

/// 查找子序列辅助函数
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
