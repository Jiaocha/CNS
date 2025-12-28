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
/// 返回 Ok(password_index) 解密数据并返回密钥索引
fn init_udp_data(data: &mut [u8], password: &[u8]) -> Result<usize, &'static str> {
    if !password.is_empty() && data.len() >= 5 {
        // 解密前5字节进行验证
        let mut test_data = [0u8; 5];
        test_data.copy_from_slice(&data[..5]);
        xor_crypt(&mut test_data, password, 0);

        // 验证协议头: de[2] != 0 || de[3] != 0 || de[4] != 0
        // Go 代码检查 [2], [3], [4] 都为 0
        // 验证协议头: de[2] != 0 || de[3] != 0 || de[4] != 0
        // Go 代码检查 [2], [3], [4] 都为 0
        if test_data[2] != 0 || test_data[3] != 0 || test_data[4] != 0 {
            info!("UDP Verify failed. Raw (hex): {:02X?}", &data[..std::cmp::min(data.len(), 16)]);
            info!("Decrypted header (hex): {:02X?}", test_data);
            return Err("Is not httpUDP protocol or Decrypt failed");
        }

        // 解密整个数据，返回密钥索引
        Ok(xor_crypt(data, password, 0))
    } else {
        Ok(0)
    }
}

/// 客户端到服务器转发
async fn client_to_server(
    client_read: &mut tokio::io::ReadHalf<TcpStream>,
    udp_socket: &UdpSocket,
    initial_data: Option<Vec<u8>>,
    initial_password_index: usize,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    let mut buffer = vec![0u8; 65536];
    let mut payload_len = 0usize;
    // 从初始化返回的密钥索引开始
    let mut password_index = initial_password_index;

    // 处理初始数据（已经被解密了）
    if let Some(data) = initial_data {
        debug!("client_to_server: processing initial data, len={}", data.len());
        let w_len = write_to_server(udp_socket, &data).await;
        if w_len == -1 {
            return;
        }
        let w_len = w_len as usize;
        if w_len < data.len() {
            payload_len = data.len() - w_len;
            buffer[..payload_len].copy_from_slice(&data[w_len..]);
        }
    }

    loop {
        let read_result =
            timeout(config.udp_timeout(), client_read.read(&mut buffer[payload_len..])).await;

        match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                debug!("client_to_server: read {} bytes from client", n);
                
                // 解密（使用当前密钥索引继续）
                if !password.is_empty() {
                    password_index = xor_crypt(
                        &mut buffer[payload_len..payload_len + n],
                        &password,
                        password_index,
                    );
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

    loop {
        // 从偏移 24 开始读取，留出协议头空间
        let recv_result = timeout(config.udp_timeout(), udp_socket.recv_from(&mut buffer[24..])).await;

        match recv_result {
            Ok(Ok((n, addr))) => {
                debug!("server_to_client: received {} bytes from {}", n, addr);
                
                // 构建 httpUDP 协议头
                // Go 代码通过检查 IPv4-mapped IPv6 地址来判断
                // bytes.HasPrefix(RAddr.IP, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
                let (header_start, total_len) = match addr.ip() {
                    IpAddr::V4(ip) => {
                        // IPv4: 从偏移 12 开始（24-12=12字节协议头空间）
                        // payload[12] = byte(payload_len + 10)
                        // payload[13] = byte((payload_len + 10) >> 8)
                        // copy(payload[14:18], []byte{0, 0, 0, 1})
                        // copy(payload[18:22], []byte(RAddr.IP)[12:16])
                        buffer[12] = ((n + 10) & 0xFF) as u8;
                        buffer[13] = ((n + 10) >> 8) as u8;
                        buffer[14] = 0;
                        buffer[15] = 0;
                        buffer[16] = 0;
                        buffer[17] = 1; // addr type = IPv4
                        buffer[18..22].copy_from_slice(&ip.octets());
                        buffer[22] = (addr.port() >> 8) as u8;
                        buffer[23] = (addr.port() & 0xFF) as u8;
                        // 总长度 = 12 (header from offset 12) + n (payload)
                        (12, 12 + n)
                    }
                    IpAddr::V6(ip) => {
                        // IPv6: 从偏移 0 开始
                        // payload[0] = byte(payload_len + 22)
                        // payload[1] = byte((payload_len + 22) >> 8)
                        // copy(payload[2:6], []byte{0, 0, 0, 3})
                        // copy(payload[6:22], []byte(RAddr.IP))
                        buffer[0] = ((n + 22) & 0xFF) as u8;
                        buffer[1] = ((n + 22) >> 8) as u8;
                        buffer[2] = 0;
                        buffer[3] = 0;
                        buffer[4] = 0;
                        buffer[5] = 3; // addr type = IPv6
                        buffer[6..22].copy_from_slice(&ip.octets());
                        buffer[22] = (addr.port() >> 8) as u8;
                        buffer[23] = (addr.port() & 0xFF) as u8;
                        // 总长度 = 24 (header from offset 0) + n (payload)
                        (0, 24 + n)
                    }
                };

                // 加密
                if !password.is_empty() {
                    password_index = xor_crypt(
                        &mut buffer[header_start..header_start + total_len],
                        &password,
                        password_index,
                    );
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

    // 初始化数据并获取密钥索引
    let mut data = initial_data;
    let initial_password_index = if let Some(ref mut d) = data {
        match init_udp_data(d, &password) {
            Ok(idx) => idx,
            Err(e) => {
                error!("Init UDP session failed: {}", e);
                return;
            }
        }
    } else {
        0
    };

    let (mut client_read, mut client_write) = tokio::io::split(client);

    let config2 = config.clone();
    let password2 = password.clone();
    let udp_socket2 = udp_socket.clone();

    // 双向转发
    tokio::select! {
        _ = client_to_server(&mut client_read, &udp_socket, data, initial_password_index, config, password) => {}
        _ = server_to_client(&mut client_write, &udp_socket2, config2, password2) => {}
    }
    
    debug!("handle_udp_session: ended");
}
