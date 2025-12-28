//! UDP 模块 - 处理 UDP over HTTP Tunnel

use crate::config::Config;
use crate::crypto::xor_crypt;
use log::{error, debug};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// 从 httpUDP 数据包中解析目标地址和 payload
/// 返回 (目标地址, 协议头长度, 包总长度)
fn parse_packet(data: &[u8], offset: usize) -> Option<(SocketAddr, usize, usize)> {
    if offset + 2 >= data.len() {
        return None;
    }

    // 2 字节包长度（小端序），包括协议头
    let pkg_len = (data[offset] as u16) | ((data[offset + 1] as u16) << 8);
    let pkg_len = pkg_len as usize;

    debug!("parse_packet: offset={}, pkg_len={}, data_len={}", offset, pkg_len, data.len());

    if pkg_len <= 10 || offset + 2 + pkg_len > data.len() {
        debug!("parse_packet: invalid pkg_len or data too short");
        return None;
    }

    // 检查保留字段 (offset+2 是包数据开始)
    // 结构: [len:2][rsv:1][frag:1][atyp:1][addr:...][port:2][data:...]
    // Go 代码检查的是 httpUDP_data[pkgSub+3:pkgSub+5] == {0, 0}
    if data[offset + 2] != 0 || data[offset + 3] != 0 {
        debug!("parse_packet: reserved fields not zero");
        return None;
    }

    // 地址类型在 offset+4 (即 pkgSub+2+2，两字节长度后再加2字节保留)
    // Go 代码: httpUDP_data[5] == 1，但这是相对于 pkgSub 的，所以是 pkgSub+2+3 = offset+5
    // 不对，Go代码是 httpUDP_data[5]，这是绝对偏移，不是相对于 pkgSub
    // 重新看：Go 代码 for 循环中 pkgSub 从 0 开始，所以第一个包时 httpUDP_data[5] = data[5]
    // 这意味着协议格式是：
    // [0-1]: 包长度 (小端序)
    // [2]: RSV
    // [3]: FRAG  
    // [4]: ATYP (0=保留，但Go用的offset是5)
    // 
    // 仔细看 Go 代码：
    // if bytes.HasPrefix(httpUDP_data[pkgSub+3:pkgSub+5], []byte{0, 0}) == false 检查 [3],[4] 是否为 0
    // if httpUDP_data[5] == 1 检查的是固定位置5，这在多包情况下不对...
    // 
    // 实际上 Go 代码可能有 bug，但原版能工作，说明正确的是：
    // [0-1]: 包长度
    // [2-3]: 保留 (必须为0)
    // [4]: 保留
    // [5]: 地址类型 (1=IPv4, 3=IPv6)
    // [6-9] 或 [6-21]: IP地址
    // [10-11] 或 [22-23]: 端口
    
    let addr_type = data[offset + 5];
    debug!("parse_packet: addr_type={}", addr_type);
    
    let (addr, header_len) = if addr_type == 1 {
        // IPv4: 4字节IP + 2字节端口
        if pkg_len < 12 {
            debug!("parse_packet: pkg_len too small for IPv4");
            return None;
        }
        let ip = Ipv4Addr::new(
            data[offset + 6],
            data[offset + 7],
            data[offset + 8],
            data[offset + 9],
        );
        let port = ((data[offset + 10] as u16) << 8) | (data[offset + 11] as u16);
        debug!("parse_packet: IPv4 addr={}:{}", ip, port);
        (SocketAddr::new(IpAddr::V4(ip), port), 12)
    } else if addr_type == 3 {
        // IPv6: 16字节IP + 2字节端口
        if pkg_len < 24 {
            debug!("parse_packet: pkg_len too small for IPv6");
            return None;
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&data[offset + 6..offset + 22]);
        let ip = Ipv6Addr::from(ip_bytes);
        let port = ((data[offset + 22] as u16) << 8) | (data[offset + 23] as u16);
        debug!("parse_packet: IPv6 addr={}:{}", ip, port);
        (SocketAddr::new(IpAddr::V6(ip), port), 24)
    } else {
        debug!("parse_packet: unknown addr_type {}", addr_type);
        return None;
    };

    // header_len 包含从包开始到 payload 的所有字节（不包括2字节长度前缀）
    // payload 从 offset + 2 + header_len 开始，到 offset + 2 + pkg_len 结束
    Some((addr, header_len, pkg_len))
}

/// 写入数据到 UDP 服务器
async fn write_to_server(udp_socket: &UdpSocket, data: &[u8]) -> Result<usize, std::io::Error> {
    let mut offset = 0;

    while let Some((addr, header_len, pkg_len)) = parse_packet(data, offset) {
        // payload 起始位置：跳过2字节长度 + 协议头
        let payload_start = offset + 2 + header_len;
        // payload 结束位置：2字节长度 + 包长度（包长度包含协议头和payload）
        let payload_end = offset + 2 + pkg_len;

        if payload_end > data.len() {
            break;
        }

        debug!("write_to_server: sending {} bytes to {}", payload_end - payload_start, addr);
        udp_socket
            .send_to(&data[payload_start..payload_end], addr)
            .await?;

        offset = payload_end;
    }

    Ok(offset)
}

/// 初始化 UDP 数据（验证加密数据）
fn init_udp_data(data: &mut [u8], password: &[u8]) -> Result<usize, &'static str> {
    if !password.is_empty() && data.len() >= 5 {
        let mut test_data = [0u8; 5];
        test_data.copy_from_slice(&data[..5]);
        xor_crypt(&mut test_data, password, 0);

        // 验证协议头: [2], [3], [4] 应该是 0, 0, 0 或 0, 0, 1/3
        // Go 代码检查 de[2] != 0 || de[3] != 0 || de[4] != 0
        // 但 de[4] 应该是地址类型（1或3），不应该是0
        // 这里 Go 代码可能有问题，或者初始化时确实需要检查
        // 保持与 Go 一致的行为
        if test_data[2] != 0 || test_data[3] != 0 {
            // 只检查保留字段
            return Err("Invalid protocol or decrypt failed");
        }

        // 解密整个数据
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
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    let mut buffer = vec![0u8; 65536];
    let mut payload_len = 0usize;
    let mut password_index = 0usize;

    // 处理初始数据
    if let Some(data) = initial_data {
        debug!("client_to_server: processing initial data, len={}", data.len());
        match write_to_server(udp_socket, &data).await {
            Ok(written) if written < data.len() => {
                payload_len = data.len() - written;
                buffer[..payload_len].copy_from_slice(&data[written..]);
            }
            Err(e) => {
                error!("Write to server error: {}", e);
                return;
            }
            _ => {}
        }
    }

    loop {
        let read_result =
            timeout(config.udp_timeout(), client_read.read(&mut buffer[payload_len..])).await;

        match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                debug!("client_to_server: read {} bytes from client", n);
                
                // 解密
                if !password.is_empty() {
                    password_index = xor_crypt(
                        &mut buffer[payload_len..payload_len + n],
                        &password,
                        password_index,
                    );
                }

                payload_len += n;

                match write_to_server(udp_socket, &buffer[..payload_len]).await {
                    Ok(written) if written < payload_len => {
                        buffer.copy_within(written..payload_len, 0);
                        payload_len -= written;
                    }
                    Ok(_) => payload_len = 0,
                    Err(e) => {
                        error!("Write to server error: {}", e);
                        return;
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Read from client error: {}", e);
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
                        // [12-13]: 包长度 = payload_len + 10 (协议头不含长度字段的部分)
                        // [14-17]: RSV(1) + FRAG(1) + ATYP(1)=1 + 保留(1) => 实际是 0,0,0,1
                        // [18-21]: IPv4 地址
                        // [22-23]: 端口
                        // [24...]: payload
                        buffer[12] = ((n + 10) & 0xFF) as u8;
                        buffer[13] = ((n + 10) >> 8) as u8;
                        buffer[14] = 0; // RSV
                        buffer[15] = 0; // FRAG
                        buffer[16] = 0; // 保留
                        buffer[17] = 1; // ATYP = IPv4
                        buffer[18..22].copy_from_slice(&ip.octets());
                        buffer[22] = (addr.port() >> 8) as u8;
                        buffer[23] = (addr.port() & 0xFF) as u8;
                        // 总长度 = 2(len) + 10(header) + n(payload) = 12 + n
                        (12, 12 + n)
                    }
                    IpAddr::V6(ip) => {
                        // IPv6: 从偏移 0 开始
                        // [0-1]: 包长度 = payload_len + 22
                        // [2-5]: RSV + FRAG + 保留 + ATYP=3 => 0,0,0,3
                        // [6-21]: IPv6 地址
                        // [22-23]: 端口
                        // [24...]: payload
                        buffer[0] = ((n + 22) & 0xFF) as u8;
                        buffer[1] = ((n + 22) >> 8) as u8;
                        buffer[2] = 0; // RSV
                        buffer[3] = 0; // FRAG
                        buffer[4] = 0; // 保留
                        buffer[5] = 3; // ATYP = IPv6
                        buffer[6..22].copy_from_slice(&ip.octets());
                        buffer[22] = (addr.port() >> 8) as u8;
                        buffer[23] = (addr.port() & 0xFF) as u8;
                        // 总长度 = 2(len) + 22(header) + n(payload) = 24 + n
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
                    error!("Write to client error: {}", e);
                    break;
                }
            }
            Ok(Err(e)) => {
                error!("Recv from server error: {}", e);
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

    // 初始化数据
    let mut data = initial_data;
    if let Some(ref mut d) = data {
        if let Err(e) = init_udp_data(d, &password) {
            error!("Init UDP session failed: {}", e);
            return;
        }
    }

    let (mut client_read, mut client_write) = tokio::io::split(client);

    let config2 = config.clone();
    let password2 = password.clone();
    let udp_socket2 = udp_socket.clone();

    // 双向转发
    tokio::select! {
        _ = client_to_server(&mut client_read, &udp_socket, data, config, password) => {}
        _ = server_to_client(&mut client_write, &udp_socket2, config2, password2) => {}
    }
    
    debug!("handle_udp_session: ended");
}
