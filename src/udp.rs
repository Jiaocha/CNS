//! UDP 模块 - 处理 UDP over HTTP Tunnel

use crate::config::Config;
use crate::crypto::xor_crypt;
use log::error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// 从 httpUDP 数据包中解析目标地址和 payload
fn parse_packet(data: &[u8], offset: usize) -> Option<(SocketAddr, usize, usize)> {
    if offset + 2 >= data.len() {
        return None;
    }

    // 2 字节包长度（小端序）
    let pkg_len = (data[offset] as u16) | ((data[offset + 1] as u16) << 8);
    let pkg_len = pkg_len as usize;

    if offset + 2 + pkg_len > data.len() || pkg_len <= 10 {
        return None;
    }

    // 检查保留字段
    if data[offset + 3] != 0 || data[offset + 4] != 0 {
        return None;
    }

    let addr_type = data[offset + 5];
    let (addr, header_len) = if addr_type == 1 {
        // IPv4
        if pkg_len < 12 {
            return None;
        }
        let ip = Ipv4Addr::new(
            data[offset + 6],
            data[offset + 7],
            data[offset + 8],
            data[offset + 9],
        );
        let port = ((data[offset + 10] as u16) << 8) | (data[offset + 11] as u16);
        (SocketAddr::new(IpAddr::V4(ip), port), 12)
    } else {
        // IPv6
        if pkg_len < 24 {
            return None;
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&data[offset + 6..offset + 22]);
        let ip = Ipv6Addr::from(ip_bytes);
        let port = ((data[offset + 22] as u16) << 8) | (data[offset + 23] as u16);
        (SocketAddr::new(IpAddr::V6(ip), port), 24)
    };

    Some((addr, header_len, pkg_len))
}

/// 写入数据到 UDP 服务器
async fn write_to_server(udp_socket: &UdpSocket, data: &[u8]) -> Result<usize, std::io::Error> {
    let mut offset = 0;

    while let Some((addr, header_len, pkg_len)) = parse_packet(data, offset) {
        let payload_start = offset + 2 + header_len;
        let payload_end = offset + 2 + pkg_len;

        if payload_end > data.len() {
            break;
        }

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

        // 验证协议头
        if test_data[2] != 0 || test_data[3] != 0 || test_data[4] != 0 {
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
            Err(_) => break,
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
        let recv_result = timeout(config.udp_timeout(), udp_socket.recv_from(&mut buffer[24..])).await;

        match recv_result {
            Ok(Ok((n, addr))) => {
                // 构建 httpUDP 协议头
                let (header_start, header_len) = match addr.ip() {
                    IpAddr::V4(ip) => {
                        // IPv4: 从偏移 12 开始
                        buffer[12] = ((n + 10) & 0xFF) as u8;
                        buffer[13] = ((n + 10) >> 8) as u8;
                        buffer[14..18].copy_from_slice(&[0, 0, 0, 1]);
                        buffer[18..22].copy_from_slice(&ip.octets());
                        (12, 12)
                    }
                    IpAddr::V6(ip) => {
                        // IPv6: 从偏移 0 开始
                        buffer[0] = ((n + 22) & 0xFF) as u8;
                        buffer[1] = ((n + 22) >> 8) as u8;
                        buffer[2..6].copy_from_slice(&[0, 0, 0, 3]);
                        buffer[6..22].copy_from_slice(&ip.octets());
                        (0, 24)
                    }
                };

                // 设置端口
                buffer[22] = (addr.port() >> 8) as u8;
                buffer[23] = (addr.port() & 0xFF) as u8;

                let total_len = header_len + n;

                // 加密
                if !password.is_empty() {
                    password_index = xor_crypt(
                        &mut buffer[header_start..header_start + total_len],
                        &password,
                        password_index,
                    );
                }

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
            Err(_) => break,
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
}
