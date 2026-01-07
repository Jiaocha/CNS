//! UDP 模块 - 处理 UDP over HTTP Tunnel

use crate::config::Config;
#[allow(deprecated)]
use crate::crypto::xor_crypt;
use log::{error, debug, info};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// 解析并转发数据到服务器
/// 返回已处理的字节数
async fn write_to_server(udp_socket: &Arc<UdpSocket>, data: &[u8]) -> i32 {
    let data_len = data.len();
    let mut pkg_sub = 0;
    
    // 循环处理数据中的所有包
    // 格式: [Len_LB, Len_HB, Body...]
    while pkg_sub + 2 < data_len {
        let pkg_len = (data[pkg_sub] as u16) | ((data[pkg_sub + 1] as u16) << 8);
        
        // 检查包是否完整
        if pkg_sub + 2 + pkg_len as usize > data_len {
            // 包不完整，等待更多数据
            break;
        }

        // 验证保留字段 (Offset 2, 3, 4)
        if pkg_len >= 10 {
             if data[pkg_sub+2] != 0 || data[pkg_sub+3] != 0 || data[pkg_sub+4] != 0 {
                  info!("UDP Error: reserved fields check failed. data[2..5]={:?}, likely decryption error or wrong protocol. PkgLen={}", &data[pkg_sub+2..pkg_sub+5], pkg_len);
                  // 尝试跳过这个包
                  pkg_sub += 2 + pkg_len as usize;
                  continue;
             }
        }

        // 解析地址
        let addr_type = data[pkg_sub + 5];
        let addr_len;
        let mut ip_addr = None;
        let port;

        match addr_type {
            1 => { // IPv4
                addr_len = 4;
                if pkg_sub + 10 + addr_len > data_len { break; }
                let ip = Ipv4Addr::new(
                    data[pkg_sub + 6],
                    data[pkg_sub + 7],
                    data[pkg_sub + 8],
                    data[pkg_sub + 9],
                );
                ip_addr = Some(IpAddr::V4(ip));
                port = (data[pkg_sub + 10] as u16) << 8 | (data[pkg_sub + 11] as u16);
                info!("UDP Decrypted IPv4: {}:{}", ip, port);
            },
            3 => { // Domain
                 if pkg_sub + 7 > data_len { break; }
                 let len = data[pkg_sub + 6] as usize;
                 addr_len = 1 + len;
                  if pkg_sub + 7 + len + 2 > data_len { break; } // Domain + Port
                   let domain_bytes = &data[pkg_sub + 7 .. pkg_sub + 7 + len];
                   if let Ok(domain) = std::str::from_utf8(domain_bytes) {
                        debug!("write_to_server: Domain address parsing (not fully supported): {}", domain);
                   }
                   port = (data[pkg_sub + 7 + len] as u16) << 8 | (data[pkg_sub + 7 + len + 1] as u16);
            },
            4 => { // IPv6
                addr_len = 16;
                if pkg_sub + 7 + addr_len + 2 > data_len { break; } // IPv6 + Port
                 let ip = Ipv6Addr::from([
                    data[pkg_sub+6], data[pkg_sub+7], data[pkg_sub+8], data[pkg_sub+9],
                    data[pkg_sub+10], data[pkg_sub+11], data[pkg_sub+12], data[pkg_sub+13],
                    data[pkg_sub+14], data[pkg_sub+15], data[pkg_sub+16], data[pkg_sub+17],
                    data[pkg_sub+18], data[pkg_sub+19], data[pkg_sub+20], data[pkg_sub+21]
                 ]);
                 ip_addr = Some(IpAddr::V6(ip));
                 port = (data[pkg_sub + 22] as u16) << 8 | (data[pkg_sub + 23] as u16);
            },
             _ => {
                debug!("write_to_server: unknown address type {}", addr_type);
                 pkg_sub += 2 + pkg_len as usize;
                 continue;
             }
        }
        
        if let Some(ip) = ip_addr {
            let target = SocketAddr::new(ip, port);
            
            let header_len = 7 + addr_len;
            if pkg_len as usize >= header_len {
                 let payload_start = pkg_sub + 2 + header_len;
                 let payload_end = pkg_sub + 2 + pkg_len as usize;
                 let payload = &data[payload_start .. payload_end];
                 
                 debug!("write_to_server: Parse OK. Sending {} bytes to {}", payload.len(), target);
                 
                 // 发送 UDP 数据
                 if let Err(e) = udp_socket.send_to(payload, target).await {
                     error!("write_to_server: send_to failed: {}", e);
                 }
            } else {
                debug!("write_to_server: pkg_len {} too small for header_len {}", pkg_len, header_len);
            }
        }

        pkg_sub += 2 + pkg_len as usize;
    }
    
    pkg_sub as i32
}

/// 客户端到服务器转发
async fn client_to_server(
    mut client_read: tokio::io::ReadHalf<TcpStream>,
    udp_socket: Arc<UdpSocket>,
    initial_data_vec: Option<Vec<u8>>,
    password: Arc<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65536];
    let mut payload_len = 0;
    
    // 如果有初始数据，先放入 buffer
    if let Some(data) = initial_data_vec {
        if data.len() < buffer.len() {
             buffer[..data.len()].copy_from_slice(&data);
             payload_len = data.len();
        }
    }
    
    loop {
        // 读取更多数据
        if payload_len < buffer.len() {
             // 设置短超时，以便处理已有的数据
             let read_future = client_read.read(&mut buffer[payload_len..]);
             match tokio::time::timeout(std::time::Duration::from_millis(10), read_future).await {
                Ok(Ok(n)) => {
                    if n == 0 {
                        debug!("client_to_server: connection closed");
                        break;
                    }
                    debug!("client_to_server: read {} bytes", n);
                    payload_len += n;
                },
                Ok(Err(e)) => {
                    error!("client_to_server: read error: {}", e);
                    break;
                },
                Err(_) => {
                    // Timeout, just process what we have
                }
             }
        }
        
        if payload_len == 0 {
            // 如果没数据且没读到，继续等（这里其实应该更智能点，避免死循环空转）
             // 实际上上面的 read 是有超时的。如果读不到，会在这里转圈。
             // 稍微 sleep 一下避免 CPU 100%
             tokio::time::sleep(std::time::Duration::from_millis(5)).await;
             
             // 再次尝试阻塞读取
             match client_read.read(&mut buffer[payload_len..]).await {
                 Ok(n) if n == 0 => break,
                 Ok(n) => payload_len += n,
                 Err(e) => { error!("client_to_server: read error: {}", e); break; }
             }
             if payload_len == 0 { break; }
        }

        // 尝试处理 buffer 中的包
        // 关键逻辑：每个包都独立加密 (reset password_index to 0)
        
        let mut processed_total = 0;
        
        loop {
            // 至少需要 2 字节来解析长度
            if payload_len - processed_total < 2 {
                break;
            }
            
            let start = processed_total;
            
            // 偷看前 2 字节，用 pwd_idx=0 解密（不修改原 buffer）
            let mut len_bytes = [buffer[start], buffer[start+1]];
            if !password.is_empty() {
                xor_crypt(&mut len_bytes, &password, 0, 0);
            }
            
            // 解析包长度 (Little Endian)
            let pkg_len = (len_bytes[0] as usize) | ((len_bytes[1] as usize) << 8);
            
            // 包总长 = 长度前缀(2) + Body(pkg_len)
            let full_pkg_len = 2 + pkg_len;
            
            if payload_len - processed_total < full_pkg_len {
                // 数据不足一个整包，等待读取
                break;
            }
            
            // 数据足够，解密这个完整的包（包括前缀）
            debug!("client_to_server: Decrypting packet of len {} with idx 0", full_pkg_len);
            
            if !password.is_empty() {
                // 必须在 buffer 上修改解密
                xor_crypt(&mut buffer[start .. start + full_pkg_len], &password, 0, 0);
            }
            
            // 调用 write_to_server 解析并转发
            // 注意：write_to_server 会处理这些已解密的数据
            let consumed = write_to_server(&udp_socket, &buffer[start .. start + full_pkg_len]).await;
            
            // 无论 write_to_server 返回消耗多少（它其实只处理这一个包），我们都认为这个包被处理了
            // 因为这是 Packet-Based 的
            processed_total += full_pkg_len;
            
            if consumed != full_pkg_len as i32 {
                 debug!("client_to_server: parsing warning, consumed={} vs len={}", consumed, full_pkg_len);
            }
        }
        
        // 移动剩余数据
        if processed_total > 0 {
            if processed_total < payload_len {
                buffer.copy_within(processed_total..payload_len, 0);
                payload_len -= processed_total;
            } else {
                payload_len = 0;
            }
        } else {
             // 没有处理任何数据（数据不足），强制读更多
             // 如果 buffer 满了还解析不出？那说明出大问题了（或者包巨大）
             if payload_len >= buffer.len() {
                 error!("client_to_server: buffer full but no packet parsed. Dropping connection.");
                 break;
             }
        }
    }
    Ok(())
}

/// 服务器到客户端转发
async fn server_to_client(
    client_write: &mut tokio::io::WriteHalf<TcpStream>,
    udp_socket: &Arc<UdpSocket>,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) -> std::io::Result<()> {
    let mut buffer = vec![0u8; 65536];
    
    // 用于加密流的维护
    // clnc 是 Per-Packet Encryption 吗？
    // 如果 Client 发送是 Per-Packet，那么 Server 回复应该也是 Per-Packet？
    // Go 版本的 udpServerToClient 也是流式的：
    // udpSess.s2c_CuteBi_XorCrypt_passwordSub = CuteBi_XorCrypt(...)
    // 但是 Go 版本在 handleUdpSession 里，passwordSub 也是 loop 变量。
    // 如果 client -> server reset mask, 那么 server -> client 也应该 reset mask?
    // v0.5.8 是流式的，导致了 timeout (server 收不到回包？或者发不回去？)
    // 假设是 reset mask 0 for every packet sent back.
    
    let password_is_empty = password.is_empty();

    loop {
        let (n, addr) = match timeout(config.udp_timeout(), udp_socket.recv_from(&mut buffer[2..])).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                error!("server_to_client: recv error: {}", e);
                return Err(e);
            }
            Err(_) => {
                debug!("server_to_client: timeout");
                return Ok(());
            }
        };

        debug!("server_to_client: received {} bytes from {}", n, addr);

        // 构造 socks5 头部回包
        // Length (2 bytes) + [0,0,0] (Resv) + 1 (IPv4) + Addr + Port
        // 实际上我们可能只需要把接收到的数据（不含Socks头）打包成 Socks UDP 格式？
        // UDP over TCP 协议格式：[Len_LB, Len_HB, Body]
        // Body 格式：Socks5 UDP Header + Payload.
        // Socks5 UDP Header: RSV(2) FRAG(1) ATYP(1) ADDR PORT
        
        // 我们接收到的是纯 UDP payload。我们需要封装它。
        
        // 构造头部
        // RSV, FRAG
        // buffer[2] start.
        // shift data? No, we recv at buffer[2..].
        // Header space at buffer[0..].
        // We need simplify construction.
        // Let's build a new buffer.
        
        // UDP Response Body:
        // RSV(2) 00 00
        // FRAG(1) 00
        // ATYP(1) 
        // ADDR
        // PORT
        // DATA
        
        let mut packet = Vec::new(); // Length placeholder
        packet.extend_from_slice(&[0, 0]); // Length
        packet.extend_from_slice(&[0, 0, 0]); // RSV, FRAG
        
        match addr {
            SocketAddr::V4(v4) => {
                packet.push(1); // IPv4
                packet.extend_from_slice(&v4.ip().octets());
                packet.extend_from_slice(&v4.port().to_be_bytes());
            },
            SocketAddr::V6(v6) => {
                packet.push(4); // IPv6
                packet.extend_from_slice(&v6.ip().octets());
                packet.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        
        // DATA
        packet.extend_from_slice(&buffer[2..2+n]);
        
        // Fill Length
        let total_body_len = packet.len() - 2;
        packet[0] = total_body_len as u8;
        packet[1] = (total_body_len >> 8) as u8;
        
        // Encrypt (Reset idx 0)
        if !password_is_empty {
            xor_crypt(&mut packet, &password, 0, 0);
        }
        
        client_write.write_all(&packet).await?;
    }
}


/// 处理 UDP 会话
pub async fn handle_udp_session(
    client: TcpStream,
    initial_data: Option<Vec<u8>>,
    config: Arc<Config>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("handle_udp_session: starting");
    
    // 创建 UDP socket
    let udp_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to create UDP socket: {}", e);
            return Err(Box::new(e));
        }
    };

    let password = Arc::new(config.encrypt_password.clone().into_bytes());
    
    // 如果有初始数据，需要先剥离 httpUDP 伪头部
    let mut initial_data_clean = None;
    if let Some(data) = initial_data {
        let flag_bytes = config.udp_flag.as_bytes();
        let header_len = flag_bytes.len() + 4; // flag + \r\n\r\n
        
        // 只有当数据确实以 udp_flag 开头时才剥离
        // 这主要用于非标准 HTTP 头的 UDP 连接（如 raw httpUDP）
        // 对于通过标准 HTTP 头建立的连接，header 已经被 http_tunnel 剥离，这里的 data 是 payload
        if data.len() >= flag_bytes.len() && &data[..flag_bytes.len()] == flag_bytes {
            if data.len() >= header_len {
                info!("UDP session starts with flag, stripped {} bytes header", header_len);
                initial_data_clean = Some(data[header_len..].to_vec());
            } else {
                // 数据长度不足完整头部，但以前缀开头，可能只是部分头部
                // 这种情况下我们清空数据等待后续
                initial_data_clean = Some(Vec::new());
            }
        } else {
             // 不以 flag 开头，认为是 payload 数据
             initial_data_clean = Some(data);
        }
    }

    let (client_read, mut client_write) = tokio::io::split(client);
    
    let udp_socket_clone = udp_socket.clone();
    let config_clone = config.clone();
    let password_clone = password.clone();
    let password_clone2 = password.clone();

    // 启动两个任务：Client->Server 和 Server->Client
    
    let s2c = server_to_client(&mut client_write, &udp_socket, config_clone, password_clone);
    let c2s = client_to_server(client_read, udp_socket_clone, initial_data_clean, password_clone2);

    // 等待任意一个结束
    tokio::select! {
        res = s2c => {
            debug!("handle_udp_session: s2c ended {:?}", res);
        }
        res = c2s => {
            debug!("handle_udp_session: c2s ended {:?}", res);
        }
    }
    
    debug!("handle_udp_session: ended");
    Ok(())
}

/// 查找子序列辅助函数
#[allow(dead_code)]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
