//! 流量统计模块 - 跟踪连接和数据传输统计

use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// 全局统计数据
static STATS: Lazy<Statistics> = Lazy::new(Statistics::new);

/// 统计数据结构
pub struct Statistics {
    /// 服务启动时间
    start_time: Instant,
    
    /// 总接收字节数
    bytes_received: AtomicU64,
    
    /// 总发送字节数
    bytes_sent: AtomicU64,
    
    /// 总连接数
    total_connections: AtomicU64,
    
    /// 当前活跃连接数
    active_connections: AtomicU64,
    
    /// TCP 连接数
    tcp_connections: AtomicU64,
    
    /// UDP 会话数
    udp_sessions: AtomicU64,
    
    /// TLS 连接数
    tls_connections: AtomicU64,
    
    /// HTTP DNS 请求数
    http_dns_requests: AtomicU64,
    
    /// 错误计数
    errors: AtomicU64,
}

impl Statistics {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
            udp_sessions: AtomicU64::new(0),
            tls_connections: AtomicU64::new(0),
            http_dns_requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

/// 统计快照 (用于导出)
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub uptime_secs: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub tcp_connections: u64,
    pub udp_sessions: u64,
    pub tls_connections: u64,
    pub http_dns_requests: u64,
    pub errors: u64,
}

// ============================================================================
// 公共 API
// ============================================================================

/// 获取统计快照
pub fn get_snapshot() -> StatsSnapshot {
    StatsSnapshot {
        uptime_secs: STATS.start_time.elapsed().as_secs(),
        bytes_received: STATS.bytes_received.load(Ordering::Relaxed),
        bytes_sent: STATS.bytes_sent.load(Ordering::Relaxed),
        total_connections: STATS.total_connections.load(Ordering::Relaxed),
        active_connections: STATS.active_connections.load(Ordering::Relaxed),
        tcp_connections: STATS.tcp_connections.load(Ordering::Relaxed),
        udp_sessions: STATS.udp_sessions.load(Ordering::Relaxed),
        tls_connections: STATS.tls_connections.load(Ordering::Relaxed),
        http_dns_requests: STATS.http_dns_requests.load(Ordering::Relaxed),
        errors: STATS.errors.load(Ordering::Relaxed),
    }
}

/// 记录接收的字节数
#[inline]
pub fn record_bytes_received(bytes: u64) {
    STATS.bytes_received.fetch_add(bytes, Ordering::Relaxed);
}

/// 记录发送的字节数
#[inline]
pub fn record_bytes_sent(bytes: u64) {
    STATS.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
}

/// 记录新连接
#[inline]
pub fn record_new_connection() {
    STATS.total_connections.fetch_add(1, Ordering::Relaxed);
    STATS.active_connections.fetch_add(1, Ordering::Relaxed);
}

/// 记录连接关闭
#[inline]
pub fn record_connection_closed() {
    STATS.active_connections.fetch_sub(1, Ordering::Relaxed);
}

/// 记录 TCP 连接
#[inline]
pub fn record_tcp_connection() {
    STATS.tcp_connections.fetch_add(1, Ordering::Relaxed);
}

/// 记录 UDP 会话
#[inline]
pub fn record_udp_session() {
    STATS.udp_sessions.fetch_add(1, Ordering::Relaxed);
}

/// 记录 TLS 连接
#[inline]
pub fn record_tls_connection() {
    STATS.tls_connections.fetch_add(1, Ordering::Relaxed);
}

/// 记录 HTTP DNS 请求
#[inline]
pub fn record_http_dns_request() {
    STATS.http_dns_requests.fetch_add(1, Ordering::Relaxed);
}

/// 记录错误
#[inline]
pub fn record_error() {
    STATS.errors.fetch_add(1, Ordering::Relaxed);
}

/// 获取运行时间 (秒)
pub fn uptime_secs() -> u64 {
    STATS.start_time.elapsed().as_secs()
}

/// 格式化统计信息为字符串
pub fn format_stats() -> String {
    let snap = get_snapshot();
    
    let uptime = format_duration(snap.uptime_secs);
    let bytes_recv = format_bytes(snap.bytes_received);
    let bytes_sent = format_bytes(snap.bytes_sent);
    
    format!(
        "Uptime: {}\n\
         Connections: {} total, {} active\n\
         Traffic: {} received, {} sent\n\
         By type: {} TCP, {} UDP, {} TLS\n\
         HTTP DNS: {} requests\n\
         Errors: {}",
        uptime,
        snap.total_connections, snap.active_connections,
        bytes_recv, bytes_sent,
        snap.tcp_connections, snap.udp_sessions, snap.tls_connections,
        snap.http_dns_requests,
        snap.errors
    )
}

/// 格式化字节数为可读格式
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    
    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// 格式化持续时间为可读格式
fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(60), "1m 0s");
        assert_eq!(format_duration(3661), "1h 1m 1s");
        assert_eq!(format_duration(86400 + 3661), "1d 1h 1m 1s");
    }

    #[test]
    fn test_record_stats() {
        record_bytes_received(100);
        record_bytes_sent(200);
        record_new_connection();
        record_tcp_connection();
        
        let snap = get_snapshot();
        assert!(snap.bytes_received >= 100);
        assert!(snap.bytes_sent >= 200);
        assert!(snap.total_connections >= 1);
        assert!(snap.tcp_connections >= 1);
    }
}
