//! DNS 缓存模块 - 提供高效的 DNS 查询缓存

use lru::LruCache;
use parking_lot::Mutex;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use once_cell::sync::Lazy;

/// 默认 DNS 缓存大小
const DEFAULT_CACHE_SIZE: usize = 1000;

/// 默认 DNS 缓存 TTL (秒)
const DEFAULT_TTL_SECS: u64 = 300; // 5 分钟

/// DNS 缓存条目
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// IP 地址列表
    addresses: Vec<IpAddr>,
    /// 过期时间
    expires_at: Instant,
}

impl DnsCacheEntry {
    fn new(addresses: Vec<IpAddr>, ttl: Duration) -> Self {
        Self {
            addresses,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// 全局 DNS 缓存
static DNS_CACHE: Lazy<Mutex<LruCache<String, DnsCacheEntry>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap()))
});

/// DNS 缓存统计
#[derive(Debug, Default)]
pub struct DnsCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub expired: u64,
}

static CACHE_STATS: Lazy<Mutex<DnsCacheStats>> = Lazy::new(|| {
    Mutex::new(DnsCacheStats::default())
});

/// 从缓存获取 DNS 解析结果
/// 
/// 返回 Some(addresses) 如果缓存命中且未过期
/// 返回 None 如果缓存未命中或已过期
pub fn get_cached(domain: &str) -> Option<Vec<IpAddr>> {
    let mut cache = DNS_CACHE.lock();
    
    if let Some(entry) = cache.get(domain) {
        if entry.is_expired() {
            // 缓存已过期,移除
            cache.pop(domain);
            CACHE_STATS.lock().expired += 1;
            tracing::debug!(domain = %domain, "DNS cache expired");
            None
        } else {
            // 缓存命中
            CACHE_STATS.lock().hits += 1;
            tracing::debug!(domain = %domain, "DNS cache hit");
            Some(entry.addresses.clone())
        }
    } else {
        // 缓存未命中
        CACHE_STATS.lock().misses += 1;
        tracing::debug!(domain = %domain, "DNS cache miss");
        None
    }
}

/// 将 DNS 解析结果存入缓存
pub fn put_cached(domain: &str, addresses: Vec<IpAddr>) {
    put_cached_with_ttl(domain, addresses, Duration::from_secs(DEFAULT_TTL_SECS));
}

/// 使用自定义 TTL 将 DNS 解析结果存入缓存
pub fn put_cached_with_ttl(domain: &str, addresses: Vec<IpAddr>, ttl: Duration) {
    if addresses.is_empty() {
        return;
    }
    
    let entry = DnsCacheEntry::new(addresses, ttl);
    DNS_CACHE.lock().put(domain.to_string(), entry);
    tracing::debug!(domain = %domain, ttl_secs = %ttl.as_secs(), "DNS cached");
}

/// 获取缓存统计信息
pub fn get_stats() -> DnsCacheStats {
    let stats = CACHE_STATS.lock();
    DnsCacheStats {
        hits: stats.hits,
        misses: stats.misses,
        expired: stats.expired,
    }
}

/// 清空 DNS 缓存
pub fn clear_cache() {
    DNS_CACHE.lock().clear();
    tracing::info!("DNS cache cleared");
}

/// 获取缓存大小
pub fn cache_size() -> usize {
    DNS_CACHE.lock().len()
}

/// 使用缓存解析 DNS
/// 
/// 先查缓存,未命中则执行实际查询并缓存结果
pub async fn resolve_cached(domain: &str) -> std::io::Result<Vec<IpAddr>> {
    // 先查缓存
    if let Some(addresses) = get_cached(domain) {
        return Ok(addresses);
    }
    
    // 缓存未命中,执行 DNS 查询
    let lookup_result = tokio::net::lookup_host(format!("{}:0", domain)).await?;
    
    let addresses: Vec<IpAddr> = lookup_result.map(|addr| addr.ip()).collect();
    
    if !addresses.is_empty() {
        put_cached(domain, addresses.clone());
    }
    
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_cache_put_get() {
        let domain = "test-cache-domain.example.com";
        let addresses = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        
        put_cached(domain, addresses.clone());
        
        let cached = get_cached(domain);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), addresses);
    }

    #[test]
    fn test_cache_expiry() {
        let domain = "test-expiry-domain.example.com";
        let addresses = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        
        // 使用很短的 TTL
        put_cached_with_ttl(domain, addresses, Duration::from_millis(1));
        
        // 等待过期
        std::thread::sleep(Duration::from_millis(10));
        
        let cached = get_cached(domain);
        assert!(cached.is_none());
    }

    #[test]
    fn test_cache_empty_addresses() {
        let domain = "test-empty-domain.example.com";
        put_cached(domain, vec![]);
        
        // 空地址不应该被缓存
        let cached = get_cached(domain);
        assert!(cached.is_none());
    }
}
