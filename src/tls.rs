//! TLS 模块 - 处理 TLS 连接和证书生成

use crate::config::{Config, TlsConfig};
use crate::http_tunnel::handle_tls_tunnel;
use log::{error, info};
use rcgen::{CertificateParams, Certificate, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// 生成自签名证书
fn generate_self_signed_cert(
    hosts: &[String],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    // 生成密钥对
    let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
    
    // 创建证书参数
    let mut params = CertificateParams::default();

    // 设置主题备用名称
    for host in hosts {
        if !host.is_empty() {
            params.subject_alt_names.push(rcgen::SanType::DnsName(host.clone()));
        }
    }

    // 设置密钥对
    params.key_pair = Some(key_pair);

    // 生成证书
    let cert = Certificate::from_params(params)?;

    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivateKeyDer::try_from(cert.serialize_private_key_der())
        .map_err(|e| format!("Key error: {:?}", e))?;

    Ok((vec![cert_der], key_der))
}

/// 从文件加载证书
fn load_certs_from_file(
    cert_file: &str,
    key_file: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    // 加载证书
    let cert_data = fs::read(cert_file)?;
    let mut cert_reader = BufReader::new(cert_data.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err("No certificates found in file".into());
    }

    // 加载私钥
    let key_data = fs::read(key_file)?;
    let mut key_reader = BufReader::new(key_data.as_slice());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or("No private key found in file")?;

    Ok((certs, key))
}

/// 创建 TLS 配置
pub fn make_tls_config(tls_config: &TlsConfig) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let (certs, key) = if let (Some(cert_file), Some(key_file)) =
        (&tls_config.cert_file, &tls_config.key_file)
    {
        // 从文件加载
        load_certs_from_file(cert_file, key_file)?
    } else {
        // 自动生成
        let hosts = if tls_config.auto_cert_hosts.is_empty() {
            vec![String::new()]
        } else {
            tls_config.auto_cert_hosts.clone()
        };
        generate_self_signed_cert(&hosts)?
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// 启动 TLS 服务器
pub async fn start_tls_server(
    addr: &str,
    tls_config: Arc<ServerConfig>,
    config: Arc<Config>,
    password: Arc<Vec<u8>>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind TLS {}: {}", addr, e);
            return;
        }
    };

    let acceptor = TlsAcceptor::from(tls_config);

    info!("TLS server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New TLS connection from {}", peer_addr);

                // 设置 keep-alive
                if let Err(e) = stream.set_nodelay(true) {
                    error!("Set nodelay failed: {}", e);
                }

                let acceptor = acceptor.clone();
                let config = config.clone();
                let password = password.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            handle_tls_tunnel(tls_stream, config, password).await;
                        }
                        Err(e) => {
                            error!("TLS handshake error: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("TLS accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    }
}
