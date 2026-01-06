//! CuteBi Network Server - 主程序入口

use clap::Parser;
use cns::config::Config;
use cns::http_tunnel::start_http_tunnel;
use cns::platform::init_platform;
use cns::tls::{make_tls_config, start_tls_server};
use log::{error, info, warn};
use std::fs;
use std::process;
use std::sync::Arc;
use tokio::sync::broadcast;

/// CuteBi Network Server
#[derive(Parser, Debug)]
#[command(name = "cns")]
#[command(author = "CuteBi <supercutename@gmail.com>")]
#[command(version = "0.6.0")]
#[command(about = "CuteBi Network Server - A high-performance network proxy server", long_about = None)]
struct Args {
    /// JSON 配置文件路径
    #[arg(short, long, alias = "json")]
    config: String,

    /// 守护进程模式
    #[arg(short, long, default_value_t = false)]
    daemon: bool,
}

/// 将 PID 保存到文件
fn save_pid_to_file(pid_path: &str) {
    let pid = process::id();
    if let Err(e) = fs::write(pid_path, pid.to_string()) {
        error!("Failed to write PID file: {}", e);
    }
}

/// 删除 PID 文件
fn remove_pid_file(pid_path: &str) {
    if let Err(e) = fs::remove_file(pid_path) {
        warn!("Failed to remove PID file: {}", e);
    }
}

/// 启动守护进程
#[cfg(unix)]
fn start_daemon() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let args: Vec<String> = std::env::args().collect();
    let mut new_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // 移除 --daemon 参数
    new_args.retain(|&arg| arg != "--daemon" && arg != "-d");

    unsafe {
        Command::new(&args[0])
            .args(&new_args[1..])
            .pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()
            .expect("Failed to start daemon");
    }

    process::exit(0);
}

#[cfg(windows)]
fn start_daemon() {
    use std::process::Command;

    let args: Vec<String> = std::env::args().collect();
    let mut new_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // 移除 --daemon 参数
    new_args.retain(|&arg| arg != "--daemon" && arg != "-d");

    Command::new(&args[0])
        .args(&new_args[1..])
        .spawn()
        .expect("Failed to start daemon");

    process::exit(0);
}

/// 等待关闭信号
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        
        let mut sigterm = signal(SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");
        
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT (Ctrl+C), shutting down...");
            }
        }
    }
    
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to register Ctrl+C handler");
        info!("Received Ctrl+C, shutting down...");
    }
}

#[tokio::main]
async fn main() {
    // 初始化日志
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(Some(env_logger::TimestampPrecision::Seconds))
        .init();

    // 解析命令行参数
    let args = Args::parse();

    // 守护进程模式
    if args.daemon {
        start_daemon();
    }

    // 初始化平台特定设置
    init_platform();

    // 加载配置
    let config = match Config::load_from_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config: {}", e);
            process::exit(1);
        }
    };

    // 验证配置
    if let Err(e) = config.validate() {
        error!("Config validation failed: {}", e);
        process::exit(1);
    }

    info!("　/) /)");
    info!("ฅ(՞•ﻌ•՞)ฅ");
    info!("CuteBi Network Server 0.6.0 (Rust)");
    info!("Author: CuteBi(Mmmdbybyd)");
    info!("E-mail: supercutename@gmail.com");
    info!("");

    // 显示加密模式
    if config.encryption_enabled() {
        info!("Encryption mode: {:?}", config.encryption_mode);
    } else {
        info!("Encryption: disabled");
    }

    // 检查 TFO
    #[cfg(unix)]
    if config.enable_tfo {
        if unsafe { libc::geteuid() } != 0 {
            warn!("TFO cannot be opened: CNS effective UID isn't 0(root).");
        }
    }

    // 保存 PID
    let pid_path = config.pid_path.clone();
    if let Some(ref path) = pid_path {
        save_pid_to_file(path);
    }

    let config = Arc::new(config);
    let password = Arc::new(config.encrypt_password.as_bytes().to_vec());

    // 创建关闭信号广播通道
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    let mut handles = Vec::new();

    // 启动 TLS 服务器
    if !config.tls.listen_addr.is_empty() {
        match make_tls_config(&config.tls) {
            Ok(tls_config) => {
                for addr in &config.tls.listen_addr {
                    let addr = addr.clone();
                    let tls_config = tls_config.clone();
                    let config = config.clone();
                    let password = password.clone();
                    let mut shutdown_rx = shutdown_tx.subscribe();

                    handles.push(tokio::spawn(async move {
                        tokio::select! {
                            _ = start_tls_server(&addr, tls_config, config, password) => {}
                            _ = shutdown_rx.recv() => {
                                info!("TLS server {} shutting down", addr);
                            }
                        }
                    }));
                }
            }
            Err(e) => {
                error!("Failed to create TLS config: {}", e);
            }
        }
    }

    // 启动 HTTP 隧道服务器
    for addr in &config.listen_addr {
        let addr = addr.clone();
        let config = config.clone();
        let password = password.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        handles.push(tokio::spawn(async move {
            tokio::select! {
                _ = start_http_tunnel(&addr, config, password) => {}
                _ = shutdown_rx.recv() => {
                    info!("HTTP tunnel server {} shutting down", addr);
                }
            }
        }));
    }

    if handles.is_empty() {
        error!("No listen address configured!");
        process::exit(1);
    }

    info!("Server started, press Ctrl+C to stop");

    // 等待关闭信号
    wait_for_shutdown_signal().await;

    // 发送关闭信号给所有服务器
    info!("Sending shutdown signal to all servers...");
    let _ = shutdown_tx.send(());

    // 给服务器一些时间来清理
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // 等待所有服务器关闭 (带超时)
    let shutdown_timeout = tokio::time::Duration::from_secs(5);
    for handle in handles {
        let _ = tokio::time::timeout(shutdown_timeout, handle).await;
    }

    // 清理 PID 文件
    if let Some(ref path) = pid_path {
        remove_pid_file(path);
    }

    info!("Server stopped gracefully");
}

