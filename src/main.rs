//! CuteBi Network Server - 主程序入口

use clap::Parser;
use cns::config::Config;
use cns::http_tunnel::start_http_tunnel;
use cns::platform::init_platform;
use cns::tls::{make_tls_config, start_tls_server};
use log::{error, info};
use std::fs;
use std::process;
use std::sync::Arc;

/// CuteBi Network Server
#[derive(Parser, Debug)]
#[command(name = "cns")]
#[command(author = "CuteBi <supercutename@gmail.com>")]
#[command(version = "0.5.5")]
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

    info!("　/) /)");
    info!("ฅ(՞•ﻌ•՞)ฅ");
    info!("CuteBi Network Server 0.5.5 (Rust)");
    info!("Author: CuteBi(Mmmdbybyd)");
    info!("E-mail: supercutename@gmail.com");
    info!("");

    // 检查 TFO
    #[cfg(unix)]
    if config.enable_tfo {
        if unsafe { libc::geteuid() } != 0 {
            log::warn!("TFO cannot be opened: CNS effective UID isn't 0(root).");
        }
    }

    // 保存 PID
    if let Some(ref pid_path) = config.pid_path {
        save_pid_to_file(pid_path);
    }

    let config = Arc::new(config);
    info!("Loaded password: {:?}", config.encrypt_password.as_bytes());
    let password = Arc::new(config.encrypt_password.as_bytes().to_vec());

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

                    handles.push(tokio::spawn(async move {
                        start_tls_server(&addr, tls_config, config, password).await;
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

        handles.push(tokio::spawn(async move {
            start_http_tunnel(&addr, config, password).await;
        }));
    }

    if handles.is_empty() {
        error!("No listen address configured!");
        process::exit(1);
    }

    // 等待所有服务器
    for handle in handles {
        let _ = handle.await;
    }
}
