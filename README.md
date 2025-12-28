# CuteBi Network Server (Rust)

[![Build Multi-Platform](https://github.com/Jiaocha/CNS/actions/workflows/build.yml/badge.svg)](https://github.com/Jiaocha/CNS/actions/workflows/build.yml)
[![GitHub Release](https://img.shields.io/github/v/release/Jiaocha/CNS)](https://github.com/Jiaocha/CNS/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

高性能网络代理服务器，支持 HTTP 隧道、HTTP DNS、TCP/UDP 转发、TLS 加密等功能。

> 这是原 [mmmdbybyd/CNS](https://github.com/mmmdbybyd/CNS) Go 版本的 Rust 重写版本。

## 功能特性

- ✅ HTTP CONNECT 隧道代理
- ✅ HTTP DNS 服务（类似 114DNS/DNSPod）
- ✅ TCP/UDP 流量转发（IPv4/IPv6）
- ✅ XOR 加密
- ✅ TLS 支持（自动证书生成）
- ✅ TCP Fast Open
- ✅ 守护进程模式

## 下载

从 [Releases](https://github.com/Jiaocha/CNS/releases) 页面下载预编译版本。

## 支持平台

| 平台 | 架构 | 文件名 |
|------|------|--------|
| Windows | x64 | `cns-windows-x64.exe` |
| Linux | x64 (AMD64) | `cns-linux-x64` |
| Linux | ARM64 | `cns-linux-arm64` |
| Linux | ARMv7 | `cns-linux-armv7` |
| macOS | Intel x64 | `cns-macos-x64` |
| macOS | Apple Silicon | `cns-macos-arm64` |

## 编译

### 本地编译

```bash
git clone https://github.com/Jiaocha/CNS.git
cd CNS
cargo build --release
```

### 交叉编译（Linux ARM/多平台）

需要安装 [cross](https://github.com/cross-rs/cross) 工具：

```bash
# 安装 cross
cargo install cross --git https://github.com/cross-rs/cross

# 构建 Linux ARM64
cross build --release --target aarch64-unknown-linux-gnu

# 构建 Linux ARMv7
cross build --release --target armv7-unknown-linux-gnueabihf

# 使用构建脚本一键构建所有平台
./scripts/build-multi-platform.sh
```

## 使用方法

```bash
# 启动服务器
./cns --config config/cns.json

# 守护进程模式
./cns --config config/cns.json --daemon

# 查看帮助
./cns --help
```

## 配置文件

参考 `config/cns.json`:

```json
{
    "listen_addr": ["0.0.0.0:2222"],
    "proxy_key": "Host",
    "encrypt_password": "password",
    "Enable_dns_tcpOverUdp": true,
    "Enable_httpDNS": true,
    "Enable_TFO": false,
    "Tls": {
        "listen_addr": [":9635"],
        "AutoCertHosts": ["example.com"]
    }
}
```

## CI/CD

项目使用 GitHub Actions 自动构建多平台版本。推送 tag 时自动创建 Release。

```bash
git tag v0.4.2
git push --tags
```

## 相关项目

- [mmmdbybyd/CNS](https://github.com/mmmdbybyd/CNS) - 原始 Go 版本
- [mmmdbybyd/CLNC](https://github.com/mmmdbybyd/CLNC) - 配套客户端

## 许可证

MIT
