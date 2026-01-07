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
- ✅ **ChaCha20-Poly1305 加密** (v0.7.0 新增)
- ✅ XOR 加密 (兼容旧客户端)
- ✅ TLS 支持（自动证书生成）
- ✅ TCP Fast Open
- ✅ 守护进程模式
- ✅ **优雅关闭** - 支持 Ctrl+C/SIGTERM (v0.7.0 新增)
- ✅ **DNS 缓存** - LRU 缓存加速解析 (v0.7.0 新增)
- ✅ **流量统计** - 实时连接和流量统计 (v0.7.0 新增)
- ✅ **环境变量配置** - 敏感信息可从环境变量读取 (v0.7.0 新增)

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

## 安装

### Linux 一键安装

使用一键安装脚本可以自动完成架构检测、配置生成和服务部署。安装过程会交互式询问配置项，也可使用默认配置。

```bash
# 下载并安装（自动检测架构）
curl -fsSL https://raw.githubusercontent.com/Jiaocha/CNS/main/scripts/install.sh | bash

# 或使用 wget
wget -qO- https://raw.githubusercontent.com/Jiaocha/CNS/main/scripts/install.sh | bash
```

#### 安装流程说明

1. **架构检测** - 自动识别系统架构（x86_64/aarch64/armv7l）
2. **二进制下载** - 从 GitHub Releases 下载对应版本
3. **交互配置** - 安装过程中会提示输入以下配置项：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| 监听端口 | `2222` | HTTP 隧道监听端口 |
| 代理 Key | `Meng` | 获取目标 Host 的请求头 Key |
| 加密密码 | 留空 | 可选设置 ChaCha20-Poly1305 加密 |
| HTTP DNS | `y` | 是否启用 HTTP DNS 服务 |
| TLS | `n` | 是否启用 TLS 加密 |
| TLS 端口 | `443` | TLS 监听端口（启用 TLS 时） |
| 证书域名 | 留空 | 自动生成证书或自定义域名 |
| 立即启动 | `y` | 安装完成后启动服务并设置开机自启 |

4. **自动完成事项**：
   - 安装二进制文件到 `/usr/local/bin/cns`
   - 创建配置目录 `/etc/cns`
   - 生成配置文件 `/etc/cns/config.json`
   - 创建 systemd 服务 `/etc/systemd/system/cns.service`
   - 可选启动服务并设置开机自启

### Linux 手动安装

```bash
# AMD64
wget https://github.com/Jiaocha/CNS/releases/latest/download/cns-linux-x64 -O /usr/local/bin/cns
chmod +x /usr/local/bin/cns

# ARM64
wget https://github.com/Jiaocha/CNS/releases/latest/download/cns-linux-arm64 -O /usr/local/bin/cns
chmod +x /usr/local/bin/cns

# ARMv7
wget https://github.com/Jiaocha/CNS/releases/latest/download/cns-linux-armv7 -O /usr/local/bin/cns
chmod +x /usr/local/bin/cns
```

### Windows 安装

1. 从 [Releases](https://github.com/Jiaocha/CNS/releases) 下载 `cns-windows-x64.exe`
2. 放置到合适的目录
3. 可选：添加到系统 PATH

### 配置 systemd 服务 (Linux)

```bash
# 创建配置目录
sudo mkdir -p /etc/cns

# 创建配置文件
sudo tee /etc/cns/config.json << 'EOF'
{
    "listen_addr": ["0.0.0.0:2222"],
    "proxy_key": "Host",
    "Enable_httpDNS": true
}
EOF

# 创建 systemd 服务
sudo tee /etc/systemd/system/cns.service << 'EOF'
[Unit]
Description=CuteBi Network Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cns --config /etc/cns/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable cns
sudo systemctl start cns
```

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

### 直接运行

```bash
# 启动服务器
./cns --config config/cns.json

# 守护进程模式
./cns --config config/cns.json --daemon

# 查看帮助
./cns --help
```

### systemd 服务管理 (Linux)

使用 systemd 管理 CNS 服务（推荐生产环境）：

```bash
# 启动服务
sudo systemctl start cns

# 停止服务
sudo systemctl stop cns

# 重启服务
sudo systemctl restart cns

# 查看服务状态
sudo systemctl status cns

# 设置开机自启
sudo systemctl enable cns

# 取消开机自启
sudo systemctl disable cns

# 查看服务日志（实时）
sudo journalctl -u cns -f

# 查看最近 100 条日志
sudo journalctl -u cns -n 100

# 查看日志（从今天开始）
sudo journalctl -u cns --since today

# 重载 systemd 配置（修改服务文件后）
sudo systemctl daemon-reload
```

**服务状态说明**：
- `active (running)` - 服务正在运行
- `inactive (dead)` - 服务已停止
- `failed` - 服务启动失败，请查看日志排查

**查看服务详细信息**：
```bash
# 查看服务配置
sudo systemctl show cns

# 查看服务启动失败原因
sudo systemctl status cns -l
```

**修改配置后重启服务**：
```bash
# 1. 编辑配置文件
sudo nano /etc/cns/config.json

# 2. 重启服务使配置生效
sudo systemctl restart cns

# 3. 验证服务状态
sudo systemctl status cns
```

## 配置文件

参考 `config/cns.json`:

```json
{
    "listen_addr": ["0.0.0.0:2222"],
    "proxy_key": "Host",
    "encrypt_password": "password",
    "encryption_mode": "chacha20",
    "Enable_dns_tcpOverUdp": true,
    "Enable_httpDNS": true,
    "Enable_TFO": false,
    "Tls": {
        "listen_addr": [":9635"],
        "AutoCertHosts": ["example.com"]
    }
}
```

### 配置项说明

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `listen_addr` | 数组 | `[]` | HTTP 隧道监听地址 |
| `proxy_key` | 字符串 | `"Host"` | 获取目标 Host 的请求头 Key |
| `encrypt_password` | 字符串 | `""` | 加密密码（留空则不加密） |
| `encryption_mode` | 字符串 | `"chacha20"` | 加密模式: `chacha20`/`xor`/`none` |
| `Enable_dns_tcpOverUdp` | 布尔 | `false` | 启用 TCP DNS over UDP |
| `Enable_httpDNS` | 布尔 | `false` | 启用 HTTP DNS 服务 |
| `Enable_TFO` | 布尔 | `false` | 启用 TCP Fast Open |
| `Tcp_timeout` | 数字 | `600` | TCP 超时秒数 |
| `Udp_timeout` | 数字 | `30` | UDP 超时秒数 |

### 环境变量配置

敏感信息可通过环境变量配置，避免明文存储：

```bash
# 设置加密密码
export CNS_ENCRYPT_PASSWORD="your-secret-password"

# 设置加密模式 (chacha20/xor/none)
export CNS_ENCRYPTION_MODE="chacha20"

# 启动服务器
./cns --config config/cns.json
```

> **安全提示**: 环境变量配置优先级高于配置文件,推荐在生产环境使用。

### proxy_key（代理 Key）说明

`proxy_key` 用于从 HTTP 请求头中获取目标服务器的 Host 地址。

**工作原理**：
- 客户端连接到 CNS 服务器时，需要在 HTTP 请求头中设置 `proxy_key` 指定的字段
- 服务器读取该字段的值作为目标地址
- 例如：`proxy_key: "Meng"`，客户端请求头需包含 `Meng: target.com:80`

**示例**：
```json
{
    "proxy_key": "Meng"
}
```

客户端请求示例（使用 curl）：
```bash
# 假设 CNS 服务器监听在 2222 端口，proxy_key 为 "Meng"
curl -x http://127.0.0.1:2222 -H "Meng: www.example.com:80" http://www.example.com
```

**注意事项**：
- 默认值为 `"Host"`，此时客户端可以直接访问目标 URL
- 自定义 `proxy_key` 可以混淆流量，提高隐蔽性
- 客户端必须使用相同的 `proxy_key` 才能正常连接

### encrypt_password（加密密码）说明

`encrypt_password` 用于加密代理流量，保护数据传输安全。

**设置方式**：

**方式一：配置文件（不推荐生产环境）**
```json
{
    "encrypt_password": "your-secret-password",
    "encryption_mode": "chacha20"
}
```

**方式二：环境变量（推荐）**
```bash
# Linux/macOS
export CNS_ENCRYPT_PASSWORD="your-secret-password"
export CNS_ENCRYPTION_MODE="chacha20"

# Windows PowerShell
$env:CNS_ENCRYPT_PASSWORD="your-secret-password"
$env:CNS_ENCRYPTION_MODE="chacha20"

# 启动服务
./cns --config config/cns.json
```

**加密模式对比**：

| 模式 | 安全性 | 性能 | 兼容性 | 推荐场景 |
|------|--------|------|--------|----------|
| `chacha20` | ⭐⭐⭐⭐⭐ | 高 | 新客户端 | 生产环境（推荐） |
| `xor` | ⭐ | 极高 | 旧客户端 | 仅用于兼容旧版本 |
| `none` | ⭐⭐⭐⭐⭐ | 极高 | 所有客户端 | 内网/测试环境 |

**完整配置示例**：
```json
{
    "listen_addr": ["0.0.0.0:2222"],
    "proxy_key": "Meng",
    "encrypt_password": "MySecretPassword123",
    "encryption_mode": "chacha20",
    "Enable_httpDNS": true
}
```

**客户端配置**：
客户端需要使用相同的 `encrypt_password` 和 `encryption_mode` 才能解密流量。具体配置方式请参考客户端文档（[mmmdbybyd/CLNC](https://github.com/mmmdbybyd/CLNC)）。

**安全建议**：
1. 生产环境务必设置强密码（至少 16 位，包含大小写字母、数字、特殊字符）
2. 优先使用 `chacha20` 加密模式
3. 不要在配置文件中明文存储密码，使用环境变量
4. 定期更换密码

## 卸载

### Linux

```bash
sudo systemctl stop cns
sudo systemctl disable cns
sudo rm -f /etc/systemd/system/cns.service
sudo rm -f /usr/local/bin/cns
sudo rm -rf /etc/cns
sudo systemctl daemon-reload
```

## 相关项目

- [mmmdbybyd/CNS](https://github.com/mmmdbybyd/CNS) - 原始 Go 版本
- [mmmdbybyd/CLNC](https://github.com/mmmdbybyd/CLNC) - 配套客户端

## 许可证

MIT
