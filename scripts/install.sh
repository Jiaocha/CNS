#!/bin/bash
# CNS 一键安装脚本
# https://github.com/Jiaocha/CNS

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  /) /)"
echo "ฅ(՞•ﻌ•՞)ฅ"
echo "CuteBi Network Server 安装脚本"
echo -e "${NC}"
echo "================================"

# 检测架构
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        BINARY="cns-linux-x64-musl"
        ;;
    aarch64)
        BINARY="cns-linux-arm64-musl"
        ;;
    armv7l|armhf)
        BINARY="cns-linux-armv7"
        ;;
    *)
        echo -e "${RED}不支持的架构: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}检测到架构: $ARCH${NC}"
echo -e "${YELLOW}正在下载: $BINARY${NC}"

# 获取最新版本
LATEST_URL="https://github.com/Jiaocha/CNS/releases/latest/download/$BINARY"

# 下载
if command -v curl &> /dev/null; then
    curl -fsSL "$LATEST_URL" -o /tmp/cns
elif command -v wget &> /dev/null; then
    wget -q "$LATEST_URL" -O /tmp/cns
else
    echo -e "${RED}错误: 需要安装 curl 或 wget${NC}"
    exit 1
fi

# 安装
sudo mv /tmp/cns /usr/local/bin/cns
sudo chmod +x /usr/local/bin/cns

# 创建配置目录
sudo mkdir -p /etc/cns

echo ""
echo -e "${CYAN}========== 服务器配置 ==========${NC}"
echo ""

# 从 /dev/tty 读取用户输入（绕过管道）
prompt_input() {
    local prompt="$1"
    local default="$2"
    local result
    
    echo -n "$prompt" > /dev/tty
    read result < /dev/tty || result="$default"
    
    if [ -z "$result" ]; then
        result="$default"
    fi
    echo "$result"
}

# 获取监听端口
LISTEN_PORT=$(prompt_input "请输入监听端口 [默认: 2222]: " "2222")

# 获取代理 Key
PROXY_KEY=$(prompt_input "请输入代理 Key [默认: Host]: " "Host")

# 获取加密密码
ENCRYPT_PASSWORD=$(prompt_input "请输入加密密码 [留空则不加密]: " "")

# HTTP DNS
ENABLE_DNS=$(prompt_input "是否启用 HTTP DNS? (y/n) [默认: y]: " "y")
if [ "$ENABLE_DNS" = "y" ] || [ "$ENABLE_DNS" = "Y" ]; then
    ENABLE_HTTP_DNS="true"
else
    ENABLE_HTTP_DNS="false"
fi

# TLS 配置
ENABLE_TLS=$(prompt_input "是否启用 TLS? (y/n) [默认: n]: " "n")

TLS_CONFIG=""
if [ "$ENABLE_TLS" = "y" ] || [ "$ENABLE_TLS" = "Y" ]; then
    TLS_PORT=$(prompt_input "请输入 TLS 监听端口 [默认: 443]: " "443")
    TLS_HOSTS=$(prompt_input "请输入证书域名 (用逗号分隔，留空自动生成): " "")
    
    if [ -n "$TLS_HOSTS" ]; then
        # 转换为 JSON 数组格式
        TLS_HOSTS_JSON=$(echo "$TLS_HOSTS" | sed 's/,/","/g')
        TLS_CONFIG=",
    \"Tls\": {
        \"listen_addr\": [\"0.0.0.0:$TLS_PORT\"],
        \"AutoCertHosts\": [\"$TLS_HOSTS_JSON\"]
    }"
    else
        TLS_CONFIG=",
    \"Tls\": {
        \"listen_addr\": [\"0.0.0.0:$TLS_PORT\"]
    }"
    fi
fi

# 生成配置文件
echo ""
echo -e "${YELLOW}正在生成配置文件...${NC}"

if [ -n "$ENCRYPT_PASSWORD" ]; then
    ENCRYPT_LINE="\"encrypt_password\": \"$ENCRYPT_PASSWORD\","
else
    ENCRYPT_LINE=""
fi

sudo tee /etc/cns/config.json > /dev/null << EOF
{
    "listen_addr": ["0.0.0.0:$LISTEN_PORT"],
    "proxy_key": "$PROXY_KEY",
    $ENCRYPT_LINE
    "Enable_httpDNS": $ENABLE_HTTP_DNS,
    "Enable_dns_tcpOverUdp": true$TLS_CONFIG
}
EOF

echo -e "${GREEN}配置文件已保存: /etc/cns/config.json${NC}"

# 显示配置
echo ""
echo -e "${CYAN}========== 配置信息 ==========${NC}"
echo -e "监听地址: ${GREEN}0.0.0.0:$LISTEN_PORT${NC}"
echo -e "代理 Key: ${GREEN}$PROXY_KEY${NC}"
if [ -n "$ENCRYPT_PASSWORD" ]; then
    echo -e "加密密码: ${GREEN}$ENCRYPT_PASSWORD${NC}"
else
    echo -e "加密密码: ${YELLOW}未设置${NC}"
fi
echo -e "HTTP DNS: ${GREEN}$ENABLE_HTTP_DNS${NC}"
if [ "$ENABLE_TLS" = "y" ] || [ "$ENABLE_TLS" = "Y" ]; then
    echo -e "TLS 端口: ${GREEN}$TLS_PORT${NC}"
fi
echo ""

# 创建 systemd 服务
sudo tee /etc/systemd/system/cns.service > /dev/null << 'EOF'
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

# 重载 systemd
sudo systemctl daemon-reload

# 询问是否启动服务
START_NOW=$(prompt_input "是否立即启动服务? (y/n) [默认: y]: " "y")

if [ "$START_NOW" = "y" ] || [ "$START_NOW" = "Y" ]; then
    sudo systemctl start cns
    sudo systemctl enable cns
    echo ""
    echo -e "${GREEN}✓ 服务已启动并设置开机自启!${NC}"
else
    echo ""
    echo -e "${YELLOW}服务未启动。${NC}"
fi

echo ""
echo -e "${GREEN}✓ 安装完成!${NC}"
echo ""
echo "使用方法:"
echo "  sudo systemctl start cns     # 启动服务"
echo "  sudo systemctl stop cns      # 停止服务"
echo "  sudo systemctl restart cns   # 重启服务"
echo "  sudo systemctl status cns    # 查看状态"
echo ""
echo "配置文件: /etc/cns/config.json"
echo "修改配置后请运行: sudo systemctl restart cns"
echo ""
