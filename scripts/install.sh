#!/bin/bash
# CNS 一键安装脚本
# https://github.com/Jiaocha/CNS

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# 创建默认配置（如果不存在）
if [ ! -f /etc/cns/config.json ]; then
    sudo tee /etc/cns/config.json > /dev/null << 'EOF'
{
    "listen_addr": ["0.0.0.0:2222"],
    "proxy_key": "Host",
    "Enable_httpDNS": true,
    "Enable_dns_tcpOverUdp": true
}
EOF
    echo -e "${GREEN}已创建默认配置: /etc/cns/config.json${NC}"
fi

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

echo ""
echo -e "${GREEN}✓ 安装完成!${NC}"
echo ""
echo "使用方法:"
echo "  sudo systemctl start cns     # 启动服务"
echo "  sudo systemctl stop cns      # 停止服务"
echo "  sudo systemctl enable cns    # 开机自启"
echo "  sudo systemctl status cns    # 查看状态"
echo ""
echo "配置文件: /etc/cns/config.json"
echo ""

# 版本信息
echo -e "${YELLOW}已安装版本:${NC}"
/usr/local/bin/cns --help 2>&1 | head -5 || echo -e "${GREEN}CNS 已安装成功${NC}"
