#!/bin/bash
# CNS Multi-Platform Build Script
# 使用 cross 工具进行交叉编译

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}CNS Multi-Platform Build Script${NC}"
echo "=================================="

# 检查 cross 是否安装
if ! command -v cross &> /dev/null; then
    echo -e "${YELLOW}Installing cross...${NC}"
    cargo install cross --git https://github.com/cross-rs/cross
fi

# 构建目标列表
TARGETS=(
    "x86_64-unknown-linux-gnu"      # Linux AMD64
    "aarch64-unknown-linux-gnu"     # Linux ARM64
    "armv7-unknown-linux-gnueabihf" # Linux ARMv7
    "x86_64-unknown-linux-musl"     # Linux AMD64 (静态链接)
    "aarch64-unknown-linux-musl"    # Linux ARM64 (静态链接)
)

# 创建输出目录
OUTPUT_DIR="release"
mkdir -p "$OUTPUT_DIR"

# 构建每个目标
for target in "${TARGETS[@]}"; do
    echo -e "\n${YELLOW}Building for $target...${NC}"
    
    if cross build --release --target "$target"; then
        # 复制构建结果
        cp "target/$target/release/cns" "$OUTPUT_DIR/cns-$target"
        echo -e "${GREEN}✓ Built: cns-$target${NC}"
    else
        echo -e "${RED}✗ Failed: $target${NC}"
    fi
done

echo -e "\n${GREEN}Build complete!${NC}"
echo "Output files in: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
