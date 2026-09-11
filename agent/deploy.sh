#!/bin/bash
# WardenNet Agent 一键部署脚本
# 使用方式：sudo bash deploy.sh [config_path]

set -e

INSTALL_DIR="/opt/wardennet"
SERVICE_NAME="wardennet-agent"
BINARY_NAME="wardennet"
CONFIG_PATH="${1:-/etc/wardennet/config.yaml}"

echo "=== WardenNet Agent 部署 ==="

# 1. 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "错误：此脚本需要 root 权限运行"
    exit 1
fi

# 2. 检查 ipset 和 iptables
echo "[1/5] 检查系统依赖..."
if ! command -v ipset &> /dev/null; then
    echo "警告：ipset 未安装，Agent 可能无法正常工作"
    echo "  安装: apt-get install ipset  (Debian/Ubuntu)"
    echo "  安装: yum install ipset    (CentOS/RHEL)"
fi
if ! command -v iptables &> /dev/null; then
    echo "警告：iptables 未安装"
fi

# 3. 创建目录
echo "[2/5] 创建目录..."
mkdir -p "$INSTALL_DIR"
mkdir -p /etc/wardennet
mkdir -p /var/lib/wardennet
mkdir -p /var/log/wardennet
mkdir -p /var/run

# 4. 复制二进制和配置
echo "[3/5] 安装 Agent..."
if [ -f "./wardennet_linux" ]; then
    cp ./wardennet_linux "$INSTALL_DIR/$BINARY_NAME"
elif [ -f "./wardennet" ]; then
    cp ./wardennet "$INSTALL_DIR/$BINARY_NAME"
else
    echo "错误：找不到 wardennet 二进制文件"
    echo "  请先编译: GOOS=linux GOARCH=amd64 go build -o wardennet ./cmd/wardennet"
    exit 1
fi
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# 创建系统软链接，让 wardennet CLI 全局可用
ln -sf "$INSTALL_DIR/$BINARY_NAME" "/usr/local/bin/$BINARY_NAME"

# 复制配置文件
if [ -f "./config.yaml" ]; then
    cp ./config.yaml "$CONFIG_PATH"
elif [ -f "./wardennet.production.yaml" ]; then
    cp ./wardennet.production.yaml "$CONFIG_PATH"
elif [ ! -f "$CONFIG_PATH" ]; then
    echo "警告：找不到配置文件，请手动创建 $CONFIG_PATH"
fi

# 5. 安装 systemd service
echo "[4/5] 配置 systemd 服务..."
if [ -f "./wardennet-agent.service" ]; then
    cp ./wardennet-agent.service "/etc/systemd/system/$SERVICE_NAME.service"
else
    # 动态生成 service 文件
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=WardenNet Agent - 本地恶意扫描防护
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$INSTALL_DIR/$BINARY_NAME --config $CONFIG_PATH
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# 6. 启动服务
echo "[5/5] 启动 Agent..."
systemctl start "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "✅ WardenNet Agent 部署成功！"
    echo "   状态: active (running)"
    echo "   日志: tail -f /var/log/wardennet/agent.log"
    echo "   管理: systemctl status $SERVICE_NAME"
    echo ""
    echo "   CLI 命令（全局可用，无需 socat）："
    echo "     wardennet status                   查看状态"
    echo "     wardennet blocklist status         黑名单统计"
    echo "     wardennet blocklist add <ip> -f    强制拉黑"
    echo "     wardennet blocklist del <ip>        解封"
    echo "     wardennet reload                   热重载配置"
    echo ""
    echo "   （可选：也可用 socat，见运维手册 §6.1）"
else
    echo "❌ Agent 启动失败，请查看日志:"
    echo "   journalctl -u $SERVICE_NAME -n 50"
fi

echo ""
echo "=== 部署完成 ==="
