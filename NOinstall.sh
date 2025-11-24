#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板 一键卸载脚本 (V2.2 - Native UDP Support)
# ==========================================================

echo "----------------------------------"
echo "==== WSS 基础设施一键卸载程序 ===="
echo "----------------------------------"

# =============================
# 文件路径定义
# =============================
PANEL_DIR="/etc/wss-panel"
WSS_LOG_FILE="/var/log/wss.log"
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_PATH="$PANEL_DIR/$PANEL_BACKEND_FILE"
CONFIG_PATH="$PANEL_DIR/config.json"
PANEL_APP_JS_PATH="$PANEL_DIR/app.js"
DB_PATH="$PANEL_DIR/wss_panel.db"

# 服务路径
UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service"
UDP_SERVER_SERVICE_PATH="/etc/systemd/system/udp_server.service" # 旧的 Node.js 服务
UDP_STANDALONE_SERVICE_PATH="/etc/systemd/system/udp_standalone.service" # [NEW] Native UDP
UDP_STANDALONE_SCRIPT="/usr/local/bin/udp_server_standalone.js"          # [NEW] Script

WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
STUNNEL_CONF="/etc/stunnel/ssh-tls.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"
IPTABLES_RULES="/etc/iptables/rules.v4"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"
SUDOERS_FILE="/etc/sudoers.d/99-wss-panel"
SHELL_GROUP="shell_users"
BLOCK_CHAIN="WSS_IP_BLOCK"
BADVPN_SRC_DIR="/root/badvpn"

# =============================
# 1. 检测 Panel 用户 (用于清理)
# =============================
PANEL_USER=""
if [ -f "$PANEL_SERVICE_PATH" ]; then
    PANEL_USER=$(grep -E "^User=" "$PANEL_SERVICE_PATH" | cut -d'=' -f2)
    echo "检测到 Panel 服务用户: $PANEL_USER"
else
    echo "将尝试使用默认值 'admin'..."
    PANEL_USER="admin"
fi

# =============================
# 2. 停止并禁用 Systemd 服务
# =============================
echo "2. 停止并禁用 Systemd 服务..."
systemctl stop wss_panel || true
systemctl disable wss_panel || true
systemctl stop wss || true
systemctl disable wss || true
systemctl stop udpgw || true # BadVPN
systemctl disable udpgw || true
systemctl stop udp_server || true # 旧的 Node.js UDP
systemctl disable udp_server || true
systemctl stop udp_standalone || true # [NEW] Native UDP
systemctl disable udp_standalone || true
systemctl stop stunnel4 || true
systemctl disable stunnel4 || true
systemctl stop sshd_stunnel || true
systemctl disable sshd_stunnel || true

systemctl daemon-reload

# 移除服务文件
rm -f "$PANEL_SERVICE_PATH"
rm -f "$WSS_SERVICE_PATH"
rm -f "$UDPGW_SERVICE_PATH"
rm -f "$UDP_SERVER_SERVICE_PATH"
rm -f "$UDP_STANDALONE_SERVICE_PATH" # [NEW]
rm -f "$SSHD_STUNNEL_SERVICE"
echo "Systemd 服务已停止并移除。"
echo "----------------------------------"

# =============================
# 3. 清理 IPTABLES 规则
# =============================
echo "3. 清理 IPTABLES 规则链 ($BLOCK_CHAIN)..."
while iptables -D INPUT -j "$BLOCK_CHAIN" 2>/dev/null; do
    echo "移除 $BLOCK_CHAIN 钩子..."
done
iptables -t filter -F "$BLOCK_CHAIN" 2>/dev/null || true
iptables -t filter -X "$BLOCK_CHAIN" 2>/dev/null || true

if [ -f "$IPTABLES_RULES" ]; then
    echo "警告：IPTABLES 规则持久化文件存在，建议手动检查。"
    /sbin/iptables-save | grep -v "$BLOCK_CHAIN" | /sbin/iptables-restore || true
fi

if command -v netfilter-persistent >/dev/null; then
    systemctl restart netfilter-persistent || true
fi
echo "IPTABLES 规则清理完成。"
echo "----------------------------------"

# =============================
# 4. 还原 SSHD 配置
# =============================
echo "4. 还原 SSHD 配置..."
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")
systemctl restart "$SSHD_SERVICE" || true
echo "SSHD 配置已还原。"
echo "----------------------------------"

# =============================
# 5. 还原 Sysctl
# =============================
echo "5. 还原 Sysctl 网络调优配置..."
sed -i '/# WSS_NET_START/,/# WSS_NET_END/d' /etc/sysctl.conf
sysctl -p > /dev/null
echo "Sysctl 配置已还原。"
echo "----------------------------------"

# =============================
# 6. 清理 Sudoers、用户和组
# =============================
echo "6. 清理 Sudoers、用户和组..."
rm -f "$SUDOERS_FILE"
if getent group "$SHELL_GROUP" >/dev/null; then
    groupdel "$SHELL_GROUP" || true
fi
if id -u "$PANEL_USER" >/dev/null 2>&1; then
    userdel "$PANEL_USER" || true
fi
echo "用户与权限清理完成。"
echo "----------------------------------"

# =============================
# 7. 删除文件和目录
# =============================
echo "7. 删除 WSS 相关的文件和目录..."
rm -f "$WSS_PROXY_PATH"
rm -f "$UDP_STANDALONE_SCRIPT" # [NEW] 删除脚本
rm -f "$PANEL_BACKEND_PATH"
rm -f "$PANEL_APP_JS_PATH"
rm -f "$CONFIG_PATH"
rm -f "$WSS_LOG_FILE"
rm -f "$STUNNEL_CONF"
rm -f "$SECRET_KEY_FILE"
rm -f "$ROOT_HASH_FILE"
rm -f "$SSHD_STUNNEL_CONFIG"
rm -f "$DB_PATH"

# 删除目录及其内容
rm -rf "$PANEL_DIR"
rm -rf "$BADVPN_SRC_DIR" # 清理 BadVPN 源码和构建文件
rm -rf /etc/stunnel/certs
rm -rf /var/log/stunnel4

echo "文件和目录清理完成。"
echo "----------------------------------"

echo "=================================================="
echo "✅ WSS 隧道管理面板 (V2.2) 已成功卸载！"
echo "=================================================="
