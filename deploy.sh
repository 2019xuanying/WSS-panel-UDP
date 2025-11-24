#!/usr/bin/env bash

# WSS 模块化部署引导脚本
# ----------------------------------------------------------
# 职责：
# 1. 检查依赖 (git)。
# 2. 将整个 Git 仓库克隆到临时目录。
# 3. 运行主要的 install.sh 脚本。
# 4. 清理临时文件。
# ----------------------------------------------------------

set -eu

REPO_URL="https://github.com/2019xuanying/WSS-panel.git"
TEMP_DIR="/tmp/wss_deploy_$(date +%s)"

echo "==== WSS 一键部署引导程序 V2.1 ===="

# 检查 git 是否安装
if ! command -v git >/dev/null; then
    echo "错误: 未检测到 git 命令。请先安装 git (例如: apt install -y git)。"
    exit 1
fi

echo "1. 克隆仓库到临时目录: $TEMP_DIR"
mkdir -p "$TEMP_DIR"
if ! git clone "$REPO_URL" "$TEMP_DIR"; then
    echo "严重错误: 无法克隆 Git 仓库。请检查网络连接和权限。"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# 检查主要安装脚本是否存在
if [ ! -f "$TEMP_DIR/install.sh" ]; then
    echo "严重错误: 仓库中缺少 install.sh 文件。"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "2. 启动模块化安装..."
chmod +x "$TEMP_DIR/install.sh"
# 执行安装脚本
"$TEMP_DIR/install.sh"

INSTALL_STATUS=$?

echo "3. 清理临时文件..."
rm -rf "$TEMP_DIR"

if [ $INSTALL_STATUS -eq 0 ]; then
    echo "🎉 部署脚本执行成功！"
else
    echo "❌ 部署脚本执行失败 (退出码 $INSTALL_STATUS)。"
fi

exit $INSTALL_STATUS
