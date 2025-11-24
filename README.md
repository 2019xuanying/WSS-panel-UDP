WSS (WebSocket Secure) SSH 隧道管理面板 (Axiom V4.1 架构)

本项目是一个高性能、安全加固的 WSS (WebSocket Secure) SSH 隧道管理系统，基于 Node.js 构建。

它旨在通过标准的 WebSocket 协议（运行于 80/443 等自定义端口）转发 SSH 流量，同时提供一个功能完善的 Web UI 来管理用户、流量、速率和安全策略。

V4.1 架构的核心设计理念是实时推送、最小权限和完全解耦：

**控制平面（Control Plane）与数据平面（Data Plane）**完全分离。

实时数据流 (Axiom V3.0+): 系统采用“推送”模型。数据平面 (Proxy) 主动 通过 WebSocket (/ipc) 每秒向控制平面 (Panel) 推送实时统计数据，控制平面再将其广播到所有管理员 UI (/ws/ui)，实现零延迟的仪表盘。

面板权限最小化: Web服务（控制平面）不再以 root 权限运行，而是作为一个受限的系统用户（例如 admin）运行，通过 sudoers 执行特定授权命令。

WSS 隧道与 Stunnel Shell 访问完全分离。

核心架构 (Axiom V4.1)

系统由两个独立的 Node.js 进程（控制平面和数据平面）、两个独立的 SSHD 服务和一个 sudoers 策略组成：

1. 控制平面 (Control Plane)

服务: wss_panel.service

脚本: wss_panel.js (V8.3.2+)

运行用户: admin (或您在安装时自定义的 $panel_user)

职责:

Web UI: 提供基于 Express 的 Web 管理面板 (UI)，监听自定义端口 (例如 54321)。

安全: 实现登录页速率限制（防爆破）和基于 bcrypt 的密码存储。

数据库: 管理一个 SQLite 数据库 (wss_panel.db)，存储所有用户信息、配额、速率限制等。

认证中心: 提供一个内部认证 API (/internal/auth)，供数据平面调用以验证用户连接。

实时聚合 (Axiom V3.0+):

启动一个 WebSocket 服务器 (/ipc)，监听来自所有数据平面 Worker 的主动推送。

聚合所有 Worker 的实时数据（速度、连接数、流量增量）。

将流量增量异步写入 SQLite 数据库。

实时广播 (Axiom V3.0+):

启动一个 WebSocket 服务器 (/ws/ui)，向所有已登录的管理员前端广播聚合后的实时统计数据，实现“心电图”和秒级刷新。

决策中心 (Axiom V3.0+):

实时熔断: 根据聚合的速度数据，立即决策是否触发全局熔断 (globalFuseLimitKbps)。

维护任务: 运行一个 60 秒的后台任务 (syncUserStatus)，检查非实时状态（如到期、超额）。

系统控制 (Axiom V4.0+):

通过 sudo 执行 sudoers 文件中明确授权的命令 (例如 usermod, pkill, sed, systemctl daemon-reload) 来管理系统状态。

2. 数据平面 (Data Plane)

服务: wss.service

脚本: wss_proxy.js (V8.3.0+)

运行用户: root (必须，因为它需要绑定 80/443 等特权端口并运行在多核上)

职责:

多核集群: 以 cluster 模式启动，为每个 CPU 核心创建一个 Worker 进程以实现最大吞吐量。

监听端口: 监听公共端口 (例如 80 和 443)。

Payload Eater: 智能处理“哑”HTTP请求和“升级”请求的TCP流水线。

Host 检查: 检查 Host 头是否在 hosts.json 白名单中。

认证卸载: 回调 控制平面的 /internal/auth API 来验证用户凭据，自身不执行任何昂贵的 bcrypt 或数据库操作。

策略执行: 根据从控制平面获取的限制，对每个用户实施速率限制（令牌桶算法）和并发连接数限制。

流量转发: 将所有合法流量转发到主 SSHD 服务 (例如 127.0.0.1:22)。

实时推送 (Axiom V3.0+):

作为 WebSocket 客户端，主动连接到控制平面的 /ipc 端口。

每 1 秒计算一次本地的速度和流量增量，并将其推送到控制平面。

3. Stunnel (Shell) 平面

服务: stunnel4.service 和 sshd_stunnel.service

职责:

stunnel4 监听自定义端口 (例如 444)，负责 SSL 卸载。

stunnel4 将解密的流量转发到独立的 Stunnel SSHD 服务 (例如 127.0.0.1:2222)。

sshd_stunnel.service 是一个专用的 SSHD 实例，其配置 (sshd_config_stunnel) 中包含 AllowGroups shell_users 指令。

安全: 只有在面板中被授予 "Allow Shell" 权限（即被添加到 shell_users 组）的用户才能通过此端口登录。

详细逻辑实现 (Axiom V3.0+ 实时架构)

场景 1: 实时数据流 (1秒刷新)

[数据平面] wss_proxy.js (Worker 3) 的 statsPusherIntervalId (1秒) 触发。

[数据平面] pushStatsToControlPlane 函数被调用。它聚合 Worker 3 的本地统计数据（例如 { "user_A": { "speed_kbps": {...}, "traffic_delta": {...} } }）。

[数据平面 -> 控制平面] Worker 3 通过其 WebSocket 客户端 (ipcWsClient) 将此 stats_update 消息推送到 wss_panel.js 的 /ipc 服务器。

[控制平面] wss_panel.js 的 wssIpc.on('message') 处理器收到该消息。

[控制平面] 它调用 workerStatsCache.set(...) 将 Worker 3 的数据存入内存，并异步调用 persistTrafficDelta 将流量增量写入 SQLite。

[控制平面] aggregateAllWorkerStats 函数被调用，它合并所有 Worker (1, 2, 3, 4...) 的缓存数据，得到一个全局视图。

[控制平面] (熔断检查) checkAndApplyFuse 函数检查 user_A 的聚合速度是否超过 globalFuseLimitKbps。

[控制平面 -> 前端] broadcastToFrontends 函数被调用，将聚合后的统计数据（live_update 消息）通过 /ws/ui WebSocket 广播给所有连接的管理员。

[前端] app.js 收到 live_update 消息，handleSilentUpdate 函数被触发，仅更新 HTML 元素的 textContent，实现零闪烁的 1 秒刷新。

场景 2: WSS (80/443) 隧道连接流程

客户端 (例如 HTTP Injector) 向 wss_proxy.js (端口 80) 发起连接。

wss_proxy.js 检查 Host 头是否在 hosts.json 白名单中。

(Payload Eater 逻辑...) 客户端发送 Upgrade: websocket 请求。

parseAuth() 启动：

路径 1 (令牌优先): 检查 Proxy-Authorization 头。

路径 2 (URI 备选): 检查 /?user=...。

wss_proxy.js 通过内部 API (例如 http://127.0.0.1:54321/internal/auth) 请求 wss_panel.js。

wss_panel.js (作为 admin 用户) 收到请求，查询 SQLite，使用 bcrypt.compare 验证哈希，并检查用户 status 是否为 active。

wss_panel.js 回复 wss_proxy.js 认证结果 (例如 {"success": true, "limits": {"rate_kbps": 5000, "max_connections": 2}})。

wss_proxy.js 收到成功响应，updateUserLimits 被调用以配置令牌桶。

checkConcurrency() 检查并发连接数。

检查通过，wss_proxy.js 向客户端回复 HTTP/1.1 101 Switching Protocols。

wss_proxy.js 建立到内部主 SSHD (127.0.0.1:22) 的 TCP 连接。

数据开始双向转发。wss_proxy.js 中的 TokenBucket 开始对该用户的上行/下行流量实施速率限制。

场景 3: Stunnel (444) Shell 访问流程

客户端 (例如 OpenSSH) 通过 stunnel 客户端连接到服务器的 444 端口。

服务器上的 stunnel4.service 接收连接，进行 SSL 卸载。

stunnel4 将解密后的 SSH 流量转发到 127.0.0.1:2222 (Stunnel SSHD 端口)。

sshd_stunnel.service 收到连接。

sshd_stunnel 检查认证用户的系统组。由于配置了 AllowGroups shell_users，只有属于 shell_users 组的用户才被允许继续。

sshd 检查用户的系统密码，并检查账户是否被锁定 (/etc/shadow 中是否有 ! 标记)。

认证成功，用户获得 Shell 访问权限。

场景 4: 后台维护与系统锁定 (60 秒任务)

wss_panel.js 中的 syncUserStatus 计时器（每 60 秒）触发。

wss_panel.js 查询本地数据库（注意：它不再轮询 Proxy）。

它遍历所有用户，检查非实时状态：

是否 expiration_date < now()？

是否 usage_gb > quota_gb？

决策点: 发现 user_B 已到期，其数据库 status 从 active 变为 expired。

执行 (最小权限): wss_panel.js 执行 safeRunCommand(['usermod', '-L', 'user_B'])。

admin 用户通过 /etc/sudoers.d/99-wss-panel 中授予的权限，无密码成功执行了 sudo usermod -L user_B。

user_B 的系统账户被锁定。现在，user_B 无法通过 Stunnel (444) 登录，并且 wss_proxy.js 在下次 /internal/auth 调用时也会收到失败（因为 status 不是 active）。

安装与部署

本项目使用 install.sh 脚本进行一键部署。

# 1. 克隆仓库
git clone [https://github.com/2019xuanying/WSS-panel.git](https://github.com/2019xuanying/WSS-panel.git)
cd WSS-panel

# 2. 运行安装脚本
chmod +x install.sh
./install.sh


安装脚本 (V2.0.6+) 会自动：

交互式提示：要求您设置所有服务端口（WSS, Stunnel, Panel 等）和 Panel 服务用户名。

安装依赖：安装 nodejs, stunnel4, build-essential, sudo 等。

创建服务用户：创建您指定的 Panel 服务用户 (例如 admin)。

配置 Sudoers (Axiom V4.1)：创建 /etc/sudoers.d/99-wss-panel 文件，授予服务用户执行特定命令的权限 (包括 sed 和 systemctl daemon-reload，以修复端口配置功能)。

安装 Node 依赖：包括 express, bcrypt, ws 等。

安全加固：为所有密钥文件设置 chmod 600。

配置服务：根据您的端口设置，生成所有 systemd 服务文件和 sshd 配置文件。

启动服务：启动 wss_panel, wss, stunnel4, sshd_stunnel 等。

卸载

chmod +x NOinstall.sh
./NOinstall.sh


卸载脚本会自动检测您安装时设置的服务用户名，并彻底清除所有服务、配置文件、sudoers 规则、用户组和服务用户。

故障排查 (Fault Diagnosis - Axiom V4.1)

症状

可能原因

排查步骤 (Axiom 建议)

Web 面板 (54321) 无法访问

1. Panel 服务未运行。



 2. 端口冲突。



 3. sudoers 配置错误。

1. sudo systemctl status wss_panel 查看服务状态。



 2. sudo journalctl -u wss_panel -f 查看实时日志。



 3. 检查日志中是否有 sudo 权限错误或 npm 模块失败。



 4. 检查端口占用: sudo lsof -i:54321 (使用您的 Panel 端口)。

仪表盘统计数据为 0 或不刷新

1. Proxy (Data Plane) 未运行。



 2. Proxy 无法连接到 Panel 的 /ipc 端口。



 3. internal_api_secret 不匹配。

1. sudo systemctl status wss (确保 Proxy 已启动)。



 2. sudo journalctl -u wss -f (检查 Proxy 日志，查看 [IPC_WSC] 连接错误，例如 "Unauthorized" 或 "ECONNREFUSED")。



 3. 检查 config.json 中的 panel_port 和 internal_api_secret 是否正确。

WSS (80/443) 无法连接

1. Proxy 服务 (wss.service) 未运行。



 2. 端口 80/443 被占用 (例如 Nginx, Apache)。

1. sudo systemctl status wss 查看服务状态。



 2. sudo journalctl -u wss -f 查看实时日志。



 3. 检查端口占用: sudo lsof -i:80 和 sudo lsof -i:443。

WSS 连接提示 401/403

1. 客户端 Proxy-Authorization 令牌 (Base64) 错误。



 2. 尝试免认证 (/?user=...) 但用户未配置 require_auth_header = 0。



 3. Host 头不在白名单中。

1. 检查 wss_proxy.js 日志: sudo journalctl -u wss -f。日志会显示 AUTH_FAILED, AUTH_MISSING 或 REJECTED_HOST。



 2. 检查 wss_panel.js 日志: sudo journalctl -u wss_panel -f。查看 /internal/auth API 的调用结果。



 3. 检查数据库: sudo sqlite3 /etc/wss-panel/wss_panel.db "SELECT username, status, require_auth_header FROM users;"

Stunnel (444) 无法连接

1. stunnel4 服务未运行。



 2. sshd_stunnel 服务未运行。



 3. 用户未启用 "Allow Shell" (不在 shell_users 组)。



 4. 用户账户被面板锁定 (usermod -L)。

1. sudo systemctl status stunnel4 和 sudo systemctl status sshd_stunnel。



 2. sudo journalctl -u stunnel4 -f (查看 SSL 握手)。



 3. (关键) sudo journalctl -u sshd_stunnel -f (查看 SSH 认证日志，通常会显示 AllowGroups 拒绝信息)。



 4. 检查用户组: getent group shell_users。



 5. 检查账户锁定: sudo passwd -S <username> (查看是否有 L 标记)。

面板操作 (创建/暂停用户) 失败

1. sudoers 权限配置错误。



 2. admin 用户无法执行 sudo 命令。

1. sudo journalctl -u wss_panel -f 查看执行 safeRunCommand 时的 sudo 错误。



 2. (关键) 检查 sudoers 语法: sudo visudo -c -f /etc/sudoers.d/99-wss-panel。

在 UI 中修改端口配置失败

1. (常见) install.sh 版本低于 V2.0.6。



 2. sudoers 文件中缺少 sed 或 systemctl daemon-reload 权限。

1. sudo journalctl -u wss_panel -f (查找 safeRunCommand 中关于 sed 或 daemon-reload 的权限错误)。



 2. 确保 /etc/sudoers.d/99-wss-panel 包含 sed 和 systemctl daemon-reload 的 NOPASSWD 条目。



 3. 重新运行 V2.0.6+ 的 install.sh 以自动修复 sudoers。

关键文件路径

文件/目录

目的

所有者

/etc/wss-panel/

主配置目录 (数据库, 密钥)

admin (或 $panel_user)

/etc/wss-panel/config.json

(核心) 所有端口和密钥配置

admin (600 权限)

/etc/wss-panel/wss_panel.db

SQLite 数据库 (WAL 模式)

admin

/etc/wss-panel/root_hash.txt

面板 root 用户密码哈希

admin (600 权限)

/etc/wss-panel/internal_secret.txt

内部 API / IPC 密钥

admin (600 权限)

/usr/local/bin/wss_proxy.js

数据平面 (Proxy) 脚本

root

/etc/wss-panel/wss_panel.js

控制平面 (Panel) 脚本

admin

/etc/systemd/system/wss_panel.service

控制平面 (Panel) 服务文件

root

/etc/systemd/system/wss.service

数据平面 (Proxy) 服务文件

root

/etc/systemd/system/sshd_stunnel.service

Stunnel SSHD 服务文件

root

/etc/ssh/sshd_config_stunnel

Stunnel SSHD 配置文件

root (600 权限)

/etc/sudoers.d/99-wss-panel

(核心安全) 最小权限策略文件

root (440 权限)
