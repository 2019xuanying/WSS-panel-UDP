/**
 * WSS Panel Telegram Bot Module
 * * 职责：
 * 1. 接收来自 Telegram 的指令。
 * 2. 通过传入的 Context (上下文) 调用主进程的核心功能。
 * 3. 只有 config.tg_admin_id 指定的用户可以使用。
 * * 依赖安装:
 * npm install node-telegram-bot-api
 */

const TelegramBot = require('node-telegram-bot-api');
const bcrypt = require('bcrypt');

/**
 * 初始化机器人
 * @param {Object} context - 主进程传入的上下文对象
 * @param {Object} context.config - 全局配置
 * @param {Object} context.db - SQLite 数据库实例
 * @param {Function} context.safeRunCommand - 执行系统命令的函数
 * @param {Function} context.kickUserFromProxy - 踢人下线函数
 * @param {Function} context.getSystemStatusData - 获取系统状态函数
 * @param {Function} context.broadcastToFrontends - 通知前端UI刷新
 * @param {Function} context.logAction - 审计日志记录函数
 */
async function initTelegramBot(context) {
    const { 
        config, 
        db, 
        safeRunCommand, 
        kickUserFromProxy, 
        getSystemStatusData, 
        broadcastToFrontends,
        logAction
    } = context;

    // 1. 检查配置
    if (!config.tg_bot_token) {
        console.log('[TG_BOT] 未检测到 tg_bot_token，机器人模块跳过启动。');
        return;
    }

    const token = config.tg_bot_token;
    const adminId = config.tg_admin_id ? parseInt(config.tg_admin_id) : null;

    console.log(`[TG_BOT] 正在启动 Telegram 机器人... (Admin ID: ${adminId || '未设置 - 不安全!'})`);

    // 2. 创建 Bot 实例 (Polling 模式)
    const bot = new TelegramBot(token, { polling: true });

    // --- 权限校验中间件 ---
    // 所有的消息处理前都会先经过这里
    const checkPermission = (msg) => {
        if (!adminId) {
            bot.sendMessage(msg.chat.id, "⚠️ 警告：服务器端未配置 `tg_admin_id`，拒绝执行指令。");
            return false;
        }
        if (msg.from.id !== adminId) {
            bot.sendMessage(msg.chat.id, "⛔️ 权限不足。此机器人仅限管理员使用。");
            console.warn(`[TG_BOT] 拒绝未授权访问: ${msg.from.username} (ID: ${msg.from.id})`);
            return false;
        }
        return true;
    };

    // --- 辅助函数：流量格式化 ---
    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    // =============================
    // 指令处理器
    // =============================

    // 1. /start & /help
    bot.onText(/\/start|\/help/, (msg) => {
        if (!checkPermission(msg)) return;
        const helpText = `
🤖 *WSS Panel 管理机器人*

可用指令：

📊 *状态监控*
/status - 查看系统负载、连接数、流量

👤 *用户管理*
/user <用户名> - 查询用户详情
/add <用户> <密> <天> <GB> <限速> <并发> - 添加用户
/del <用户名> - 删除用户
/reset <用户名> - 重置用户流量

⚙️ *系统操作*
/restart - 重启 WSS 面板服务
        `;
        bot.sendMessage(msg.chat.id, helpText, { parse_mode: 'Markdown' });
    });

    // 2. /status - 系统状态
    bot.onText(/\/status/, async (msg) => {
        if (!checkPermission(msg)) return;
        
        const loadingMsg = await bot.sendMessage(msg.chat.id, "🔍 正在获取系统状态...");
        
        try {
            // 调用主进程的函数获取数据
            const data = await getSystemStatusData();
            
            const statsText = `
🖥 *系统状态报告*
------------------
🔥 *CPU*: ${data.cpu_usage.toFixed(1)}%
🧠 *内存*: ${data.memory_used_gb.toFixed(2)} / ${data.memory_total_gb.toFixed(2)} GB
💾 *磁盘*: ${data.disk_used_percent}%

🌐 *网络服务*
• WSS (80/443): ${data.services.wss.status === 'running' ? '✅' : '❌'}
• Stunnel (444): ${data.services.stunnel4.status === 'running' ? '✅' : '❌'}
• UDPGW (7300): ${data.services.udpgw.status === 'running' ? '✅' : '❌'}
• UDP Custom: ${data.services['wss-udp-custom'].status === 'running' ? '✅' : '❌'}

👥 *用户统计*
• 总用户: ${data.user_stats.total}
• 活跃连接: ${data.user_stats.active}
• 暂停/过期: ${data.user_stats.paused + data.user_stats.expired}
• 总消耗流量: ${data.user_stats.total_traffic_gb.toFixed(2)} GB
            `;
            
            bot.editMessageText(statsText, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown'
            });
        } catch (e) {
            bot.editMessageText(`❌ 获取状态失败: ${e.message}`, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id
            });
        }
    });

    // 3. /user <username> - 查询用户
    bot.onText(/\/user (.+)/, async (msg, match) => {
        if (!checkPermission(msg)) return;
        const username = match[1];

        try {
            const user = await db.get('SELECT * FROM users WHERE username = ?', username);
            if (!user) {
                bot.sendMessage(msg.chat.id, `❌ 用户 \`${username}\` 不存在。`, { parse_mode: 'Markdown' });
                return;
            }

            const statusEmoji = user.status === 'active' ? '✅' : (user.status === 'paused' ? '⏸' : '❌');
            const quota = user.quota_gb > 0 ? `${user.quota_gb} GB` : '无限';
            const limit = user.rate_kbps > 0 ? `${(user.rate_kbps/1024).toFixed(1)} MB/s` : '无限';
            const conn = user.max_connections > 0 ? user.max_connections : '无限';

            const detailText = `
👤 *用户详情*: \`${user.username}\`
------------------
状态: ${statusEmoji} ${user.status_text || user.status}
到期: ${user.expiration_date || '永不'}
流量: ${user.usage_gb.toFixed(2)} / ${quota}
限速: ${limit}
并发: ${conn} (当前: ${user.active_connections || 0})
Auth头: ${user.require_auth_header ? '需要' : '免认证'}
            `;
            bot.sendMessage(msg.chat.id, detailText, { parse_mode: 'Markdown' });

        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 查询失败: ${e.message}`);
        }
    });

    // 4. /add - 添加用户
    // 格式: /add <user> <pass> <days> <gb> <limit_kbps> <conn>
    bot.onText(/\/add (.+)/, async (msg, match) => {
        if (!checkPermission(msg)) return;
        
        const params = match[1].split(' ');
        if (params.length < 2) {
            bot.sendMessage(msg.chat.id, "⚠️ 格式错误。\n用法: `/add 用户名 密码 [天数] [GB] [限速KB] [并发]`", { parse_mode: 'Markdown' });
            return;
        }

        const [username, password, daysStr, quotaStr, rateStr, connStr] = params;
        const days = parseInt(daysStr) || 365;
        const quotaGb = parseFloat(quotaStr) || 0;
        const rateKbps = parseInt(rateStr) || 0;
        const maxConn = parseInt(connStr) || 3;

        const loadingMsg = await bot.sendMessage(msg.chat.id, `⏳ 正在创建用户 ${username}...`);

        try {
            // 检查用户是否存在
            const existing = await db.get('SELECT username FROM users WHERE username = ?', username);
            if (existing) {
                throw new Error("用户已存在");
            }

            // 1. 系统命令创建用户 (复制自 wss_panel.js 的逻辑)
            const shell = "/sbin/nologin";
            const { success: userAddSuccess, output: userAddOutput } = await safeRunCommand(['useradd', '-m', '-s', shell, username]);
            if (!userAddSuccess && !userAddOutput.includes("already exists")) {
                throw new Error(`系统用户创建失败: ${userAddOutput}`);
            }

            // 2. 设置系统密码
            const chpasswdInput = `${username}:${password}`;
            const { success: chpassSuccess, output: chpassOutput } = await safeRunCommand(['chpasswd'], chpasswdInput);
            if (!chpassSuccess) throw new Error(`密码设置失败: ${chpassOutput}`);

            // 3. 解锁用户
            await safeRunCommand(['usermod', '-U', username]);

            // 4. 写入数据库
            const passwordHash = await bcrypt.hash(password, 12);
            const expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
            
            await db.run(`INSERT INTO users (
                username, password_hash, created_at, status, expiration_date, 
                quota_gb, usage_gb, rate_kbps, max_connections, 
                require_auth_header, status_text, allow_shell
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                  username, passwordHash, new Date().toISOString().slice(0, 19).replace('T', ' '),
                  'active', expiryDate, quotaGb, 0.0, rateKbps, maxConn, 
                  1, '启用 (Active)', 0
              ]
            );

            // 5. 广播通知前端
            broadcastToFrontends({ type: 'users_changed' });
            
            // 6. 记录日志
            if(logAction) await logAction("USER_ADD_BOT", "TG_BOT", `User ${username} created via Telegram.`);

            bot.editMessageText(`✅ *成功创建用户*\n\n👤 账号: \`${username}\`\n🔑 密码: \`${password}\`\n📅 到期: ${expiryDate}\n📊 配额: ${quotaGb || '∞'} GB`, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown'
            });

        } catch (e) {
            // 回滚尝试
            await safeRunCommand(['userdel', '-r', username]);
            bot.editMessageText(`❌ 创建失败: ${e.message}`, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id
            });
        }
    });

    // 5. /del - 删除用户
    bot.onText(/\/del (.+)/, async (msg, match) => {
        if (!checkPermission(msg)) return;
        const username = match[1];
        
        try {
            const user = await db.get('SELECT username FROM users WHERE username = ?', username);
            if (!user) {
                bot.sendMessage(msg.chat.id, "❌ 用户不存在。");
                return;
            }

            // 执行删除逻辑
            await kickUserFromProxy(username);
            await safeRunCommand(['pkill', '-9', '-u', username]);
            await safeRunCommand(['userdel', '-r', username]);
            await db.run('DELETE FROM users WHERE username = ?', username);
            await db.run('DELETE FROM traffic_history WHERE username = ?', username);

            broadcastToFrontends({ type: 'users_changed' });
            if(logAction) await logAction("USER_DEL_BOT", "TG_BOT", `User ${username} deleted via Telegram.`);

            bot.sendMessage(msg.chat.id, `🗑 用户 \`${username}\` 已删除。`, { parse_mode: 'Markdown' });

        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 删除失败: ${e.message}`);
        }
    });

    // 6. /restart - 重启服务
    bot.onText(/\/restart/, async (msg) => {
        if (!checkPermission(msg)) return;
        
        bot.sendMessage(msg.chat.id, "⚠️ 正在重启 WSS Panel 服务，机器人将暂时下线...");
        
        // 延迟执行，给消息发送留出时间
        setTimeout(async () => {
             // 实际上我们重启 wss_panel 服务
             // 注意：这会导致当前 Node 进程退出，Bot 也会断开，这是正常的
             await safeRunCommand(['systemctl', 'restart', 'wss_panel']);
        }, 1000);
    });
    
    // 错误处理
    bot.on('polling_error', (error) => {
        // 忽略常见的轮询超时错误，避免刷屏
        if (error.code !== 'EFATAL') {
             console.error(`[TG_BOT] Polling Error: ${error.message}`);
        }
    });
}

module.exports = { initTelegramBot };
