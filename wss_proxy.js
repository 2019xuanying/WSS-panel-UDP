/**
 * WSS Proxy Core (Node.js)
 * V9.6.0 (Axiom Stealth - Smart Dual-Mode)
 *
 * [ARCHITECT REVIEW V9.6.0]
 * - [STEALTH] 真实网站回落 (Real-Site Fallback): 非法流量（Host不匹配/协议错误）会被透明代理到 FALLBACK_TARGET (如 www.bing.com)。
 * 探测者将看到真实的 Bing 响应，而不是静态页面。
 * - [COMPATIBILITY] 宽松的 Payload Eater: 在 WebSocket 握手后，优先尝试寻找 SSH-2.0- 标记并清洗数据。
 * 如果找不到标记但有数据（针对非标准客户端），则回退到“原样转发”模式，确保连接不中断。
 * - [PERFORMANCE] 集成了 V9.x 的 IPC 性能优化（紧凑数组推送、僵尸连接修复）。
 */

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const http = require('http'); 
const { URLSearchParams } = require('url');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto'); 


// --- [AXIOM V2.0] 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        if (cluster.isWorker) {
            console.log(`[AXIOM V9.6] Worker ${cluster.worker.id} 成功从 ${CONFIG_PATH} 加载配置。`);
        }
    } catch (e) {
        console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。服务将退出。`);
        process.exit(1); 
    }
}
loadConfig(); 
// --- 结束配置加载 ---


// --- 核心常量 ---
const LISTEN_ADDR = '0.0.0.0';
const WSS_LOG_FILE = path.join(PANEL_DIR, 'wss.log'); 
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
const HTTP_PORT = config.wss_http_port;
const TLS_PORT = config.wss_tls_port;
const INTERNAL_FORWARD_PORT = config.internal_forward_port;
const INTERNAL_API_PORT = config.internal_api_port;
const PANEL_API_URL = config.panel_api_url;
const INTERNAL_API_SECRET = config.internal_api_secret;
const DEFAULT_TARGET = { host: '127.0.0.1', port: INTERNAL_FORWARD_PORT };

// [STEALTH] 真实回落目标 (可以是任何 HTTP 网站)
// 建议选择一个内容丰富且支持 HTTP 的大站，例如 www.bing.com 或 www.baidu.com
const FALLBACK_TARGET = { host: 'www.bing.com', port: 80 }; 

// [SECURITY] DoS 防护：最大允许的 HTTP 头部大小 (16KB)
const MAX_HEADER_SIZE = 16 * 1024;
const TIMEOUT = 86400000; 
const BUFFER_SIZE = 65536;
const CERT_FILE = '/etc/stunnel/certs/stunnel.pem';
const KEY_FILE = '/etc/stunnel/certs/stunnel.key';

// [SECURITY] 真实的业务响应
const SWITCH_RESPONSE = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');

const INTERNAL_ERROR_RESPONSE = Buffer.from('HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n');

let HOST_WHITELIST = new Set();
let logStream; 
let allWorkerStats = new Map();


// --- 令牌桶 (Token Bucket) 限速器 (保持不变) ---
class TokenBucket {
    constructor(capacityKbps, fillRateKbps) {
        this.capacity = Math.max(0, capacityKbps * 1024); 
        this.fillRate = Math.max(0, fillRateKbps * 1024 / 1000); 
        this.tokens = this.capacity; 
        this.lastFill = Date.now();
    }
    _fillTokens() {
        const now = Date.now();
        const elapsed = now - this.lastFill;
        if (elapsed > 0) {
            const newTokens = elapsed * this.fillRate;
            this.tokens = Math.min(this.capacity, this.tokens + newTokens);
            this.lastFill = now;
        }
    }
    consume(bytesToConsume) {
        if (this.fillRate === 0) return bytesToConsume; 
        this._fillTokens();
        if (bytesToConsume <= this.tokens) {
            this.tokens -= bytesToConsume;
            return bytesToConsume; 
        }
        if (this.tokens > 0) {
             const allowedBytes = this.tokens;
             this.tokens = 0;
             return allowedBytes; 
        }
        return 0; 
    }
    updateRate(newCapacityKbps, newFillRateKbps) {
        this._fillTokens();
        this.capacity = Math.max(0, newCapacityKbps * 1024);
        this.fillRate = Math.max(0, newFillRateKbps * 1024 / 1000);
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
}

// --- 全局状态管理 ---
const userStats = new Map();
const SPEED_CALC_INTERVAL = 1000; 

const pending_traffic_delta = {}; 
const WORKER_ID = cluster.isWorker ? cluster.worker.id : 'master';

function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            connections: new Map(), // key: net.Socket, value: {id, clientIp, startTime}
            ip_map: new Map(), 
            traffic_delta: { upload: 0, download: 0 }, 
            traffic_live: { upload: 0, download: 0 }, 
            speed_kbps: { upload: 0, download: 0 },
            lastSpeedCalc: { upload: 0, download: 0, time: Date.now() }, 
            bucket_up: new TokenBucket(0, 0),
            bucket_down: new TokenBucket(0, 0),
            limits: { rate_kbps: 0, max_connections: 0, require_auth_header: 1 },
            // [V9.5 NEW] 用于追踪自上次推送以来是否有速度/连接/流量变化 (差分更新)
            hasChanged: false, 
            lastPushConn: 0,
            lastPushSpeedUp: 0,
            lastPushSpeedDown: 0
        });
    }
    return userStats.get(username);
}

/** 实时速度计算器 */
function calculateSpeeds() {
    const now = Date.now();
    for (const [username, stats] of userStats.entries()) {
        const elapsed = now - stats.lastSpeedCalc.time;
        if (elapsed < (SPEED_CALC_INTERVAL / 2)) continue; 
        const elapsedSeconds = elapsed / 1000.0;
        
        const uploadDelta = stats.traffic_live.upload - stats.lastSpeedCalc.upload;
        const newSpeedUp = (uploadDelta / 1024) / elapsedSeconds;
        
        const downloadDelta = stats.traffic_live.download - stats.lastSpeedCalc.download;
        const newSpeedDown = (downloadDelta / 1024) / elapsedSeconds;
        
        const speedChanged = Math.abs(newSpeedUp - stats.speed_kbps.upload) > 0.1 || 
                             Math.abs(newSpeedDown - stats.speed_kbps.download) > 0.1;
        
        const deltaTraffic = stats.traffic_delta.upload + stats.traffic_delta.download;
        const connChanged = stats.connections.size !== stats.lastPushConn;
        
        if (speedChanged || deltaTraffic > 0 || connChanged) {
             stats.hasChanged = true;
        }

        stats.speed_kbps.upload = newSpeedUp;
        stats.lastSpeedCalc.upload = stats.traffic_live.upload;

        stats.speed_kbps.download = newSpeedDown;
        stats.lastSpeedCalc.download = stats.traffic_live.download;
        
        stats.lastSpeedCalc.time = now;
        
        if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
            if (!pending_traffic_delta[username]) {
                pending_traffic_delta[username] = { upload: 0, download: 0 };
            }
            pending_traffic_delta[username].upload += stats.traffic_delta.upload;
            pending_traffic_delta[username].download += stats.traffic_delta.download;
            
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0; 
        }
        
        const hasPending = pending_traffic_delta[username] && 
                           (pending_traffic_delta[username].upload > 0 || pending_traffic_delta[username].download > 0);
                           
        if (stats.connections.size === 0 && !hasPending) {
            // [V9.5 BUGFIX] 在删除前，先强制发送归零状态
            if (stats.lastPushConn > 0) {
                 pushZeroStatus(username);
            }
            userStats.delete(username);
            if (pending_traffic_delta[username]) {
                delete pending_traffic_delta[username];
            }
        }
    }
}
setInterval(calculateSpeeds, SPEED_CALC_INTERVAL);


// --- [AXIOM V5.0] 实时 IPC 客户端 (指数退避重连) ---

let ipcWsClient = null;
let statsPusherIntervalId = null;

let ipcReconnectTimer = null;
let ipcReconnectAttempts = 0;
const MAX_RECONNECT_DELAY_MS = 60000; 

/**
 * [V9.5 BUGFIX] 显式推送用户归零状态 (僵尸连接修复)
 */
function pushZeroStatus(username) {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
        return; 
    }
     const stats = userStats.get(username);
     if (!stats) return; 
     
     stats.lastPushConn = 0;
     stats.lastPushSpeedUp = 0;
     stats.lastPushSpeedDown = 0;

     const zeroPacket = [
        [
             username, 
             0, 
             0, 
             0, 
             stats.traffic_delta.upload,
             stats.traffic_delta.download
        ]
     ];
     
     stats.traffic_delta.upload = 0;
     stats.traffic_delta.download = 0;
     
     try {
        ipcWsClient.send(JSON.stringify({
            type: 'stats_update_compact',
            workerId: WORKER_ID, 
            payload: zeroPacket
        }));
    } catch (e) {
        console.error(`[IPC_WSC Worker ${WORKER_ID}] 推送归零状态失败: ${e.message}`);
    }
}


/**
 * [AXIOM V9.5] 实时统计推送器 (使用紧凑数组)
 */
function pushStatsToControlPlane(ws_client) {
    if (!ws_client || ws_client.readyState !== WebSocket.OPEN) {
        return; 
    }

    for (const username in pending_traffic_delta) {
        const stats = getUserStat(username); 
        stats.traffic_delta.upload += pending_traffic_delta[username].upload;
        stats.traffic_delta.download += pending_traffic_delta[username].download;
        if (stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
             stats.hasChanged = true;
        }
        delete pending_traffic_delta[username];
    }
    
    const compactStatsArray = [];
    
    for (const [username, stats] of userStats.entries()) {
        const speedUp = parseFloat(stats.speed_kbps.upload.toFixed(1));
        const speedDown = parseFloat(stats.speed_kbps.download.toFixed(1));
        
        const hasSignificantChange = 
            stats.hasChanged || 
            stats.connections.size !== stats.lastPushConn || 
            speedUp !== stats.lastPushSpeedUp || 
            speedDown !== stats.lastPushSpeedDown; 

        if (hasSignificantChange) {
            compactStatsArray.push([
                username, 
                stats.connections.size, 
                speedUp, 
                speedDown,
                stats.traffic_delta.upload,
                stats.traffic_delta.download
            ]);
            
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0;
            stats.lastPushConn = stats.connections.size;
            stats.lastPushSpeedUp = speedUp;
            stats.lastPushSpeedDown = speedDown;
            stats.hasChanged = false; 
        }
    }

    if (compactStatsArray.length > 0) {
         try {
            ws_client.send(JSON.stringify({
                type: 'stats_update_compact', 
                workerId: WORKER_ID, 
                payload: compactStatsArray 
            }));
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 推送紧凑统计数据失败: ${e.message}`);
        }
    }
}

function kickUser(username) {
    const stats = userStats.get(username);
    if (stats && stats.connections.size > 0) {
        console.log(`[IPC_CMD Worker ${WORKER_ID}] 正在踢出用户 ${username} (${stats.connections.size} 个连接)...`);
        for (const socket of stats.connections.keys()) {
            socket.destroy(); 
        }
        stats.connections.clear();
        stats.ip_map.clear();
    }
}

function updateUserLimits(username, limits) {
    if (!limits) return;
    const stats = getUserStat(username); 
    stats.limits = {
        rate_kbps: limits.rate_kbps || 0,
        max_connections: limits.max_connections || 0,
        require_auth_header: limits.require_auth_header === 0 ? 0 : 1
    };
    const rateUp = stats.limits.rate_kbps;
    stats.bucket_up.updateRate(rateUp * 2, rateUp); 
    const rateDown = stats.limits.rate_kbps; 
    stats.bucket_down.updateRate(rateDown * 2, rateDown); 
}

function resetUserTraffic(username) {
    const stats = userStats.get(username);
    if (stats) {
        console.log(`[IPC_CMD Worker ${WORKER_ID}] 正在重置用户 ${username} 的流量计数器...`);
        stats.traffic_delta = { upload: 0, download: 0 };
        stats.traffic_live = { upload: 0, download: 0 };
        stats.lastSpeedCalc = { upload: 0, download: 0, time: Date.now() };
        stats.hasChanged = true; 
        if (pending_traffic_delta[username]) {
             delete pending_traffic_delta[username];
        }
    }
}

function attemptIpcReconnect() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    const baseDelay = Math.pow(2, ipcReconnectAttempts) * 1000;
    const delay = Math.min(baseDelay, MAX_RECONNECT_DELAY_MS);
    ipcReconnectAttempts++;
    console.warn(`[IPC_WSC Worker ${WORKER_ID}] 正在重试连接 (尝试次数: ${ipcReconnectAttempts}, 延迟: ${delay / 1000}s)...`);
    ipcReconnectTimer = setTimeout(connectToIpcServer, delay);
}


function connectToIpcServer() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    if (ipcWsClient && (ipcWsClient.readyState === WebSocket.OPEN || ipcWsClient.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    
    if (ipcWsClient) {
        ipcWsClient.removeAllListeners(); 
        ipcWsClient.close();
        ipcWsClient = null;
    }

    const ws = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret,
            'X-Worker-ID': WORKER_ID 
        }
    });

    ipcWsClient = ws;

    ws.on('open', () => {
        console.log(`[IPC_WSC Worker ${WORKER_ID}] 成功连接到控制平面 (Panel)。实时推送已激活。`);
        ipcReconnectAttempts = 0;
        
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        
        statsPusherIntervalId = setInterval(() => {
            pushStatsToControlPlane(ipcWsClient); 
        }, 1000); 

    });

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            switch (message.action) {
                case 'kick':
                    if (message.username) {
                        kickUser(message.username);
                    }
                    break;
                case 'update_limits':
                    if (message.username && message.limits) {
                        updateUserLimits(message.username, message.limits);
                    }
                    break;
                case 'reset_traffic':
                     if (message.username) {
                        resetUserTraffic(message.username);
                    }
                    break;
                case 'delete':
                    if (message.username) {
                        kickUser(message.username); 
                        pushZeroStatus(message.username);
                        if (userStats.has(message.username)) {
                            userStats.delete(message.username); 
                        }
                    }
                    break;
                case 'reload_hosts':
                    console.log(`[IPC_CMD Worker ${WORKER_ID}] 收到重载 Hosts 命令...`);
                    loadHostWhitelist();
                    break;
                case 'GET_METADATA':
                     if (message.username && message.requestId) {
                         const stats = userStats.get(message.username);
                         const connections = [];
                         if (stats) {
                            stats.connections.forEach(meta => {
                                connections.push({
                                    id: meta.id,
                                    ip: meta.clientIp,
                                    start: meta.startTime,
                                    workerId: WORKER_ID 
                                });
                            });
                         }
                         ws.send(JSON.stringify({
                             type: 'METADATA_RESPONSE',
                             requestId: message.requestId,
                             username: message.username,
                             workerId: WORKER_ID,
                             connections: connections
                         }));
                     }
                    break;
            }
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 解析 IPC 消息失败: ${e.message}`);
        }
    });

    ws.on('close', (code, reason) => {
        console.warn(`[IPC_WSC Worker ${WORKER_ID}] 与控制平面的连接已断开。代码: ${code}.`);
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        statsPusherIntervalId = null;
        ipcWsClient = null;
        attemptIpcReconnect();
    });

    ws.on('error', (err) => {
        console.error(`[IPC_WSC Worker ${WORKER_ID}] WebSocket 发生错误: ${err.message}`);
    });
}


// --- 异步日志设置 ---
function setupLogStream() {
    try {
        logStream = fs.createWriteStream(WSS_LOG_FILE, { flags: 'a' });
        logStream.on('error', (err) => {
            console.error(`[CRITICAL] Error in WSS log stream: ${err.message}`);
        });
    } catch (e) {
        console.error(`[CRITICAL] Failed to create log stream: ${e.message}`);
    }
}

function logConnection(clientIp, clientPort, localPort, username, status) {
    if (!logStream) return;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const workerId = cluster.isWorker ? `Worker ${WORKER_ID}` : 'Master(N/A)';
    const logEntry = `[${timestamp}] [${status}] [${workerId}] USER=${username} CLIENT_IP=${clientIp} LOCAL_PORT=${localPort}\n`;
    logStream.write(logEntry);
}

// --- Host 白名单管理 ---
function loadHostWhitelist() {
    try {
        if (!fs.existsSync(HOSTS_DB_PATH)) {
            HOST_WHITELIST = new Set();
            return;
        }
        const data = fs.readFileSync(HOSTS_DB_PATH, 'utf8');
        const hosts = JSON.parse(data);
        if (Array.isArray(hosts)) {
            const cleanHosts = new Set();
            hosts.forEach(host => {
                if (typeof host === 'string') {
                    let h = host.trim().toLowerCase();
                    if (h.includes(':')) h = h.split(':')[0]; 
                    if (h) cleanHosts.add(h);
                }
            });
            HOST_WHITELIST = cleanHosts;
            if (cluster.isWorker) {
                console.log(`[Worker ${WORKER_ID}] Host Whitelist loaded successfully. Count: ${HOST_WHITELIST.size}`);
            }
        } else {
            HOST_WHITELIST = new Set();
        }
    } catch (e) {
        HOST_WHITELIST = new Set();
        console.error(`Error loading Host Whitelist: ${e.message}. Using empty list.`);
    }
}

function checkHost(headers) {
    const hostMatch = headers.match(/Host:\s*([^\s\r\n]+)/i);
    if (!hostMatch) {
        if (HOST_WHITELIST.size > 0) {
            return false;
        }
        return true; 
    }
    let requestedHost = hostMatch[1].trim().toLowerCase();
    if (requestedHost.includes(':')) requestedHost = requestedHost.split(':')[0];
    if (HOST_WHITELIST.size === 0) return true; 
    if (HOST_WHITELIST.has(requestedHost)) return true;
    
    return false;
}

// --- 认证与并发检查 ---

function parseAuth(headers) {
    const authMatch = headers.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
    if (!authMatch) return null;
    try {
        const credentials = Buffer.from(authMatch[1], 'base64').toString('utf8');
        const [username, ...passwordParts] = credentials.split(':');
        const password = passwordParts.join(':');
        if (!username || !password) return null;
        return { username, password };
    } catch (e) {
        return null;
    }
}

async function authenticateUser(username, password) {
    try {
        const response = await fetch(PANEL_API_URL + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            return { success: false, limits: null, requireAuthHeader: 1, message: errorData.message || `Auth failed with status ${response.status}` };
        }
        const data = await response.json();
        updateUserLimits(username, data.limits);
        return { success: true, limits: data.limits, requireAuthHeader: data.require_auth_header, message: 'Auth successful' };
    } catch (e) {
        console.error(`[AUTH] Failed to fetch Panel /auth API: ${e.message}`);
        return { success: false, limits: null, requireAuthHeader: 1, message: 'Internal API connection error', status: 503 };
    }
}

async function getLiteAuthStatus(username) {
    try {
        const params = new URLSearchParams({ username });
        const response = await fetch(PANEL_API_URL + '/auth/user-settings?' + params.toString(), {
            method: 'GET',
        });
        if (!response.ok) {
            const status = response.status;
            return { exists: false, requireAuthHeader: 1, status };
        }
        const data = await response.json();
        if (data.success && data.require_auth_header === 0) {
            if (data.limits) {
                updateUserLimits(username, data.limits);
            }
        }
        return { exists: data.success, requireAuthHeader: data.require_auth_header || 1, status: 200 };
    } catch (e) {
        console.error(`[LITE_AUTH] Failed to fetch Panel /auth/user-settings API: ${e.message}`);
        return { exists: false, requireAuthHeader: 1, status: 503 };
    }
}

async function checkConcurrency(username, maxConnections) {
    if (maxConnections === 0) return true; 
    
    const stats = getUserStat(username); 
    if (stats.connections.size >= maxConnections) {
        return false;
    }
    
    try {
        const params = new URLSearchParams({ username, worker_id: WORKER_ID });
        const response = await fetch(PANEL_API_URL + '/auth/check-conn?' + params.toString(), {
            method: 'GET'
        });
        const data = await response.json();
        
        if (!response.ok || !data.success || !data.allowed) {
            return false;
        }
        return data.allowed;
    } catch (e) {
        return (stats.connections.size < maxConnections);
    }
}


// --- Client Handler (Core Logic with Fallback) ---
function handleClient(clientSocket, isTls) {
    
    let clientIp = clientSocket.remoteAddress;
    if (clientIp.startsWith('::ffff:')) {
        clientIp = clientIp.substring(7);
    }
    
    let clientPort = clientSocket.remotePort;
    let localPort = clientSocket.localPort;

    let fullRequest = Buffer.alloc(0);
    
    let state = 'handshake';
    let remoteSocket = null;
    let username = null; 
    let limits = null; 
    let requireAuthHeader = 1; 

    clientSocket.setTimeout(TIMEOUT);
    clientSocket.setKeepAlive(true, 60000);

    // [STEALTH] 核心功能：将非法流量透明转发到回落目标 (Real-Site)
    // 无论是爬虫、浏览器直接访问，还是错误的鉴权，都会被“喂”给这个真实网站。
    const proxyToFallback = (initialData) => {
        // 防止重复调用
        if (state === 'fallback' || clientSocket.destroyed) return;
        state = 'fallback';

        logConnection(clientIp, clientPort, localPort, 'N/A', `REDIRECTING_TO_FALLBACK (${FALLBACK_TARGET.host})`);

        const fallbackSocket = net.connect(FALLBACK_TARGET.port, FALLBACK_TARGET.host, () => {
            // 收到连接后，发送客户端的原始数据
            if (initialData && initialData.length > 0) {
                fallbackSocket.write(initialData);
            }
            // 建立双向管道：Client <-> Fallback Site
            clientSocket.pipe(fallbackSocket).pipe(clientSocket);
        });

        fallbackSocket.on('error', (err) => {
            console.error(`[FALLBACK_ERR] Worker ${WORKER_ID} Failed to connect to fallback (${FALLBACK_TARGET.host}): ${err.message}`);
            clientSocket.destroy(); // 回落目标挂了，断开客户端
        });
        
        // 当回落目标关闭连接时，我们也关闭客户端
        fallbackSocket.on('close', () => {
            if (!clientSocket.destroyed) clientSocket.end(); 
        });
        
        // 错误处理：确保两端错误都会导致双方断开
        clientSocket.on('error', () => fallbackSocket.destroy());
    };

    clientSocket.on('error', (err) => {
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });

    clientSocket.on('timeout', () => {
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });
    
    clientSocket.on('close', () => {
        if (remoteSocket && !remoteSocket.destroyed) remoteSocket.destroy();
        if (username) {
            try {
                const stats = getUserStat(username);
                // [V9.5 BUGFIX] 标记连接数变化
                stats.connections.delete(clientSocket);
                stats.ip_map.delete(clientIp);
                stats.hasChanged = true;
            } catch (e) {}
            logConnection(clientIp, clientPort, localPort, username, 'CONN_END');
        }
    });

    clientSocket.on('data', async (data) => {
        
        if (state === 'forwarding') {
            const stats = getUserStat(username);
            const allowedBytes = stats.bucket_up.consume(data.length);
            if (allowedBytes === 0) return; 
            const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
            stats.traffic_delta.upload += dataToWrite.length;
            stats.traffic_live.upload += dataToWrite.length;
            stats.hasChanged = true; // 标记有流量变化
            if (remoteSocket && remoteSocket.writable) {
                remoteSocket.write(dataToWrite);
            }
            return;
        }

        if (state === 'fallback') {
            // 已经处于回落状态，将数据直接写入回落 socket (由 proxyToFallback 接管)
            return;
        }

        // [SECURITY] DoS 防护：检查缓冲区大小
        if (fullRequest.length + data.length > MAX_HEADER_SIZE) {
            logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_DOS_HEADER_SIZE');
            clientSocket.destroy(); // 直接切断
            return;
        }

        fullRequest = Buffer.concat([fullRequest, data]);

        while (state === 'handshake' && fullRequest.length > 0) {
            
            const headerEndIndex = fullRequest.indexOf('\r\n\r\n');

            if (headerEndIndex === -1) {
                return; // 等待更多数据
            }

            const headersRaw = fullRequest.subarray(0, headerEndIndex);
            let dataAfterHeaders = fullRequest.subarray(headerEndIndex + 4);
            const headers = headersRaw.toString('utf8', 0, headersRaw.length);
            
            fullRequest = dataAfterHeaders;
            
            // 1. Host 检查 (Anti-Probing)
            if (!checkHost(headers)) {
                logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_HOST_FALLBACK');
                proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                return; 
            }
            
            const auth = parseAuth(headers);
            
            const isWebsocketRequest = headers.includes('Upgrade: websocket') || 
                                       headers.includes('Connection: Upgrade') || 
                                       headers.includes('GET-RAY'); 

            // 2. 协议检查 (Anti-Probing)
            if (!isWebsocketRequest) {
                 // 哑请求或纯 HTTP 流量，直接代理到回落网站
                 logConnection(clientIp, clientPort, localPort, 'N/A', 'DUMMY_HTTP_REQUEST_FALLBACK');
                 proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders]));
                 return; 
            }
            
            // --- 认证流程 ---
            let authResult;
            if (auth) {
                username = auth.username; 
                authResult = await authenticateUser(auth.username, auth.password);
                
                if (authResult.status === 503) {
                    clientSocket.end(INTERNAL_ERROR_RESPONSE);
                    return;
                }
                if (!authResult.success) {
                    logConnection(clientIp, clientPort, localPort, username, `AUTH_FAILED_FALLBACK (${authResult.message})`);
                    // 认证失败，代理到回落网站
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                    return; 
                }
                limits = authResult.limits; 
                requireAuthHeader = authResult.requireAuthHeader;
                
            } else {
                // 尝试 URI 免认证
                const uriMatch = headers.match(/GET\s+\/\?user=([a-z0-9_]{3,16})/i);
                
                if (requireAuthHeader === 1) { 
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'AUTH_MISSING_FALLBACK');
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                    return;
                }

                if (!uriMatch) {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'URI_AUTH_MISSING_FALLBACK');
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders]));
                    return; 
                }
                
                const tempUsername = uriMatch[1];
                const liteAuth = await getLiteAuthStatus(tempUsername);

                if (liteAuth.status === 503) {
                     clientSocket.end(INTERNAL_ERROR_RESPONSE);
                     return;
                }
                
                if (liteAuth.exists && liteAuth.requireAuthHeader === 0) {
                    username = tempUsername;
                    limits = getUserStat(username).limits; 
                    requireAuthHeader = 0;
                    logConnection(clientIp, clientPort, localPort, username, 'AUTH_LITE_SUCCESS');
                    
                } else {
                    logConnection(clientIp, clientPort, localPort, tempUsername, 'AUTH_LITE_FAILED_FALLBACK');
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders]));
                    return; 
                }
            }
            
            // --- 并发检查 ---
            if (!await checkConcurrency(username, limits.max_connections)) {
                logConnection(clientIp, clientPort, localPort, username, `REJECTED_CONCURRENCY`);
                // 并发超限，代理到回落网站 (以避免返回可追踪的 429 或 403 错误码)
                proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                return; 
            }
            
            // --- 升级连接 ---
            clientSocket.write(SWITCH_RESPONSE); 
            
            const initialSshData = fullRequest;
            fullRequest = Buffer.alloc(0); 

            // --- Payload Eater / 分割载荷处理 (V8.6.0 Logic - Loose Mode) ---
            // [AXIOM V9.5 CRITICAL FIX] 使用宽松的检测逻辑。
            // 如果找到 SSH-2.0- 标记，则截断前面的垃圾数据。
            // 如果没有找到标记，但有数据，则原样转发（兼容非标准客户端）。
            
            const sshVersionMarker = Buffer.from('SSH-2.0-');
            const sshStartIndex = initialSshData.indexOf(sshVersionMarker);
            
            let dataToSend = initialSshData;
            
            if (sshStartIndex !== -1) {
                dataToSend = initialSshData.subarray(sshStartIndex);
                logConnection(clientIp, clientPort, localPort, username, `PAYLOAD_EATER_SUCCESS (Skipped ${sshStartIndex} bytes)`);
            } else if (initialSshData.length > 0) {
                 logConnection(clientIp, clientPort, localPort, username, `PAYLOAD_EATER_WARNING (No SSH Marker)`);
            }
            
            connectToTarget(dataToSend);
            return;

        } 
    }); 

    async function connectToTarget(initialData) {
        if (remoteSocket) return; 
        try {
            remoteSocket = net.connect(DEFAULT_TARGET.port, DEFAULT_TARGET.host, () => {
                logConnection(clientIp, clientPort, localPort, username, 'CONN_START'); 
                const stats = getUserStat(username);
                
                const connectionId = crypto.randomUUID();
                stats.connections.set(clientSocket, {
                    id: connectionId,
                    clientIp: clientIp,
                    startTime: new Date().toISOString(),
                    workerId: WORKER_ID
                });
                
                stats.ip_map.set(clientIp, clientSocket);
                stats.hasChanged = true; // 标记连接数变化
                
                state = 'forwarding';
                
                if (initialData.length > 0) {
                    clientSocket.emit('data', initialData);
                }
                
                // --- Downstream (Download) ---
                remoteSocket.on('data', (data) => {
                    const stats = getUserStat(username);
                    const allowedBytes = stats.bucket_down.consume(data.length);
                    if (allowedBytes === 0) return; 
                    const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
                    stats.traffic_delta.download += dataToWrite.length;
                    stats.traffic_live.download += dataToWrite.length;
                    stats.hasChanged = true; // 标记有流量变化
                    if (clientSocket.writable) {
                        clientSocket.write(dataToWrite);
                    }
                });
                remoteSocket.setKeepAlive(true, 60000);
            });

            remoteSocket.on('error', (err) => {
                if (err.code === 'ECONNREFUSED') {
                    // console.error(`[WSS] Connection refused by target`);
                }
                clientSocket.destroy();
            });

            remoteSocket.on('close', () => {
                clientSocket.end();
            });
        } catch (e) {
            clientSocket.destroy();
        }
    }
}


// --- Internal API Server (Master Process Only) ---
function startInternalApiServer() {
    
    const internalApiSecretMiddleware = (req, res, next) => {
        if (req.headers['x-internal-secret'] === INTERNAL_API_SECRET) {
            next();
        } else {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Forbidden' }));
        }
    };
    
    const server = http.createServer((req, res) => {
        const clientIp = req.socket.remoteAddress;
        if (clientIp !== '127.0.0.1' && clientIp !== '::1' && clientIp !== '::ffff:127.0.0.1') {
             res.writeHead(403, { 'Content-Type': 'application/json' });
             res.end(JSON.stringify({ success: false, message: 'Forbidden' }));
             return;
        }
        
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                if (req.method === 'GET' && req.url === '/stats') {
                    internalApiSecretMiddleware(req, res, () => {
                        // [V9.5 OPT] 移除 Master 聚合 API
                        res.writeHead(501, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, message: 'API /stats is deprecated. Use IPC for real-time aggregation.' }));
                    });
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Not Found' }));
                }
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Internal Server Error' }));
            }
        });
    });

    server.listen(INTERNAL_API_PORT, '127.0.0.1', () => {
        // console.log(`[WSS API] Listening on 127.0.0.1:${INTERNAL_API_PORT}`);
    }).on('error', (err) => {
        console.error(`[CRITICAL] WSS Internal API failed: ${err.message}`);
        process.exit(1);
    });
}


// --- Server Initialization ---
function startServers() {
    loadHostWhitelist();
    setupLogStream();
    connectToIpcServer(); 

    const httpServer = net.createServer((socket) => {
        handleClient(socket, false);
    });
    httpServer.listen(HTTP_PORT, LISTEN_ADDR, () => {
        console.log(`[WSS Worker ${WORKER_ID}] Listening on ${LISTEN_ADDR}:${HTTP_PORT} (HTTP)`);
    }).on('error', (err) => {
        console.error(`[CRITICAL Worker ${WORKER_ID}] HTTP Server failed to start on port ${HTTP_PORT}: ${err.message}`);
        process.exit(1); 
    });

    try {
        if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
            // console.warn(`[WSS Worker ${WORKER_ID}] TLS certificate not found. TLS disabled.`);
            return;
        }
        const tlsOptions = {
            key: fs.readFileSync(KEY_FILE),
            cert: fs.readFileSync(CERT_FILE),
            rejectUnauthorized: false
        };
        const tlsServer = tls.createServer(tlsOptions, (socket) => {
            handleClient(socket, true);
        });
        tlsServer.listen(TLS_PORT, LISTEN_ADDR, () => {
            console.log(`[WSS Worker ${WORKER_ID}] Listening on ${LISTEN_ADDR}:${TLS_PORT} (TLS)`);
        }).on('error', (err) => {
            console.error(`[CRITICAL Worker ${WORKER_ID}] TLS Server failed to start on port ${TLS_PORT}: ${err.message}`);
            process.exit(1); 
        });
    } catch (e) {
        console.error(`[WSS Worker ${WORKER_ID}] TLS setup failed: ${e.message}`);
    }
}

process.on('SIGINT', () => {
    if (logStream) logStream.end();
    if (ipcReconnectTimer) clearTimeout(ipcReconnectTimer);
    if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
    process.exit(0);
});


// --- [AXIOM V3.0] 集群启动逻辑 (重构) ---

if (cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    console.log(`[AXIOM Cluster Master] Master process ${process.pid} is running.`);
    console.log(`[AXIOM Cluster Master] Forking ${numCPUs} worker processes...`);

    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    
    startInternalApiServer();
    
    cluster.on('message', (worker, message) => {
        // [V9.5 OPT] 移除 Master 上的 STATS_RESPONSE 逻辑
    });

    cluster.on('exit', (worker, code, signal) => {
        console.error(`[AXIOM Cluster Master] Worker ${worker.process.pid} died. Forking replacement...`);
        cluster.fork();
    });

} else {
    // This is a worker process
    console.log(`[AXIOM Cluster Worker] Worker ${process.pid} (ID: ${WORKER_ID}) starting...`);
    
    startServers();
    
    process.on('message', (msg) => {
        // [V9.5 OPT] 移除 Master 轮询请求，数据推送改为主动 IPC
    });
    
    process.on('uncaughtException', (err, origin) => {
        console.error(`[AXIOM Cluster Worker ${WORKER_ID}] Uncaught Exception: ${err.message}`, `Origin: ${origin}`);
        process.exit(1); 
    });
}
