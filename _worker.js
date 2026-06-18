// ==========================================
// 全局配置与预设
// ==========================================
const PAGE_SIZE = 30;
const BATCH_SIZE = 50;
const MAX_IPS = 1000; 
const CACHE_TTL = 60;
const STATS_CACHE_KEY = 'cache:stats';
const TASK_TTL = 300; 

const REGIONS = ['HK', '香港', 'TW', '台湾', 'JP', '日本', 'SG', '新加坡', 'KR', '韩国', 'US', '美国'];
const REGION_ORDER = new Map(REGIONS.map((r, i) => [r, i]));
const UNKNOWN_REGION_INDEX = REGIONS.length;
const REGION_PATTERNS = REGIONS.map(r => `(${r})`).join('|');
const COMBINED_REGION_REGEX = new RegExp(REGION_PATTERNS, 'i');
const IP_FORMAT_REGEX = /^(\[[a-fA-F0-9:]+\]|[^:#\[\]]+)(?::(\d+))?(#.*)?$/;

// ==========================================
// 核心工具函数
// ==========================================
const json = (d, s = 200) => Response.json(d, { status: s });
const err = (m, s = 400) => Response.json({ error: m }, { status: s });
const encodeBase64 = (str) => btoa(unescape(encodeURIComponent(str)));
const decodeBase64 = (str) => decodeURIComponent(escape(atob(str)));

// 生成伪装错误节点，让客户端能成功解析并显示报错信息
const createErrorNode = (msg) => {
    return `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=tcp#${encodeURIComponent(msg)}`;
};

const parseIP = (ip) => {
    if (!ip) return { displayIp: '', port: '443', name: '' };
    const match = ip.match(IP_FORMAT_REGEX);
    if (!match) return { displayIp: ip, port: '443', name: '' };
    return {
        displayIp: match[1],
        port: match[2] || '443',
        name: (match[3] || '').slice(1),
    };
};

const extractRegion = (name) => {
    if (!name) return '';
    const match = name.match(COMBINED_REGION_REGEX);
    return match ? match[0].toUpperCase() : '';
};
const getRegionIndex = (region) => region ? (REGION_ORDER.get(region) ?? UNKNOWN_REGION_INDEX) : UNKNOWN_REGION_INDEX;

// ==========================================
// 核心订阅引擎：链接裂变拼接 (Multiplex)
// ==========================================
const multiplexLink = (baseLink, premiumIpRow) => {
    const { displayIp, port, name } = parseIP(premiumIpRow.ip);
    const nodeName = premiumIpRow.name || name || displayIp;

    try {
        if (baseLink.startsWith('vless://') || baseLink.startsWith('trojan://')) {
            const url = new URL(baseLink);
            const originalHost = url.hostname;
            url.hostname = displayIp;
            if (port && port !== 'N/A') url.port = port;
            
            // 直接赋值即可，URL对象会自动处理编码，避免双重编码导致客户端报错
            url.hash = nodeName;
            
            if (!url.searchParams.has('host') && originalHost) url.searchParams.set('host', originalHost);
            if (!url.searchParams.has('sni') && originalHost) url.searchParams.set('sni', originalHost);
            return url.toString();
        } 
        else if (baseLink.startsWith('vmess://')) {
            const b64 = baseLink.slice(8).replace(/-/g, '+').replace(/_/g, '/');
            const config = JSON.parse(decodeBase64(b64));
            if (!config.sni) config.sni = config.add;
            if (!config.host) config.host = config.add;
            config.add = displayIp;
            if (port && port !== 'N/A') config.port = port;
            config.ps = nodeName; 
            return 'vmess://' + encodeBase64(JSON.stringify(config));
        }
    } catch (e) {
        return null;
    }
    return null;
};

// ==========================================
// 数据库与任务缓存管理
// ==========================================
const taskCache = new Map();
const execBatches = async (db, statements) => {
    const len = statements.length;
    if (len === 0) return;
    for (let i = 0; i < len; i += BATCH_SIZE) {
        await db.batch(statements.slice(i, Math.min(i + BATCH_SIZE, len)));
    }
};

const saveTask = async (kv, id, status, msg = '') => {
    const data = { status, message: msg, timestamp: Date.now() };
    taskCache.set(id, data);
    setTimeout(() => taskCache.delete(id), TASK_TTL * 1000);
    if (kv) await kv.put(`task:${id}`, JSON.stringify(data), { expirationTtl: TASK_TTL }).catch(() => {});
};

const getTask = async (kv, id) => {
    const cached = taskCache.get(id);
    if (cached) return cached;
    if (kv) {
        try {
            const data = await kv.get(`task:${id}`, { type: 'json' });
            if (data) { taskCache.set(id, data); return data; }
        } catch {}
    }
    return null;
};

const invalidateCache = async (kv) => { if (kv) await kv.delete(STATS_CACHE_KEY).catch(() => {}); };
const getCachedStats = async (kv) => {
    if (!kv) return null;
    try { return await kv.get(STATS_CACHE_KEY, { type: 'json' }); } catch { return null; }
};
const setCachedStats = async (kv, stats) => { if (kv) await kv.put(STATS_CACHE_KEY, JSON.stringify(stats), { expirationTtl: CACHE_TTL }).catch(() => {}); };

const performIdReorder = async (db, sortedIds) => {
    if (sortedIds.length === 0) return;
    const tempStmts = sortedIds.map((id, i) => db.prepare('UPDATE ips SET id = ? WHERE id = ?').bind(-(i + 1), id));
    const finalStmts = sortedIds.map((_, i) => db.prepare('UPDATE ips SET id = ? WHERE id = ?').bind(i + 1, -(i + 1)));
    await execBatches(db, tempStmts);
    await execBatches(db, finalStmts);
};

// ==========================================
// 后台 API 实现 
// ==========================================
const api = {
    async getIps(db, params) {
        const page = Math.max(1, parseInt(params.get('page')) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(params.get('limit')) || PAGE_SIZE));
        const offset = (page - 1) * limit;
        const needTotal = params.get('needTotal') === 'true';
        const keyword = params.get('keyword') || '';

        let baseQuery = 'FROM ips';
        const bindings = [];
        if (keyword) {
            baseQuery += ' WHERE ip LIKE ? OR name LIKE ?';
            bindings.push(`%${keyword}%`, `%${keyword}%`);
        }

        const queries = [
            db.prepare(`SELECT id, ip, name, active, priority ${baseQuery} ORDER BY id LIMIT ? OFFSET ?`)
              .bind(...bindings, limit, offset)
        ];

        if (needTotal) {
            queries.push(db.prepare(`SELECT COUNT(*) as total ${baseQuery}`).bind(...bindings));
        }

        const results = await db.batch(queries);
        const ips = results[0].results.map(r => {
            const { displayIp, port } = parseIP(r.ip);
            return { ...r, displayIp, port, region: extractRegion(r.name) };
        });

        const pagination = { page, limit };
        if (needTotal) {
            pagination.total = results[1].results[0].total;
            pagination.pages = Math.ceil(pagination.total / limit) || 1;
        }
        return json({ ips, pagination });
    },
    async getStats(db, kv) {
        const cached = await getCachedStats(kv);
        if (cached) return json(cached);
        const { total, active } = await db.prepare('SELECT COUNT(*) as total, SUM(active) as active FROM ips').first();
        const stats = { total, active: active || 0, inactive: total - (active || 0) };
        await setCachedStats(kv, stats);
        return json(stats);
    },
    async getTaskStatus(kv, taskId) {
        const task = await getTask(kv, taskId);
        return task ? json(task) : err('任务不存在或已过期', 404);
    },
    async addIp(db, { ip, priority }, kv) {
        if (!ip) return err('IP不能为空');
        const { displayIp, port, name } = parseIP(ip);
        if (port === 'N/A') return err('IP格式错误');
        
        let prio = priority;
        if (prio === undefined || prio === null) {
            const { n } = await db.prepare('SELECT COALESCE(MAX(priority), 0) + 1 as n FROM ips').first();
            prio = n;
        }

        const { meta } = await db.prepare('INSERT OR IGNORE INTO ips(ip, name, active, priority) VALUES(?, ?, 1, ?)')
            .bind(`${displayIp}:${port}`, name || null, prio).run();

        if (meta.changes === 0) return err('IP已存在');
        await invalidateCache(kv);
        return json({ success: true });
    },
    async batchImport(db, { ips }, ctx, kv) {
        if (!Array.isArray(ips) || !ips.length) return err('列表为空');
        const taskId = crypto.randomUUID();
        ctx.waitUntil((async () => {
            try {
                const parsed = ips.map(ip => {
                    const { displayIp, port, name } = parseIP(ip);
                    return port === 'N/A' ? null : { ip: `${displayIp}:${port}`, name: name || null };
                }).filter(Boolean);
                if (parsed.length === 0) return await saveTask(kv, taskId, 'completed', '没有有效的IP地址');

                const { p } = await db.prepare('SELECT COALESCE(MAX(priority), 0) as p FROM ips').first();
                const stmt = db.prepare('INSERT OR IGNORE INTO ips(ip, name, active, priority) VALUES(?, ?, 1, ?)');
                const batch = parsed.map((item, i) => stmt.bind(item.ip, item.name, p + i + 1));

                await execBatches(db, batch);
                await invalidateCache(kv);
                await saveTask(kv, taskId, 'completed', `成功导入 ${parsed.length} 条数据`);
            } catch (e) { await saveTask(kv, taskId, 'failed', e.message); }
        })());
        return json({ success: true, async: true, taskId, count: ips.length });
    },
    async batchDelete(db, { ips }, ctx, kv) {
        if (!Array.isArray(ips) || !ips.length) return err('列表为空');
        const taskId = crypto.randomUUID();
        ctx.waitUntil((async () => {
            try {
                const deleteIps = ips.map(line => {
                    let targetIp = line.trim();
                    if (targetIp.startsWith('vless://') || targetIp.startsWith('trojan://')) {
                        try {
                            const url = new URL(targetIp);
                            targetIp = `${url.hostname}:${url.port || '443'}`;
                            return targetIp;
                        } catch(e) {}
                    }
                    if (targetIp.startsWith('vmess://')) {
                        try {
                            const b64 = targetIp.slice(8).replace(/-/g, '+').replace(/_/g, '/');
                            const config = JSON.parse(decodeBase64(b64));
                            targetIp = `${config.add}:${config.port || '443'}`;
                            return targetIp;
                        } catch(e) {}
                    }
                    const { displayIp, port } = parseIP(targetIp);
                    return port === 'N/A' ? null : `${displayIp}:${port}`;
                }).filter(Boolean);

                if (deleteIps.length === 0) return await saveTask(kv, taskId, 'completed', '没有识别到有效的节点或IP进行删除');

                const batch = deleteIps.map(ip => db.prepare('DELETE FROM ips WHERE ip=?').bind(ip));
                await execBatches(db, batch);
                await invalidateCache(kv);
                await saveTask(kv, taskId, 'completed', `成功清理了 ${deleteIps.length} 条匹配的数据`);
            } catch (e) { await saveTask(kv, taskId, 'failed', e.message); }
        })());
        return json({ success: true, async: true, taskId, count: ips.length });
    },
    async clearAll(db, ctx, kv) {
        const taskId = crypto.randomUUID();
        ctx.waitUntil((async () => {
            try {
                await db.prepare('DELETE FROM ips').run();
                await invalidateCache(kv);
                await saveTask(kv, taskId, 'completed', '清空完成');
            } catch (e) { await saveTask(kv, taskId, 'failed', e.message); }
        })());
        return json({ success: true, async: true, taskId });
    },
    async toggleAll(db, { active }, ctx, kv) {
        const taskId = crypto.randomUUID();
        ctx.waitUntil((async () => {
            try {
                await db.prepare('UPDATE ips SET active = ?').bind(active ? 1 : 0).run();
                await invalidateCache(kv);
                await saveTask(kv, taskId, 'completed', '更新完成');
            } catch (e) { await saveTask(kv, taskId, 'failed', e.message); }
        })());
        return json({ success: true, async: true, taskId });
    },
    async updateIp(db, id, body, kv) {
        const { active, ip, priority } = body;
        const updates = [];
        if (ip !== undefined) {
            const { displayIp, port, name } = parseIP(ip);
            updates.push(db.prepare('UPDATE ips SET ip=?, name=? WHERE id=?').bind(`${displayIp}:${port}`, name || null, id));
        }
        if (active !== undefined) updates.push(db.prepare('UPDATE ips SET active=? WHERE id=?').bind(active ? 1 : 0, id));
        if (priority !== undefined) updates.push(db.prepare('UPDATE ips SET priority = ? WHERE id = ?').bind(priority, id));
        if (updates.length > 0) { await db.batch(updates); await invalidateCache(kv); }
        return json({ success: true });
    },
    async deleteIp(db, id, kv) {
        await db.prepare('DELETE FROM ips WHERE id=?').bind(id).run();
        await invalidateCache(kv);
        return json({ success: true });
    },
    async sortIps(db, ctx, kv) {
        const taskId = crypto.randomUUID();
        ctx.waitUntil((async () => {
            try {
                const { results } = await db.prepare('SELECT id, ip, name, priority FROM ips').all();
                const parsed = results.map(r => ({ ...r, region: extractRegion(r.name) }));
                parsed.sort((a, b) => getRegionIndex(a.region) - getRegionIndex(b.region) || a.priority - b.priority || a.id - b.id);
                await performIdReorder(db, parsed.map(s => s.id));
                await invalidateCache(kv);
                await saveTask(kv, taskId, 'completed', '排序完成');
            } catch (e) { await saveTask(kv, taskId, 'failed', e.message); }
        })());
        return json({ success: true, async: true, taskId });
    },
    async removeDuplicates(db, ctx, kv) {
        const taskId = crypto.randomUUID();
        ctx.waitUntil((async () => {
            try {
                const { results } = await db.prepare(`SELECT GROUP_CONCAT(id) as ids FROM ips GROUP BY SUBSTR(ip, 1, INSTR(ip, ':') - 1) HAVING COUNT(*) > 1`).all();
                const deleteIds = results.flatMap(r => r.ids.split(',').map(Number).sort((a, b) => a - b).slice(1));
                const batch = deleteIds.map(id => db.prepare('DELETE FROM ips WHERE id = ?').bind(id));
                await execBatches(db, batch);
                await invalidateCache(kv);
                await saveTask(kv, taskId, 'completed', `清理了 ${deleteIds.length} 条重复数据`);
            } catch (e) { await saveTask(kv, taskId, 'failed', e.message); }
        })());
        return json({ success: true, async: true, taskId });
    }
};

const handleApiRoute = async (req, db, ctx, kv) => {
    const url = new URL(req.url);
    const path = url.pathname.slice(4);
    const method = req.method;
    try {
        const body = (method === 'POST' || method === 'PUT') ? await req.json().catch(() => ({})) : {};
        
        // --- 【新增】处理短链生成的 API ---
        if (path === '/shorten' && method === 'POST') {
            const { longUrl } = body;
            if (!longUrl) return err('链接不能为空');
            // 生成 6 位随机短码
            const shortId = Math.random().toString(36).substring(2, 8);
            if (kv) {
                await kv.put(`short:${shortId}`, longUrl);
                return json({ success: true, shortId });
            }
            return err('未绑定 KV 空间', 500);
        }

        if (path === '/ips' && method === 'GET') return api.getIps(db, url.searchParams);
        if (path === '/ips' && method === 'POST') return api.addIp(db, body, kv);
        if (path === '/ips/stats') return api.getStats(db, kv);
        if (path === '/ips/batch') return api.batchImport(db, body, ctx, kv);
        if (path === '/ips/batch-delete') return api.batchDelete(db, body, ctx, kv);
        if (path === '/ips/clear' && method === 'DELETE') return api.clearAll(db, ctx, kv);
        if (path === '/ips/toggle-all') return api.toggleAll(db, body, ctx, kv);
        if (path === '/ips/sort') return api.sortIps(db, ctx, kv);
        if (path === '/ips/remove-duplicates') return api.removeDuplicates(db, ctx, kv);
        if (path.startsWith('/task/')) return api.getTaskStatus(kv, path.slice(6));
        
        const idMatch = path.match(/^\/ips\/(\d+)$/);
        if (idMatch) {
            if (method === 'PUT') return api.updateIp(db, idMatch[1], body, kv);
            if (method === 'DELETE') return api.deleteIp(db, idMatch[1], kv);
        }
        return new Response('Not Found', { status: 404 });
    } catch (e) { return err(e.message, 500); }
};

// ==========================================
// 前端 HTML: 公开生成页面 (手机端适配版)
// ==========================================
const getPublicHTML = () => `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>灵鹿优选</title>
<link rel="icon" sizes="56x56" href="https://pan.ling-lu-02.ccwu.cc/raw/------/2.jpg">
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { 
    background: #0a0a1a; 
    min-height: 100vh; 
    display: flex; 
    align-items: center; 
    justify-content: center; 
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
    padding: 16px; 
}
body::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: radial-gradient(ellipse at 50% 0%, #1a1a3e 0%, #0a0a1a 70%);
    z-index: -1;
}
.card { 
    background: rgba(255,255,255,0.05); 
    backdrop-filter: blur(20px); 
    -webkit-backdrop-filter: blur(20px); 
    padding: 24px 20px; 
    border-radius: 24px; 
    width: 100%; 
    max-width: 440px; 
    box-shadow: 0 20px 60px rgba(0,0,0,0.6); 
    border: 1px solid rgba(255,255,255,0.08); 
}
.avatar { 
    width: 64px; 
    height: 64px; 
    border-radius: 50%; 
    margin: 0 auto 16px; 
    display: flex; 
    align-items: center; 
    justify-content: center; 
    overflow: hidden; 
    border: 2px solid rgba(255,255,255,0.1);
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}
.avatar img { width: 100%; height: 100%; object-fit: cover; }
h1 { 
    font-size: 22px; 
    text-align: center; 
    margin-bottom: 28px; 
    font-weight: 600; 
    letter-spacing: 0.5px; 
    background: linear-gradient(135deg, #60a5fa, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.form-group { margin-bottom: 16px; }
label { 
    display: block; 
    font-size: 13px; 
    margin-bottom: 6px; 
    color: #94a3b8; 
    font-weight: 500; 
}
input, select { 
    width: 100%; 
    padding: 14px 16px; 
    background: rgba(0,0,0,0.4); 
    border: 1px solid rgba(255,255,255,0.08); 
    border-radius: 12px; 
    color: #f1f5f9; 
    font-size: 15px; 
    transition: all 0.3s ease; 
    -webkit-appearance: none;
    appearance: none;
}
input:focus, select:focus { 
    outline: none; 
    border-color: #3b82f6; 
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); 
    background: rgba(0,0,0,0.6); 
}
input::placeholder { color: #64748b; }
select { 
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%2394a3b8' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 16px center;
    padding-right: 40px;
}
select option { color: #000; background: #1e293b; }
button { 
    width: 100%; 
    padding: 14px; 
    background: linear-gradient(135deg, #3b82f6, #6366f1); 
    color: #fff; 
    border: none; 
    border-radius: 12px; 
    font-size: 16px; 
    font-weight: 600; 
    cursor: pointer; 
    transition: all 0.3s; 
    margin-top: 4px;
}
button:hover { transform: translateY(-1px); box-shadow: 0 8px 30px rgba(59, 130, 246, 0.3); }
button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; }
#subResult { 
    background: rgba(0,0,0,0.5); 
    color: #60a5fa; 
    font-size: 14px; 
    cursor: pointer; 
    padding: 14px 16px;
    border-radius: 12px;
    border: 1px solid rgba(96, 165, 250, 0.2);
    word-break: break-all;
}
.footer { 
    margin-top: 24px; 
    text-align: center; 
    font-size: 12px; 
    color: #64748b; 
    line-height: 1.8; 
}
.tg-link { color: #60a5fa; text-decoration: none; font-weight: 500; }
.tg-link:hover { text-decoration: underline; }
#qrWrap { display: none; justify-content: center; margin-top: 20px; }
#qrCodeBox { background: #fff; padding: 12px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
#qrCodeBox img { display: block; }

/* 手机端特殊优化 */
@media (max-width: 480px) {
    body { padding: 12px; }
    .card { padding: 20px 16px; border-radius: 20px; }
    h1 { font-size: 20px; margin-bottom: 24px; }
    input, select { padding: 12px 14px; font-size: 16px; } /* 防止 iOS 自动缩放 */
    button { padding: 14px; font-size: 15px; }
    .avatar { width: 56px; height: 56px; }
}

/* 针对 iOS 安全区域 */
@supports (padding: max(0px)) {
    body { padding-left: max(16px, env(safe-area-inset-left)); padding-right: max(16px, env(safe-area-inset-right)); }
}
</style>
</head>
<body>
<div class="card">
    <div class="avatar"><img src="https://pan.ling-lu-02.ccwu.cc/raw/------/2.jpg" alt="Logo"></div>
    <h1>灵鹿の优选订阅</h1>
    
    <div class="form-group">
        <label>基础节点链接</label>
        <input type="text" id="nodeLink" placeholder="请输入 VMess / VLESS / Trojan 链接" autocomplete="off">
    </div>

    <div class="form-group">
        <label>优选 IP 来源</label>
        <select id="ipSource" onchange="toggleExtInput()">
            <option value="local">本地私有优选库 (高稳定)</option>
            <option value="ext">外部公开优选库 (实时拉取)</option>
        </select>
    </div>

    <div class="form-group" id="extUrlGroup" style="display: none;">
        <label>外部优选库接口 (API 或 TXT)</label>
        <select id="extUrlSelect" onchange="document.getElementById('extUrl').value = this.value" style="margin-bottom: 8px;">
            <option value="https://cf.junzhen.qzz.io/best_ips_bj.txt">📶 动态测速 API - 电信优先</option>
            <option value="https://cf.junzhen.qzz.io/best_ips.txt">📶 动态测速 API - 联通优先</option>
            <option value="https://raw.githubusercontent.com/svip-s/cloudflare_ip/refs/heads/main/best_ips.txt">📶 动态测速 API - 移动优先</option>
            <option value="https://bestcf.pages.dev/luoli/all.txt">🌐 动态测速 API - 通用官方</option>
            <option value="https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt">📦 静态 TXT 库 - cmliu (备用)</option>
            <option value="https://raw.githubusercontent.com/xiagefei/CFBestIP/refs/heads/main/addressesapi.txt">📦 红星优选库 (主力)</option>
            <option value="">✍️ 自定义：清空并手动输入链接...</option>
        </select>
        <input type="text" id="extUrl" placeholder="请选择上方接口或粘贴你的链接..." value="https://api.example.com/ct?ips=6" autocomplete="off">
    </div>

    <div class="form-group">
        <label>
            安全 Token (必填!)
            <a href="https://t.me/lingluai" target="_blank" style="font-size: 12px; color: #60a5fa; font-weight: 400; margin-left: 6px; text-decoration: none;">(sub-token:9527)</a>
        </label>
        <input type="password" id="subToken" placeholder="请输入变量设置的sub-token" autocomplete="off">
    </div>

    <button onclick="generateSub()" id="genBtn">生成优选短链</button>
    
    <div class="form-group" style="margin-top: 20px;">
        <label>您的专属订阅 ❗</label>
        <input type="text" id="subResult" placeholder="点击生成后自动出现" readonly onclick="copyLink()">
    </div>
    
    <div id="qrWrap">
        <div id="qrCodeBox"></div>
    </div>

    <div class="footer">
        支持: <a href="https://t.me/lingluai" target="_blank" class="tg-link">加入TG群组</a> - 由 灵鹿优选 维护 &copy; 2026
    </div>
</div>
<script>
function toggleExtInput() {
    const val = document.getElementById('ipSource').value;
    document.getElementById('extUrlGroup').style.display = val === 'ext' ? 'block' : 'none';
}

async function generateSub() {
    const link = document.getElementById('nodeLink').value.trim();
    const token = document.getElementById('subToken').value.trim();
    const source = document.getElementById('ipSource').value;
    const extUrl = document.getElementById('extUrl').value.trim();

    if (!link) { alert('哎呀，你还没有填入节点链接哦！'); return; }
    if (source === 'ext' && !extUrl) { alert('请填写外部优选链接！'); return; }

    const btn = document.getElementById('genBtn');
    btn.innerText = "生成中..."; btn.disabled = true;
    
    let subParams = '/sub?base=' + encodeURIComponent(link);
    if(token) subParams += '&token=' + encodeURIComponent(token);
    if(source === 'ext') subParams += '&source=ext&ext_url=' + encodeURIComponent(extUrl);
    
    try {
        const res = await fetch('/api/shorten', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ longUrl: subParams })
        });
        const data = await res.json();

        if (data.success) {
            const shortUrl = window.location.origin + '/s/' + data.shortId;
            document.getElementById('subResult').value = shortUrl;
            
            const qrWrap = document.getElementById('qrWrap');
            const qrCodeBox = document.getElementById('qrCodeBox');
            qrCodeBox.innerHTML = ''; 
            qrWrap.style.display = 'flex'; 
            
            new QRCode(qrCodeBox, {
                text: shortUrl, width: 160, height: 160,
                colorDark : "#000000", colorLight : "#ffffff",
                correctLevel : QRCode.CorrectLevel.M
            });
        } else {
            alert('生成短链失败: ' + (data.error || '未知错误'));
            document.getElementById('subResult').value = window.location.origin + subParams;
        }
    } catch (e) {
        alert('网络请求失败，请检查控制台。');
        document.getElementById('subResult').value = window.location.origin + subParams;
    } finally {
        btn.innerText = "生成优选短链"; 
        btn.disabled = false;
    }
}

function copyLink() {
    const res = document.getElementById('subResult');
    if(res.value) { 
        res.select(); 
        document.execCommand('copy'); 
        alert('✅ 订阅链接已复制！');
    }
}
</script>
</body>
</html>`;

// ==========================================
// 前端 HTML: 后台优选 IP 管理面板 (手机端适配版)
// ==========================================
const getAdminHTML = () => `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>优选 IP 管理后台</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#1c2333;--fg:#e6edf3;--fg2:#8b949e;--border:#30363d;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--purple:#a371f7;--radius:12px;}
*{margin:0;padding:0;box-sizing:border-box}
body{font:15px/1.6 -apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh;padding:12px}
.container{max-width:1200px;margin:0 auto;padding:12px 8px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
h1{font-size:24px;background:linear-gradient(135deg,var(--blue),var(--purple));-webkit-background-clip:text;color:transparent;margin:0}
.back-btn{color:var(--blue);text-decoration:none;font-weight:bold;font-size:14px}
.section{background:var(--bg2);border-radius:var(--radius);padding:16px;margin-bottom:16px;border:1px solid var(--border)}
h2{font-size:16px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
h2::before{content:'';width:3px;height:14px;background:var(--blue);border-radius:2px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
.stat{background:var(--bg3);padding:16px;border-radius:var(--radius);text-align:center;border:1px solid var(--border)}
.stat-num{font-size:24px;font-weight:bold;color:var(--blue)}
.stat-label{font-size:13px;color:var(--fg2);margin-top:4px}
input,textarea{width:100%;padding:12px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--fg);font-size:15px;margin-bottom:12px;font-family:inherit}
input:focus,textarea:focus{outline:none;border-color:var(--blue)}
textarea{min-height:80px;resize:vertical}
button{background:var(--blue);color:#fff;border:none;padding:10px 18px;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;transition:opacity 0.2s;min-height:44px}
button:hover{opacity:0.85}
button:disabled{opacity:0.5;cursor:not-allowed}
button.danger{background:var(--red)}
button.sec{background:var(--bg3);color:var(--fg);border:1px solid var(--border)}
button.page-btn{padding:8px 14px;margin:0;min-height:36px;font-size:13px}
button.page-btn.active{background:var(--blue);color:#fff;border-color:var(--blue);cursor:default}
.ip-list{list-style:none}
.ip-item{display:flex;flex-direction:column;padding:14px 16px;background:var(--bg3);border:1px solid var(--border);margin-bottom:8px;border-radius:8px;gap:10px}
.ip-address{font-family:monospace;font-size:15px;color:var(--fg);word-break:break-all}
.ip-meta{font-size:13px;color:var(--fg2);display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.tag{background:rgba(88,166,255,0.12);color:var(--blue);padding:2px 10px;border-radius:12px;font-size:12px}
.action-buttons{display:flex;gap:8px;flex-wrap:wrap}
.action-buttons button{flex:1;min-width:80px;text-align:center}
.status-text.active{color:var(--green)}
.status-text.inactive{color:var(--red)}
.search-box{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.search-box input{flex:1;min-width:120px;margin-bottom:0}
.page-badge{color:var(--fg2);font-size:13px;background:var(--bg3);padding:4px 14px;border-radius:16px;border:1px solid var(--border)}
#pagination{display:flex;justify-content:center;gap:6px;flex-wrap:wrap;margin-top:20px;align-items:center}
#msg{color:var(--green);margin-top:10px;font-weight:bold;font-size:14px;min-height:24px}
#editModal{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);align-items:center;justify-content:center;z-index:1000;padding:16px;backdrop-filter:blur(4px)}
#editModal>div{background:var(--bg2);border-radius:var(--radius);padding:20px;width:100%;max-width:380px;border:1px solid var(--border)}
#editModal h2{font-size:18px;margin-top:0}

/* 手机端优化 */
@media (max-width: 480px) {
    body{padding:8px}
    .container{padding:8px 4px}
    .header h1{font-size:20px}
    .stats{grid-template-columns:1fr 1fr;gap:8px}
    .stat{padding:12px}
    .stat-num{font-size:20px}
    .section{padding:12px}
    .action-buttons button{flex:1;min-width:60px;font-size:13px;padding:8px 12px}
    .ip-item{padding:12px 14px}
    .ip-address{font-size:14px}
    button.page-btn{padding:6px 10px;font-size:12px;min-height:32px}
    #pagination{gap:4px}
    input,textarea{font-size:16px;padding:10px 12px} /* 防止 iOS 缩放 */
}
@media (max-width: 360px) {
    .stats{grid-template-columns:1fr 1fr}
    .header{flex-direction:column;align-items:flex-start}
    .action-buttons button{font-size:12px;padding:6px 10px;min-width:50px}
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>优选 IP 库管理</h1>
        <a href="/" class="back-btn">&larr; 返回首页</a>
    </div>

    <div class="stats">
        <div class="stat"><div class="stat-num" id="total">-</div><div class="stat-label">总优选IP</div></div>
        <div class="stat"><div class="stat-num" id="active">-</div><div class="stat-label">活跃中</div></div>
    </div>

    <div class="section">
        <h2>批量操作</h2>
        <textarea id="batchIps" rows="4" placeholder="格式: IP:端口#国家 (例如 104.16.2.3:443#美国)&#10;每行一个。删除时粘贴IP或节点链接即可。"></textarea>
        <div class="action-buttons">
            <button onclick="batchImport()">批量导入</button>
            <button class="danger" onclick="batchDelete()">删除指定</button>
            <button class="danger" style="background:#8b0000;" onclick="clearAll()">清空全部</button>
        </div>
    </div>

    <div class="section">
        <h2>操作面板</h2>
        <div class="search-box">
            <input id="searchInput" placeholder="搜索IP或名称...">
            <button class="sec" style="flex:0 0 auto;" onclick="clearSearch()">显示全部</button>
        </div>
        <div class="action-buttons">
            <button class="sec" onclick="sortIps()">按地区排序</button>
            <button class="sec" onclick="removeDuplicates()">去重</button>
            <button class="sec" style="color:var(--green)" onclick="toggleAll(1)">全部启用</button>
            <button class="sec" style="color:var(--red)" onclick="toggleAll(0)">全部禁用</button>
        </div>
        <div id="msg"></div>
    </div>

    <div class="section">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">
            <h2 style="margin:0;">IP 列表</h2>
            <div class="page-badge">第 <strong id="page" style="color:var(--blue)">1</strong> / <strong id="totalPages" style="color:var(--blue)">1</strong> 页</div>
        </div>
        <div class="ip-list" id="list">加载中...</div>
        <div id="pagination"></div>
    </div>
</div>

<div id="editModal" onclick="if(event.target===this)closeEdit()">
    <div>
        <h2>编辑节点</h2>
        <input id="editId" type="hidden">
        <label style="display:block;font-size:13px;color:var(--fg2);margin-bottom:4px;">IP 和 端口</label>
        <input id="editIp" placeholder="例如 104.16.2.3:443">
        <label style="display:block;font-size:13px;color:var(--fg2);margin-bottom:4px;">备注名称</label>
        <input id="editName" placeholder="例如 香港优选 (选填)">
        <label style="display:block;font-size:13px;color:var(--fg2);margin-bottom:4px;">排序权重</label>
        <input id="editPriority" type="number" placeholder="数字越小越靠前">
        <div style="display:flex;gap:10px;margin-top:16px">
            <button style="flex:1;" onclick="saveEdit()">保存</button>
            <button style="flex:1;" class="sec" onclick="closeEdit()">取消</button>
        </div>
    </div>
</div>

<script>
let page = 1;
let totalPages = 1;
let currentKeyword = '';
let searchTimeout = null;

const $ = id => document.getElementById(id);
const msg = t => { $('msg').innerText = t; setTimeout(() => $('msg').innerText='', 3000) };
const api = async (p, o={}) => { const r = await fetch('/api'+p, {headers:{'Content-Type':'application/json'}, ...o}); return r.json(); };

$('searchInput').addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => { currentKeyword = e.target.value.trim(); page = 1; load(); }, 500); 
});

const clearSearch = () => { $('searchInput').value = ''; currentKeyword = ''; page = 1; load(); };

const load = async () => {
    const query = new URLSearchParams({ page, needTotal: 'true' });
    if (currentKeyword) query.append('keyword', currentKeyword);

    try {
        const [stats, res] = await Promise.all([api('/ips/stats'), api('/ips?' + query.toString())]);
        
        $('total').innerText = stats.total || 0; 
        $('active').innerText = stats.active || 0;
        totalPages = res.pagination?.pages || 1;
        $('page').innerText = page; 
        $('totalPages').innerText = totalPages;

        if (res.ips && res.ips.length > 0) {
            $('list').innerHTML = res.ips.map(ip => \`
                <li class="ip-item">
                    <div>
                        <div class="ip-address">\${ip.displayIp}:\${ip.port}</div>
                        <div class="ip-meta">
                            \${ip.name ? '<span class="tag">'+ip.name+'</span>' : ''}
                            <span class="status-text \${ip.active ? 'active' : 'inactive'}">\${ip.active?'启用中':'已禁用'}</span>
                        </div>
                    </div>
                    <div class="action-buttons" style="width:100%;">
                        <button class="sec" onclick="openEdit(\${ip.id}, '\${ip.displayIp}', '\${ip.port}', '\${ip.name || ''}', \${ip.priority || 0})">编辑</button>
                        <button class="sec" onclick="toggleIp(\${ip.id}, \${ip.active})">\${ip.active?'禁用':'启用'}</button>
                        <button class="danger" onclick="del(\${ip.id})">删除</button>
                    </div>
                </li>
            \`).join('');
        } else {
            $('list').innerHTML = '<div style="text-align:center;color:var(--fg2);padding:30px;">'+(currentKeyword?'没有搜索到匹配的节点':'暂无数据')+'</div>';
        }
        renderPagination();
    } catch (e) {
        $('list').innerHTML = '<div style="text-align:center;color:var(--red);padding:20px;">加载失败，请刷新重试</div>';
    }
};

const renderPagination = () => {
    let html = \`<button class="sec page-btn" \${page === 1 ? 'disabled' : \`onclick="goToPage(\${page-1})"\`}>上一页</button>\`;
    let start = Math.max(1, page - 2);
    let end = Math.min(totalPages, page + 2);
    if (start > 1) {
        html += \`<button class="sec page-btn" onclick="goToPage(1)">1</button>\`;
        if (start > 2) html += \`<span style="color:var(--fg2);padding:0 4px;">...</span>\`;
    }
    for (let i = start; i <= end; i++) {
        if (i === page) html += \`<button class="page-btn active">\${i}</button>\`;
        else html += \`<button class="sec page-btn" onclick="goToPage(\${i})">\${i}</button>\`;
    }
    if (end < totalPages) {
        if (end < totalPages - 1) html += \`<span style="color:var(--fg2);padding:0 4px;">...</span>\`;
        html += \`<button class="sec page-btn" onclick="goToPage(\${totalPages})">\${totalPages}</button>\`;
    }
    html += \`<button class="sec page-btn" \${page === totalPages ? 'disabled' : \`onclick="goToPage(\${page+1})"\`}>下一页</button>\`;
    $('pagination').innerHTML = html;
};

const goToPage = (p) => { page = p; load(); };
const poll = (id, cb) => {
    const t = setInterval(async () => {
        try {
            const res = await api('/task/'+id);
            if(res.status === 'completed' || res.status === 'failed') {
                clearInterval(t); 
                msg(res.message || (res.status === 'completed' ? '操作完成' : '操作失败')); 
                if(cb) cb();
            }
        } catch(e) { clearInterval(t); }
    }, 1000);
};

const toggleIp = async (id, currentStatus) => { 
    await api('/ips/'+id, {method:'PUT', body:JSON.stringify({active: currentStatus ? 0 : 1})}); 
    load(); 
};

const openEdit = (id, ip, port, name, priority) => { 
    $('editId').value = id; 
    $('editIp').value = ip + ':' + port; 
    $('editName').value = name; 
    $('editPriority').value = priority; 
    $('editModal').style.display = 'flex'; 
};

const closeEdit = () => { $('editModal').style.display = 'none'; };

const saveEdit = async () => {
    const id = $('editId').value;
    const ipStr = $('editIp').value.trim();
    const nameStr = $('editName').value.trim();
    const priorityVal = parseInt($('editPriority').value);

    if(!ipStr) return msg('IP不能为空');
    let fullIP = ipStr; 
    if(nameStr) fullIP += '#' + nameStr;

    const updateBody = { ip: fullIP };
    if (!isNaN(priorityVal)) updateBody.priority = priorityVal; 

    try { 
        await api('/ips/'+id, {method:'PUT', body:JSON.stringify(updateBody)}); 
        msg('修改成功'); 
        closeEdit(); 
        load(); 
    } catch(e) { 
        msg('修改失败'); 
    }
};

const del = async (id) => { 
    if(confirm('确定要彻底删除此IP吗？')) { 
        await api('/ips/'+id, {method:'DELETE'}); 
        load(); 
    } 
};

const toggleAll = async (active) => { 
    if(!confirm(active ? '确定将所有节点设为启用吗？' : '确定将所有节点设为禁用吗？')) return; 
    const res = await api('/ips/toggle-all', {method:'POST', body:JSON.stringify({active})}); 
    msg('操作执行中...'); 
    poll(res.taskId, load); 
};

const batchImport = async () => { 
    const ips = $('batchIps').value.split('\\n').filter(Boolean); 
    if(!ips.length) { msg('请先在输入框填写 IP'); return; } 
    const res = await api('/ips/batch', {method:'POST', body:JSON.stringify({ips})}); 
    msg('导入任务已启动...'); 
    $('batchIps').value = ''; 
    poll(res.taskId, load); 
};

const batchDelete = async () => { 
    const ips = $('batchIps').value.split('\\n').filter(Boolean); 
    if(!ips.length) { msg('请先在输入框填写要删除的 IP 或节点链接'); return; } 
    if(!confirm('确定要删除上面填写的节点对应的 IP 吗？')) return; 
    const res = await api('/ips/batch-delete', {method:'POST', body:JSON.stringify({ips})}); 
    msg('批量删除任务已启动...'); 
    $('batchIps').value = ''; 
    poll(res.taskId, load); 
};

const clearAll = async () => { 
    if(!confirm('警告：确定清空所有优选IP吗？此操作不可逆！')) return; 
    const res = await api('/ips/clear', {method:'DELETE'}); 
    msg('清空任务启动...'); 
    poll(res.taskId, () => { page=1; load(); }); 
};

const sortIps = async () => { 
    const res = await api('/ips/sort', {method:'POST'}); 
    msg('排序中...'); 
    poll(res.taskId, load); 
};

const removeDuplicates = async () => { 
    const res = await api('/ips/remove-duplicates', {method:'POST'}); 
    msg('去重中...'); 
    poll(res.taskId, load); 
};

load();
</script>
</body>
</html>`;

// ==========================================
// 密码验证核心逻辑 (Basic Auth)
// ==========================================
const checkAuth = (req, env) => {
    const expectedPassword = env.ADMIN_PASSWORD;
    if (!expectedPassword) return true;

    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return false;

    const [scheme, encoded] = authHeader.split(' ');
    if (scheme !== 'Basic' || !encoded) return false;

    try {
        const decoded = atob(encoded);
        const [username, password] = decoded.split(':');
        if (password === expectedPassword) return true;
    } catch (e) {
        return false;
    }
    return false;
};

// ==========================================
// 主路由引擎
// ==========================================
export default {
    async fetch(req, env, ctx) {
        const url = new URL(req.url);
        const path = url.pathname;

        // --- 【新增】处理短链跳转 (公开接口，无密码拦截) ---
        if (path.startsWith('/s/')) {
            const shortId = path.slice(3); // 截取 /s/ 后面的字符
            if (env.TASK_KV) {
                const longUrl = await env.TASK_KV.get(`short:${shortId}`);
                if (longUrl) {
                    // 使用 302 重定向到真实的 /sub 长链接，并将原长链自动拼在域名后
                    return Response.redirect(new URL(longUrl, url.origin).toString(), 302);
                }
            }
            return new Response('❌ 短链接无效或已过期', { status: 404, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
        }

        // 安全拦截区
        if (path === '/admin' || path.startsWith('/api/')) {
            // 放行公开的 /api/shorten 接口，避免前端无法生成短链
            if (path !== '/api/shorten' && !checkAuth(req, env)) {
                return new Response('Unauthorized', {
                    status: 401,
                    headers: { 'WWW-Authenticate': 'Basic realm="Admin Access Requires Password"' }
                });
            }
        }

        if (path === '/') {
            return new Response(getPublicHTML(), {
                headers: { 'Content-Type': 'text/html;charset=utf-8' }
            });
        }

        if (path === '/admin') {
            return new Response(getAdminHTML(), {
                headers: { 'Content-Type': 'text/html;charset=utf-8' }
            });
        }

        // --- /sub 接口：终极防爆修复版 ---
        if (path === '/sub') {
            const baseLink = url.searchParams.get('base');
            const reqToken = url.searchParams.get('token');
            const source = url.searchParams.get('source'); 
            const extUrl = url.searchParams.get('ext_url');

            // 1. Token 校验
            const expectedToken = env.SUB_TOKEN;
            if (expectedToken && reqToken !== expectedToken) {
                return new Response(encodeBase64(createErrorNode('❌ Token 验证失败，请检查链接参数')), { 
                    headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-cache' } 
                });
            }

            if (!baseLink) return new Response(encodeBase64(createErrorNode('❌ 请在首页输入基础节点链接')), {
                headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-cache' }
            });

            // 2. 缓存读取
            const cache = caches.default;
            const cacheKey = new Request(url.toString(), req); 
            let res = await cache.match(cacheKey);
            if (res) return res;

            let ipRows = [];

            // 3. 获取数据源
            if (source === 'ext' && extUrl) {
                try {
                    // 加上 User-Agent 伪装，防止被部分外部链接的防火墙拦截
                    const extRes = await fetch(extUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }});
                    if (!extRes.ok) throw new Error(`HTTP状态码异常: ${extRes.status}`);
                    
                    const extText = await extRes.text();
                    
                    // 防御检查：如果拉取到的内容是 HTML（比如防CC盾、404网页），直接报错，防止生成无效节点
                    if (extText.trim().startsWith('<')) {
                        throw new Error('获取到的是网页而非纯文本列表，可能是链接失效或触发了防CC拦截');
                    }

                    const lines = extText.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
                    ipRows = lines.map(line => {
                        const { displayIp, port, name } = parseIP(line);
                        return { 
                            ip: port === 'N/A' ? displayIp : `${displayIp}:${port}`, 
                            name: name || '外网优选节点' 
                        };
                    }).filter(r => r.ip);
                } catch (e) {
                    // 核心修复：如果是外部拉取报错，返回一个伪装的 VLESS 节点，将错误原因直接显示在客户端列表里！
                    return new Response(encodeBase64(createErrorNode(`❌ 外部优选库拉取失败: ${e.message}`)), {
                        headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-cache' }
                    });
                }
            } else {
                const { results } = await env.DB.prepare(
                    'SELECT ip, name FROM ips WHERE active=1 ORDER BY priority, id LIMIT ?'
                ).bind(MAX_IPS).all();
                ipRows = results;
            }

            // 4. 合并裂变
            const generatedLinks = ipRows
                .map(row => multiplexLink(baseLink, row))
                .filter(Boolean)
                .join('\n');

            // 5. 兜底检查
            const finalOutput = generatedLinks || createErrorNode('❌ 没有生成任何可用节点(可能是基础节点格式不兼容或无优选IP)');

            res = new Response(encodeBase64(finalOutput), {
                headers: {
                    'Content-Type': 'text/plain;charset=utf-8',
                    'Cache-Control': `public, max-age=${CACHE_TTL}`
                }
            });

            ctx.waitUntil(cache.put(cacheKey, res.clone()));
            return res;
        }

        if (path.startsWith('/api/')) {
            return handleApiRoute(req, env.DB, ctx, env.TASK_KV);
        }

        return new Response('Not Found', { status: 404 });
    },
};
