/**
 * 灯雪镇 Cloudflare Workers - 零依赖版本
 * 纯 fetch + Web Crypto，无需 npm install
 */

function cors() {
    return {
        'Access-Control-Allow-Origin': 'https://tr114512.github.io',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'X-Content-Type-Options': 'nosniff'
    };
}
function json(data, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: { ...cors(), 'Content-Type': 'application/json; charset=utf-8' } });
}

// Supabase REST 调用
function supabaseAPI(env, path, opts = {}) {
    return fetch(`${env.SUPABASE_URL}/rest/v1${path}`, {
        ...opts,
        headers: { 'apikey': env.SUPABASE_SERVICE_ROLE_KEY, 'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type': 'application/json', ...opts.headers }
    });
}
async function supabaseAuthAdmin(env, path, opts = {}) {
    return fetch(`${env.SUPABASE_URL}/auth/v1/admin${path}`, {
        ...opts,
        headers: { 'apikey': env.SUPABASE_SERVICE_ROLE_KEY, 'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type': 'application/json', ...opts.headers }
    });
}
async function supabaseAuth(env, path, opts = {}) {
    return fetch(`${env.SUPABASE_URL}/auth/v1${path}`, {
        ...opts,
        headers: { 'apikey': env.SUPABASE_SERVICE_ROLE_KEY, 'Content-Type': 'application/json', ...opts.headers }
    });
}
async function listUsers(env, page = 1, perPage = 500) {
    const r = await supabaseAuthAdmin(env, `/users?page=${page}&per_page=${perPage}`);
    return r.ok ? await r.json() : { users: [] };
}
async function getUser(env, userId) {
    const r = await supabaseAuthAdmin(env, `/users/${userId}`);
    return r.ok ? await r.json() : null;
}
async function deleteUser(env, userId) {
    return supabaseAuthAdmin(env, `/users/${userId}`, { method: 'DELETE' });
}
async function updateUser(env, userId, data) {
    return supabaseAuthAdmin(env, `/users/${userId}`, { method: 'PUT', body: JSON.stringify(data) });
}
async function createUser(env, data) {
    return supabaseAuthAdmin(env, '/users', { method: 'POST', body: JSON.stringify(data) });
}

// ===== JWT (Web Crypto) =====
function b64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}
async function signJWT(payload, secret) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const h = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
    const b = b64url(enc.encode(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 })));
    const s = b64url(await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${b}`)));
    return `${h}.${b}.${s}`;
}
async function verifyJWT(token, secret) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('invalid');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('HMAC', key, b64urlDecode(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
    if (!ok) throw new Error('invalid');
    return JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
}

// ===== 角色 =====
function nr(role) { return (role === 'super_admin' || role === 'admin') ? 'admin' : 'user'; }
async function getUserRole(env, userId, email) {
    try { const u = await getUser(env, userId); if (u?.user_metadata?.role) return nr(u.user_metadata.role); } catch (_) { }
    try { const r = await supabaseAPI(env, `/profiles?id=eq.${userId}&select=role`); const d = await r.json(); if (d?.[0]?.role) return nr(d[0].role); } catch (_) { }
    const admins = (env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase());
    return admins.includes((email || '').toLowerCase()) ? 'admin' : 'user';
}
async function requireRole(env, req, minRole) {
    const auth = req.headers.get('Authorization');
    if (!auth) return null;
    try {
        const tok = auth.split(' ')[1];
        const dec = await verifyJWT(tok, env.JWT_SECRET);
        const role = await getUserRole(env, dec.id, dec.email);
        return ({ admin: 1, user: 0 })[role] >= ({ admin: 1, user: 0 })[minRole] ? { ...dec, role } : null;
    } catch (_) { return null; }
}

// ===== 工具 =====
function getIP(req) { return req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown'; }
function genCode() { return String(Math.floor(100000 + Math.random() * 900000)); }

async function sendEmail(env, to, subject, html) {
    try {
        await fetch('https://api.mailchannels.net/tx/v1/send', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                personalizations: [{ to: [{ email: to }] }],
                from: { email: env.EMAIL_FROM || 'noreply@example.com', name: '灯雪镇' },
                subject, content: [{ type: 'text/html', value: html }]
            })
        });
    } catch (_) { }
}

async function logLogin(env, email, ip, success, reason) {
    try { await supabaseAPI(env, '/login_logs', { method: 'POST', body: JSON.stringify({ email, ip, success, reason, created_at: new Date().toISOString() }) }); } catch (_) { }
}
async function logAudit(env, op, action, target) {
    try { await supabaseAPI(env, '/audit_logs', { method: 'POST', body: JSON.stringify({ operator_email: op.email, operator_id: op.id, action, target, created_at: new Date().toISOString() }) }); } catch (_) { }
}

async function checkRate(env, ip) {
    try {
        const tenMin = new Date(Date.now() - 10 * 60 * 1000).toISOString();
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const c1 = await supabaseAPI(env, `/reg_attempts?select=id&ip=eq.${encodeURIComponent(ip)}&created_at=gte.${tenMin}`, { headers: { 'Prefer': 'count=exact' } });
        if (parseInt(c1.headers.get('content-range')?.split('/')[1] || '0') >= 5) return { blocked: true, reason: '操作太频繁，请10分钟后再试' };
        const c2 = await supabaseAPI(env, `/reg_attempts?select=id&ip=eq.${encodeURIComponent(ip)}&created_at=gte.${dayAgo}`, { headers: { 'Prefer': 'count=exact' } });
        if (parseInt(c2.headers.get('content-range')?.split('/')[1] || '0') >= 15) return { blocked: true, reason: '该IP注册过于频繁，已封禁24小时' };
    } catch (_) { }
    return { blocked: false };
}
async function recordIP(env, ip, email) {
    try { await supabaseAPI(env, '/reg_attempts', { method: 'POST', body: JSON.stringify({ ip, email, created_at: new Date().toISOString() }) }); } catch (_) { }
}

async function cleanupUnverified(env) {
    let deleted = 0;
    const fiveMin = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const data = await listUsers(env, 1, 100);
    for (const u of (data.users || [])) {
        if (!u.email_confirmed_at && u.created_at < fiveMin) {
            try { await deleteUser(env, u.id); deleted++; } catch (_) { }
        }
    }
    return deleted;
}

async function enrichNames(env, items) {
    if (!items?.length) return items;
    const ids = [...new Set(items.map(i => i.author_id).filter(Boolean))];
    if (!ids.length) return items;
    const names = {};
    for (const id of ids) {
        try { const u = await getUser(env, id); names[id] = u?.user_metadata?.game_id || u?.user_metadata?.display_name || ''; } catch (_) { }
    }
    return items.map(i => ({ ...i, author_name: names[i.author_id] || (i.author_email || '').split('@')[0] }));
}

// ===== 主路由 =====
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname.replace(/^\/api\//, '').replace(/\/$/, '');
        if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });

        try {
            // ping
            if (path === 'ping' || path === '') {
                return json({ ok: true, time: new Date().toISOString(), platform: 'Cloudflare Workers' });
            }

            // === Auth ===
            if (path === 'login' && request.method === 'POST') {
                const { email, password } = await request.json();
                if (!email || !password) return json({ message: '请填写完整信息' }, 400);
                const ip = getIP(request);
                const r = await supabaseAuth(env, `/token?grant_type=password`, { method: 'POST', body: JSON.stringify({ email, password }) });
                const d = await r.json();
                if (!r.ok) { await logLogin(env, email, ip, false, d.error_description || d.msg); return json({ message: d.error_description || d.msg || '登录失败' }, 400); }
                await logLogin(env, email, ip, true);
                const token = await signJWT({ id: d.user.id, email: d.user.email }, env.JWT_SECRET);
                return json({ message: '登录成功', user: { email: d.user.email, id: d.user.id }, token });
            }

            if (path === 'register' && request.method === 'POST') {
                const { email, password, qq, game_id, _website, _ts } = await request.json();
                if (!email || !password) return json({ message: '请填写完整信息' }, 400);
                if (_website?.length > 0) return json({ message: '注册成功！验证码已发送至您的邮箱', user: { email, id: 'fake' } }, 201);
                const now = Date.now();
                if (_ts && (now - parseInt(_ts) < 2000 || now - parseInt(_ts) > 600000)) return json({ message: '请稍后再试' }, 400);
                const ip = getIP(request);
                const rate = await checkRate(env, ip);
                if (rate.blocked) return json({ message: rate.reason }, 429);
                const safeQQ = String(qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
                const safeGameId = String(game_id || '').replace(/[<>]/g, '').slice(0, 32);
                const r = await createUser(env, { email, password, email_confirm: false, user_metadata: { qq: safeQQ, game_id: safeGameId } });
                const d = await r.json();
                if (!r.ok) {
                    if (d.msg?.includes('already')) {
                        const all = await listUsers(env, 1, 500);
                        const exist = (all.users || []).find(u => u.email === email);
                        if (exist) {
                            if (exist.email_confirmed_at) return json({ message: '该邮箱已注册并验证，请直接登录' }, 400);
                            const code = genCode();
                            await supabaseAPI(env, '/verification_codes', { method: 'POST', body: JSON.stringify({ user_id: exist.id, code, type: 'email_verify', expires_at: new Date(now + 10 * 60 * 1000).toISOString() }) });
                            await sendEmail(env, email, '【灯雪镇】验证码', `<p>验证码：<strong style="font-size:24px">${code}</strong></p><p>10分钟内有效</p>`);
                            return json({ message: '重新发送了验证码', user: { email: exist.email, id: exist.id } });
                        }
                    }
                    return json({ message: d.msg || '注册失败' }, 400);
                }
                await recordIP(env, ip, email);
                const code = genCode();
                await supabaseAPI(env, '/verification_codes', { method: 'POST', body: JSON.stringify({ user_id: d.id, code, type: 'email_verify', expires_at: new Date(now + 10 * 60 * 1000).toISOString() }) });
                await sendEmail(env, email, '【灯雪镇】验证码', `<p>验证码：<strong style="font-size:24px">${code}</strong></p><p>10分钟内有效</p>`);
                return json({ message: '注册成功！验证码已发送至您的邮箱', user: { email: d.email, id: d.id } }, 201);
            }

            if (path === 'verify-email' && request.method === 'POST') {
                const { email, code } = await request.json();
                if (!email || !code) return json({ message: '请提供邮箱和验证码' }, 400);
                const all = await listUsers(env, 1, 500);
                const user = (all.users || []).find(u => u.email === email);
                if (!user) return json({ message: '用户不存在' }, 404);
                const r = await supabaseAPI(env, `/verification_codes?user_id=eq.${user.id}&code=eq.${code}&type=eq.email_verify&expires_at=gt.${new Date().toISOString()}&order=created_at.desc&limit=1`);
                const rows = await r.json();
                if (!rows?.length) return json({ message: '验证码无效或已过期' }, 400);
                await updateUser(env, user.id, { email_confirm: true });
                await supabaseAPI(env, `/verification_codes?id=eq.${rows[0].id}`, { method: 'DELETE' });
                return json({ message: '邮箱验证成功！' });
            }

            if (path === 'reset-password' && request.method === 'POST') {
                const { email } = await request.json();
                if (!email) return json({ message: '请输入邮箱' }, 400);
                const site = env.SITE_URL || 'https://tr114512.github.io/light-snow-town/';
                await supabaseAuth(env, '/recover', { method: 'POST', body: JSON.stringify({ email, redirect_to: site + '?reset=true' }) });
                return json({ message: '重置邮件已发送' });
            }

            if (path === 'change-password' && request.method === 'POST') {
                const op = await requireRole(env, request, 'user');
                if (!op) return json({ message: '未登录' }, 401);
                const { oldPassword, newPassword } = await request.json();
                if (!oldPassword || !newPassword || newPassword.length < 8) return json({ message: '请填写完整信息' }, 400);
                const user = await getUser(env, op.id);
                if (!user) return json({ message: '用户不存在' }, 404);
                const check = await supabaseAuth(env, `/token?grant_type=password`, { method: 'POST', body: JSON.stringify({ email: user.email, password: oldPassword }) });
                if (!check.ok) return json({ message: '当前密码错误' }, 400);
                await updateUser(env, op.id, { password: newPassword });
                return json({ message: '密码已更新' });
            }

            if (path === 'me') {
                const auth = request.headers.get('Authorization');
                if (!auth) return json({ message: '未登录' }, 401);
                try {
                    const dec = await verifyJWT(auth.split(' ')[1], env.JWT_SECRET);
                    const user = await getUser(env, dec.id);
                    if (!user) return json({ message: '用户不存在' }, 404);
                    const role = await getUserRole(env, user.id, user.email);
                    let profile = {};
                    try { const r = await supabaseAPI(env, `/profiles?id=eq.${user.id}&select=qq,game_id,display_name`); const d = await r.json(); if (d?.length) profile = d[0]; } catch (_) { }
                    return json({ user: { email: user.email, id: user.id, role, qq: profile.qq || user.user_metadata?.qq || '', game_id: profile.game_id || user.user_metadata?.game_id || '', display_name: profile.display_name || '', created_at: user.created_at, email_confirmed_at: user.email_confirmed_at } });
                } catch (_) { return json({ message: 'Token无效' }, 401); }
            }

            if (path === 'update-profile' && request.method === 'POST') {
                const auth = request.headers.get('Authorization');
                if (!auth) return json({ message: '未登录' }, 401);
                try {
                    const dec = await verifyJWT(auth.split(' ')[1], env.JWT_SECRET);
                    const body = await request.json();
                    const sq = String(body.qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
                    const sg = String(body.game_id || '').replace(/[<>]/g, '').slice(0, 32);
                    await supabaseAPI(env, '/profiles', { method: 'POST', body: JSON.stringify({ id: dec.id, qq: sq, game_id: sg, updated_at: new Date().toISOString() }), headers: { 'Prefer': 'resolution=merge-duplicates' } });
                    await updateUser(env, dec.id, { user_metadata: { qq: sq, game_id: sg } });
                    return json({ message: '资料已更新' });
                } catch (_) { return json({ message: 'Token无效' }, 401); }
            }

            // === Admin ===
            if (path === 'admin/users') {
                const op = await requireRole(env, request, 'admin');
                if (!op) return json({ message: '未登录或权限不足' }, 401);
                if (request.method === 'POST') {
                    const { action, userIds } = await request.json();
                    if (action === 'cleanup') { const c = await cleanupUnverified(env); return json({ message: `已清理 ${c} 个未验证账号` }); }
                    if (action === 'batch-delete' && Array.isArray(userIds)) {
                        let del = 0;
                        for (const uid of userIds) { if (uid !== op.id) { try { await deleteUser(env, uid); del++; } catch (_) { } } }
                        return json({ message: `已删除 ${del} 个用户` });
                    }
                    return json({ message: '无效操作' }, 400);
                }
                const params = Object.fromEntries(url.searchParams);
                let allUsers = [];
                for (let p = 1; p <= 4; p++) { const d = await listUsers(env, p); const b = d.users || []; allUsers = allUsers.concat(b); if (b.length < 500) break; }
                const pr = await supabaseAPI(env, '/profiles?select=id,role,display_name,qq,game_id');
                const profiles = await pr.json();
                const rm = {};
                (profiles || []).forEach(p => { rm[p.id] = { role: p.role, display_name: p.display_name, qq: p.qq, game_id: p.game_id }; });
                let list = allUsers.map(u => ({ id: u.id, email: u.email, role: nr(u.user_metadata?.role || rm[u.id]?.role || 'user'), qq: rm[u.id]?.qq || u.user_metadata?.qq || '', game_id: rm[u.id]?.game_id || u.user_metadata?.game_id || '', display_name: rm[u.id]?.display_name || '', email_confirmed: !!u.email_confirmed_at, created_at: u.created_at, last_sign_in: u.last_sign_in_at }));
                if (params.verified === '1') list = list.filter(u => u.email_confirmed);
                if (params.search) { const q = params.search.toLowerCase(); list = list.filter(u => u.email.toLowerCase().includes(q)); }
                list.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
                if (params.format === 'csv') {
                    const hdr = '编号,邮箱,QQ,游戏ID,状态,角色,注册时间\n';
                    const rows = list.map((u, i) => `${i+1},"${u.email}","${u.qq||''}","${u.game_id||''}",${u.email_confirmed?'已验证':'未验证'},${u.role==='admin'?'管理员':'玩家'},"${new Date(u.created_at).toLocaleDateString('zh-CN')}"`).join('\n');
                    return new Response('\uFEFF' + hdr + rows, { headers: { ...cors(), 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename=users.csv' } });
                }
                return json({ total: list.length, operator_role: op.role, users: list.map((u, i) => ({ ...u, user_no: i + 1 })) });
            }

            if (path === 'admin/dashboard') {
                const op = await requireRole(env, request, 'admin');
                if (!op) return json({ message: '未登录或权限不足' }, 401);
                let total = 0, v = 0, uv = 0, today = 0;
                const td = new Date().toISOString().slice(0, 10);
                for (let p = 1; p <= 4; p++) { const d = await listUsers(env, p); const uu = d.users || []; if (!uu.length) break; total += uu.length; uu.forEach(u => { if (u.email_confirmed_at) v++; else uv++; if (u.created_at?.startsWith(td)) today++; }); }
                const qc = await supabaseAPI(env, '/questions?select=id', { headers: { 'Prefer': 'count=exact' } });
                const oc = await supabaseAPI(env, '/questions?select=id&status=eq.open', { headers: { 'Prefer': 'count=exact' } });
                return json({ stats: { totalUsers: total, verified: v, unverified: uv, todayReg: today, totalQuestions: parseInt(qc.headers.get('content-range')?.split('/')[1] || '0'), openQuestions: parseInt(oc.headers.get('content-range')?.split('/')[1] || '0') } });
            }

            if (path === 'admin/delete-user' && request.method === 'POST') {
                const op = await requireRole(env, request, 'admin');
                if (!op) return json({ message: '未登录或权限不足' }, 401);
                const { userId } = await request.json();
                if (!userId || userId === op.id) return json({ message: '无效操作' }, 400);
                const u = await getUser(env, userId);
                if (!u) return json({ message: '用户不存在' }, 404);
                await deleteUser(env, userId);
                await logAudit(env, op, '删除用户', u.email);
                return json({ message: `已删除用户 ${u.email}` });
            }

            if (path === 'admin/reset-user-password' && request.method === 'POST') {
                const op = await requireRole(env, request, 'admin');
                if (!op) return json({ message: '未登录或权限不足' }, 401);
                const { userId, newPassword } = await request.json();
                if (!userId || !newPassword || newPassword.length < 8) return json({ message: '请提供有效信息' }, 400);
                const u = await getUser(env, userId);
                if (!u) return json({ message: '用户不存在' }, 404);
                await updateUser(env, userId, { password: newPassword });
                await logAudit(env, op, '重置密码', u.email);
                return json({ message: `已重置用户 ${u.email} 的密码` });
            }

            if (path === 'admin/set-role' && request.method === 'POST') {
                const op = await requireRole(env, request, 'admin');
                if (!op) return json({ message: '未登录或权限不足' }, 401);
                const { userId, role } = await request.json();
                if (!userId || !role || !['admin', 'user'].includes(role) || userId === op.id) return json({ message: '无效操作' }, 400);
                const u = await getUser(env, userId);
                if (!u) return json({ message: '用户不存在' }, 404);
                await updateUser(env, userId, { user_metadata: { role } });
                await supabaseAPI(env, '/profiles', { method: 'POST', body: JSON.stringify({ id: userId, role, updated_at: new Date().toISOString() }), headers: { 'Prefer': 'resolution=merge-duplicates' } });
                await logAudit(env, op, `设置角色为${role}`, u.email);
                return json({ message: `已将用户 ${u.email} 的角色更新为 ${role}` });
            }

            // === QA ===
            if (path === 'qa/questions') {
                if (request.method === 'POST') {
                    const op = await requireRole(env, request, 'user');
                    if (!op) return json({ message: '请先登录' }, 401);
                    const { title, content } = await request.json();
                    if (!title || !content || title.length > 200 || content.length > 5000) return json({ message: '请填写有效内容' }, 400);
                    const mr = await supabaseAPI(env, '/questions?select=question_number&order=question_number.desc&limit=1');
                    const mRows = await mr.json();
                    const next = (mRows?.[0]?.question_number || 0) + 1;
                    const r = await supabaseAPI(env, '/questions', { method: 'POST', body: JSON.stringify({ question_number: next, author_id: op.id, author_email: op.email, title, content }) });
                    const q = await r.json();
                    return json({ question: q?.[0] || q, message: '问题已发布' }, 201);
                }
                const qid = url.searchParams.get('id');
                if (qid) {
                    const qr = await supabaseAPI(env, `/questions?id=eq.${qid}`);
                    const q = await qr.json();
                    if (!q?.length) return json({ message: '问题不存在' }, 404);
                    const ar = await supabaseAPI(env, `/answers?question_id=eq.${qid}&order=created_at.asc`);
                    const cr = await supabaseAPI(env, `/comments?question_id=eq.${qid}&order=created_at.asc`);
                    const aa = await ar.json(); const cc = await cr.json();
                    const all = [q[0], ...(aa || []), ...(cc || [])];
                    const enr = await enrichNames(env, all);
                    return json({ question: enr[0], answers: enr.slice(1, 1 + (aa || []).length), comments: enr.slice(1 + (aa || []).length) });
                }
                const params = Object.fromEntries(url.searchParams);
                const page = parseInt(params.page) || 1;
                const limit = Math.min(parseInt(params.limit) || 20, 50);
                const offset = (page - 1) * limit;
                let qp = `/questions?select=*&order=created_at.desc`;
                if (params.search) qp += `&title=ilike.*${encodeURIComponent(params.search)}*`;
                if (params.my === '1') { const auth = request.headers.get('Authorization'); if (!auth) return json({ message: '请先登录' }, 401); try { const d = await verifyJWT(auth.split(' ')[1], env.JWT_SECRET); qp += `&author_id=eq.${d.id}`; } catch (_) { return json({ message: 'Token无效' }, 401); } }
                if (params.author) qp += `&author_id=eq.${params.author}`;
                const totalR = await supabaseAPI(env, qp + '&limit=0', { headers: { 'Prefer': 'count=exact' } });
                const total = parseInt(totalR.headers.get('content-range')?.split('/')[1] || '0');
                const qr = await supabaseAPI(env, qp + `&limit=${limit}&offset=${offset}`);
                const qs = await qr.json();
                const enr = await enrichNames(env, qs || []);
                for (const q of enr) {
                    const ac = await supabaseAPI(env, `/answers?question_id=eq.${q.id}&select=id`, { headers: { 'Prefer': 'count=exact' } });
                    const cc = await supabaseAPI(env, `/comments?question_id=eq.${q.id}&select=id`, { headers: { 'Prefer': 'count=exact' } });
                    q.answer_count = parseInt(ac.headers.get('content-range')?.split('/')[1] || '0');
                    q.comment_count = parseInt(cc.headers.get('content-range')?.split('/')[1] || '0');
                }
                return json({ questions: enr, total, page, limit, totalPages: Math.ceil(total / limit) || 1 });
            }

            if (path === 'qa/answer' && request.method === 'POST') {
                const op = await requireRole(env, request, 'admin');
                if (!op) return json({ message: '未登录或权限不足' }, 401);
                const { question_id, content } = await request.json();
                if (!question_id || !content || content.length > 5000) return json({ message: '请填写有效内容' }, 400);
                const r = await supabaseAPI(env, '/answers', { method: 'POST', body: JSON.stringify({ question_id, author_id: op.id, author_email: op.email, content, is_admin_answer: true }) });
                await supabaseAPI(env, `/questions?id=eq.${question_id}`, { method: 'PATCH', body: JSON.stringify({ status: 'answered', updated_at: new Date().toISOString() }) });
                return json({ answer: await r.json(), message: '回答已发布' });
            }

            if (path === 'qa/comment' && request.method === 'POST') {
                const auth = request.headers.get('Authorization');
                if (!auth) return json({ message: '请先登录' }, 401);
                let dec;
                try { dec = await verifyJWT(auth.split(' ')[1], env.JWT_SECRET); } catch (_) { return json({ message: 'Token无效' }, 401); }
                const { question_id, content } = await request.json();
                if (!question_id || !content || content.length > 2000) return json({ message: '请填写有效内容' }, 400);
                const r = await supabaseAPI(env, '/comments', { method: 'POST', body: JSON.stringify({ question_id, author_id: dec.id, author_email: dec.email, content }) });
                return json({ comment: await r.json(), message: '评论已发布' });
            }

            if (path === 'qa/delete' && request.method === 'POST') {
                const op = await requireRole(env, request, 'admin');
                if (!op) return json({ message: '未登录或权限不足' }, 401);
                const { question_id } = await request.json();
                if (!question_id) return json({ message: '请提供问题ID' }, 400);
                await supabaseAPI(env, `/questions?id=eq.${question_id}`, { method: 'DELETE' });
                return json({ message: '问题已删除' });
            }

            return json({ message: `未知接口: ${path}` }, 404);
        } catch (e) {
            return json({ message: '服务器错误: ' + (e.message || '') }, 500);
        }
    }
};
