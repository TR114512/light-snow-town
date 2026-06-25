/**
 * 灯雪镇 Cloudflare Workers - 零依赖
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

// ===== btoa 安全版（避免 String.fromCharCode spread 栈溢出）=====
function safeBtoa(buf) {
    let binary = '';
    const chunk = 8192;
    for (let i = 0; i < buf.length; i += chunk) {
        binary += String.fromCharCode(...buf.slice(i, i + chunk));
    }
    return btoa(binary);
}

function b64url(buf) { return safeBtoa(buf).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function b64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ===== JWT =====
async function signJWT(payload, secret) {
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const h = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
    const b = b64url(enc.encode(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 })));
    const s = b64url(await crypto.subtle.sign('HMAC', k, enc.encode(`${h}.${b}`)));
    return `${h}.${b}.${s}`;
}
async function verifyJWT(token, secret) {
    const p = token.split('.'); if (p.length !== 3) throw new Error('invalid');
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('HMAC', k, b64urlDecode(p[2]), enc.encode(`${p[0]}.${p[1]}`));
    if (!ok) throw new Error('invalid');
    return JSON.parse(new TextDecoder().decode(b64urlDecode(p[1])));
}

// ===== Supabase REST =====
function sa(env, path, opts = {}) {
    return fetch(`${env.SUPABASE_URL}/rest/v1${path}`, { ...opts, headers: { 'apikey': env.SUPABASE_SERVICE_ROLE_KEY, 'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type': 'application/json', ...opts.headers } });
}
async function authAdmin(env, path, opts = {}) {
    return fetch(`${env.SUPABASE_URL}/auth/v1/admin${path}`, { ...opts, headers: { 'apikey': env.SUPABASE_SERVICE_ROLE_KEY, 'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type': 'application/json', ...opts.headers } });
}
async function authAPI(env, path, opts = {}) {
    return fetch(`${env.SUPABASE_URL}/auth/v1${path}`, { ...opts, headers: { 'apikey': env.SUPABASE_SERVICE_ROLE_KEY, 'Content-Type': 'application/json', ...opts.headers } });
}
async function listUsers(env, page = 1, pp = 500) { const r = await authAdmin(env, `/users?page=${page}&per_page=${pp}`); return r.ok ? await r.json() : { users: [] }; }
async function getUser(env, uid) { const r = await authAdmin(env, `/users/${uid}`); return r.ok ? await r.json() : null; }
async function delUser(env, uid) { return authAdmin(env, `/users/${uid}`, { method: 'DELETE' }); }
async function updUser(env, uid, data) { return authAdmin(env, `/users/${uid}`, { method: 'PUT', body: JSON.stringify(data) }); }
async function addUser(env, data) { return authAdmin(env, '/users', { method: 'POST', body: JSON.stringify(data) }); }

// ===== 角色 =====
function nr(r) { return (r === 'super_admin' || r === 'admin') ? 'admin' : 'user'; }
async function getUserRole(env, uid, email) {
    try { const u = await getUser(env, uid); if (u?.user_metadata?.role) return nr(u.user_metadata.role); } catch (_) { }
    try { const r = await sa(env, `/profiles?id=eq.${uid}&select=role`); const d = await r.json(); if (d?.[0]?.role) return nr(d[0].role); } catch (_) { }
    const admins = (env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase());
    return admins.includes((email || '').toLowerCase()) ? 'admin' : 'user';
}
async function requireRole(env, req, minRole) {
    const a = req.headers.get('Authorization'); if (!a) return null;
    try {
        const t = a.split(' ')[1]; const d = await verifyJWT(t, env.JWT_SECRET);
        const r = await getUserRole(env, d.id, d.email);
        return ({ admin: 1, user: 0 })[r] >= ({ admin: 1, user: 0 })[minRole] ? { ...d, role: r } : null;
    } catch (_) { return null; }
}

// ===== 工具 =====
function getIP(r) { return r.headers.get('CF-Connecting-IP') || 'unknown'; }
function genCode() { return String(Math.floor(100000 + Math.random() * 900000)); }
async function sendMail(env, to, subj, html) {
    try { await fetch('https://api.mailchannels.net/tx/v1/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ personalizations: [{ to: [{ email: to }] }], from: { email: env.EMAIL_FROM || 'noreply@lighttown.dev', name: '灯雪镇' }, subject: subj, content: [{ type: 'text/html', value: html }] }) }); } catch (_) { }
}
async function logLogin(env, email, ip, ok, reason) { try { await sa(env, '/login_logs', { method: 'POST', body: JSON.stringify({ email, ip, success: ok, reason, created_at: new Date().toISOString() }) }); } catch (_) { } }
async function logAudit(env, op, act, target) { try { await sa(env, '/audit_logs', { method: 'POST', body: JSON.stringify({ operator_email: op.email, operator_id: op.id, action: act, target, created_at: new Date().toISOString() }) }); } catch (_) { } }
async function checkRate(env, ip) {
    try {
        const t = new Date(); const tenMin = new Date(t - 10 * 60 * 1000).toISOString(); const dayAgo = new Date(t - 24 * 60 * 60 * 1000).toISOString();
        const c1 = await sa(env, `/reg_attempts?select=id&ip=eq.${encodeURIComponent(ip)}&created_at=gte.${tenMin}`, { headers: { 'Prefer': 'count=exact' } });
        if (parseInt(c1.headers.get('content-range')?.split('/')[1] || '0') >= 5) return { blocked: true, reason: '操作太频繁，请10分钟后再试' };
        const c2 = await sa(env, `/reg_attempts?select=id&ip=eq.${encodeURIComponent(ip)}&created_at=gte.${dayAgo}`, { headers: { 'Prefer': 'count=exact' } });
        if (parseInt(c2.headers.get('content-range')?.split('/')[1] || '0') >= 15) return { blocked: true, reason: '该IP注册过于频繁，已封禁24小时' };
    } catch (_) { }
    return { blocked: false };
}
async function recIP(env, ip, email) { try { await sa(env, '/reg_attempts', { method: 'POST', body: JSON.stringify({ ip, email, created_at: new Date().toISOString() }) }); } catch (_) { } }
async function cleanup(env) {
    let del = 0; const fiveMin = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const d = await listUsers(env, 1, 100);
    for (const u of (d.users || [])) { if (!u.email_confirmed_at && u.created_at < fiveMin) { try { await delUser(env, u.id); del++; } catch (_) { } } }
    return del;
}
async function enrichNames(env, items) {
    if (!items?.length) return items;
    const ids = [...new Set(items.map(i => i.author_id).filter(Boolean))]; if (!ids.length) return items;
    const names = {};
    for (const id of ids) { try { const u = await getUser(env, id); names[id] = u?.user_metadata?.game_id || u?.user_metadata?.display_name || ''; } catch (_) { } }
    return items.map(i => ({ ...i, author_name: names[i.author_id] || (i.author_email || '').split('@')[0] }));
}

// ===== 主路由 =====
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname.replace(/^\/api\//, '').replace(/\/$/, '') || 'ping';
        if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });

        try {
            if (path === 'ping') return json({ ok: true, time: new Date().toISOString(), platform: 'Cloudflare Workers' });

            // === Auth ===
            if (path === 'login' && request.method === 'POST') {
                const { email, password } = await request.json();
                if (!email || !password) return json({ message: '请填写完整信息' }, 400);
                const ip = getIP(request);
                const r = await authAPI(env, `/token?grant_type=password`, { method: 'POST', body: JSON.stringify({ email, password }) });
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
                const sq = String(qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
                const sg = String(game_id || '').replace(/[<>]/g, '').slice(0, 32);
                const r = await addUser(env, { email, password, email_confirm: false, user_metadata: { qq: sq, game_id: sg } });
                const d = await r.json();
                if (!r.ok) {
                    if (d.msg?.includes('already')) {
                        const all = await listUsers(env);
                        const ex = (all.users || []).find(u => u.email === email);
                        if (ex) {
                            if (ex.email_confirmed_at) return json({ message: '该邮箱已注册并验证，请直接登录' }, 400);
                            const code = genCode();
                            await sa(env, '/verification_codes', { method: 'POST', body: JSON.stringify({ user_id: ex.id, code, type: 'email_verify', expires_at: new Date(now + 10 * 60 * 1000).toISOString() }) });
                            await sendMail(env, email, '【灯雪镇】验证码', `<p>验证码：<strong style="font-size:24px">${code}</strong></p><p>10分钟内有效</p>`);
                            return json({ message: '重新发送了验证码', user: { email: ex.email, id: ex.id } });
                        }
                    }
                    return json({ message: d.msg || '注册失败' }, 400);
                }
                await recIP(env, ip, email);
                const code = genCode();
                await sa(env, '/verification_codes', { method: 'POST', body: JSON.stringify({ user_id: d.id, code, type: 'email_verify', expires_at: new Date(now + 10 * 60 * 1000).toISOString() }) });
                await sendMail(env, email, '【灯雪镇】验证码', `<p>验证码：<strong style="font-size:24px">${code}</strong></p><p>10分钟内有效</p>`);
                return json({ message: '注册成功！验证码已发送至您的邮箱', user: { email: d.email, id: d.id } }, 201);
            }

            // 其他路由省略，结构同上...
            return json({ message: '功能开发中，请稍候...' });

        } catch (e) {
            return json({ message: '错误: ' + (e.message || '') }, 500);
        }
    }
};
