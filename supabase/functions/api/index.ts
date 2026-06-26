/**
 * 灯雪镇 Supabase Edge Function
 * 部署: npx supabase functions deploy api --no-verify-jwt
 */

const SB_URL = 'https://yfotnbwnhulvdjxstens.supabase.co';
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '';
const JWT_SECRET = Deno.env.get('JWT_SECRET') || '';

function cors() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };
}

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...cors(), 'Content-Type': 'application/json; charset=utf-8' }
    });
}

// ===== Supabase REST =====
function sa(path, opts = {}) {
    return fetch(`${SB_URL}/rest/v1${path}`, {
        ...opts,
        headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json', ...opts.headers }
    });
}

function aa(path, opts = {}) {
    return fetch(`${SB_URL}/auth/v1/admin${path}`, {
        ...opts,
        headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json', ...opts.headers }
    });
}

function au(path, opts = {}) {
    return fetch(`${SB_URL}/auth/v1${path}`, {
        ...opts,
        headers: { apikey: SERVICE_KEY, 'Content-Type': 'application/json', ...opts.headers }
    });
}

async function listUsers(page = 1, pp = 500) {
    const r = await aa(`/users?page=${page}&per_page=${pp}`);
    return r.ok ? await r.json() : { users: [] };
}

async function getUser(uid) {
    const r = await aa(`/users/${uid}`);
    return r.ok ? await r.json() : null;
}

async function delUser(uid) {
    return aa(`/users/${uid}`, { method: 'DELETE' });
}

async function updUser(uid, data) {
    return aa(`/users/${uid}`, { method: 'PUT', body: JSON.stringify(data) });
}

async function addUser(data) {
    return aa('/users', { method: 'POST', body: JSON.stringify(data) });
}

// ===== JWT =====
function b64url(buf: Uint8Array) {
    return btoa(String.fromCharCode(...buf)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64d(str: string) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function signJWT(payload: any) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const h = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
    const b = b64url(enc.encode(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 604800 })));
    const s = b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${b}`))));
    return `${h}.${b}.${s}`;
}

async function verifyJWT(token: string) {
    const parts = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('HMAC', key, b64d(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
    if (!ok) throw new Error('invalid');
    return JSON.parse(new TextDecoder().decode(b64d(parts[1])));
}

// ===== 角色 =====
function nr(role) { return (role === 'super_admin' || role === 'admin') ? 'admin' : 'user'; }

async function getUserRole(uid: string, email: string) {
    try {
        const u = await getUser(uid);
        if (u?.user_metadata?.role) return nr(u.user_metadata.role);
    } catch (_) {}
    try {
        const r = await sa(`/profiles?id=eq.${uid}&select=role`);
        const d = await r.json();
        if (d?.[0]?.role) return nr(d[0].role);
    } catch (_) {}
    const admins = (Deno.env.get('ADMIN_EMAILS') || '').split(',').map(e => e.trim().toLowerCase());
    return admins.includes((email || '').toLowerCase()) ? 'admin' : 'user';
}

async function requireRole(req: Request, minRole: string) {
    const a = req.headers.get('Authorization');
    if (!a) return null;
    try {
        const t = a.split(' ')[1];
        const d = await verifyJWT(t);
        const r = await getUserRole(d.id, d.email);
        return ({ admin: 1, user: 0 })[r] >= ({ admin: 1, user: 0 })[minRole] ? { ...d, role: r } : null;
    } catch (_) { return null; }
}

// ===== 工具 =====
function getIP(req: Request) { return req.headers.get('CF-Connecting-IP') || 'unknown'; }
function genCode() { return String(Math.floor(100000 + Math.random() * 900000)); }

async function sendMail(to: string, subj: string, html: string) {
    try {
        await fetch('https://api.mailchannels.net/tx/v1/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                personalizations: [{ to: [{ email: to }] }],
                from: { email: Deno.env.get('EMAIL_FROM') || 'flyfishenname@qq.com', name: '灯雪镇' },
                subject: subj,
                content: [{ type: 'text/html', value: html }]
            })
        });
    } catch (_) {}
}

async function logTable(table: string, data: any) {
    try { await sa(`/${table}`, { method: 'POST', body: JSON.stringify(data) }); } catch (_) {}
}

async function checkRate(ip: string) {
    try {
        const tenMin = new Date(Date.now() - 600000).toISOString();
        const dayAgo = new Date(Date.now() - 86400000).toISOString();
        const c1 = await sa(`/reg_attempts?select=id&ip=eq.${encodeURIComponent(ip)}&created_at=gte.${tenMin}`, { headers: { 'Prefer': 'count=exact' } });
        if (parseInt(c1.headers.get('content-range')?.split('/')[1] || '0') >= 5) return { blocked: true, reason: '操作太频繁，请10分钟后再试' };
        const c2 = await sa(`/reg_attempts?select=id&ip=eq.${encodeURIComponent(ip)}&created_at=gte.${dayAgo}`, { headers: { 'Prefer': 'count=exact' } });
        if (parseInt(c2.headers.get('content-range')?.split('/')[1] || '0') >= 15) return { blocked: true, reason: '该IP注册过于频繁，已封禁24小时' };
    } catch (_) {}
    return { blocked: false };
}

async function cleanup() {
    let del = 0;
    const fiveMin = new Date(Date.now() - 300000).toISOString();
    const d = await listUsers(1, 100);
    for (const u of (d.users || [])) {
        if (!u.email_confirmed_at && u.created_at < fiveMin) {
            try { await delUser(u.id); del++; } catch (_) {}
        }
    }
    return del;
}

async function enrichNames(items: any[]) {
    if (!items?.length) return [];
    const ids = [...new Set(items.map(i => i.author_id).filter(Boolean))];
    if (!ids.length) return items;
    const names: Record<string, string> = {};
    for (const id of ids) {
        try {
            const u = await getUser(String(id));
            names[String(id)] = u?.user_metadata?.game_id || u?.user_metadata?.display_name || '';
        } catch (_) {}
    }
    return items.map(i => ({ ...i, author_name: names[String(i.author_id)] || (i.author_email || '').split('@')[0] }));
}

// ===== 主路由 =====
Deno.serve(async (request) => {
    const url = new URL(request.url);
    const p = url.pathname.replace(/^.*\/(super-api|api)\//, '').replace(/\/$/, '') || 'ping';
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });

    try {
        if (p === 'ping' || p === '') return json({ ok: true, time: new Date().toISOString(), platform: 'Supabase Edge Functions' });

        // === Auth ===
        if (p === 'login' && request.method === 'POST') {
            const { email, password } = await request.json();
            if (!email || !password) return json({ message: '请填写完整信息' }, 400);
            const r = await au(`/token?grant_type=password`, { method: 'POST', body: JSON.stringify({ email, password }) });
            const d = await r.json();
            if (!r.ok) return json({ message: d.error_description || d.msg || '登录失败' }, 400);
            const token = await signJWT({ id: d.user.id, email: d.user.email });
            return json({ message: '登录成功', user: { email: d.user.email, id: d.user.id }, token });
        }

        if (p === 'register' && request.method === 'POST') {
            const { email, password, qq, game_id, _website, _ts } = await request.json();
            if (!email || !password) return json({ message: '请填写完整信息' }, 400);
            if (_website?.length > 0) return json({ message: '注册成功', user: { email, id: 'fake' } }, 201);
            const now = Date.now();
            if (_ts && (now - parseInt(_ts) < 2000 || now - parseInt(_ts) > 600000)) return json({ message: '请稍后再试' }, 400);
            const ip = getIP(request);
            const rate = await checkRate(ip);
            if (rate.blocked) return json({ message: rate.reason }, 429);
            const sq = String(qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
            const sg = String(game_id || '').replace(/[<>]/g, '').slice(0, 32);
            const r = await addUser({ email, password, email_confirm: false, user_metadata: { qq: sq, game_id: sg } });
            const d = await r.json();
            if (!r.ok) {
                if (d.msg?.includes('already')) {
                    const all = await listUsers(1, 500);
                    const ex = (all.users || []).find((u: any) => u.email === email);
                    if (ex) {
                        if (ex.email_confirmed_at) return json({ message: '该邮箱已注册并验证' }, 400);
                        const code = genCode();
                        await sa('/verification_codes', { method: 'POST', body: JSON.stringify({ user_id: ex.id, code, type: 'email_verify', expires_at: new Date(now + 600000).toISOString() }) });
                        await sendMail(email, '【灯雪镇】验证码', `<p>验证码：<strong style="font-size:24px">${code}</strong></p><p>10分钟有效</p>`);
                        return json({ message: '重新发送了验证码', user: { email: ex.email, id: ex.id } });
                    }
                }
                return json({ message: d.msg || '注册失败' }, 400);
            }
            const code = genCode();
            await sa('/verification_codes', { method: 'POST', body: JSON.stringify({ user_id: d.id, code, type: 'email_verify', expires_at: new Date(now + 600000).toISOString() }) });
            await sendMail(email, '【灯雪镇】验证码', `<p>验证码：<strong style="font-size:24px">${code}</strong></p><p>10分钟有效</p>`);
            return json({ message: '注册成功！验证码已发送', user: { email: d.email, id: d.id } }, 201);
        }

        if (p === 'verify-email' && request.method === 'POST') {
            const { email, code } = await request.json();
            if (!email || !code) return json({ message: '请提供邮箱和验证码' }, 400);
            const all = await listUsers(1, 500);
            const user = (all.users || []).find((u: any) => u.email === email);
            if (!user) return json({ message: '用户不存在' }, 404);
            const r = await sa(`/verification_codes?user_id=eq.${user.id}&code=eq.${code}&type=eq.email_verify&expires_at=gt.${new Date().toISOString()}&order=created_at.desc&limit=1`);
            const rows = await r.json();
            if (!rows?.length) return json({ message: '验证码无效或已过期' }, 400);
            await updUser(user.id, { email_confirm: true });
            await sa(`/verification_codes?id=eq.${rows[0].id}`, { method: 'DELETE' });
            return json({ message: '邮箱验证成功！' });
        }

        if (p === 'reset-password' && request.method === 'POST') {
            const { email } = await request.json();
            if (!email) return json({ message: '请输入邮箱' }, 400);
            const site = Deno.env.get('SITE_URL') || 'https://tr114512.github.io/light-snow-town/';
            await au('/recover', { method: 'POST', body: JSON.stringify({ email, redirect_to: site + '?reset=true' }) });
            return json({ message: '重置邮件已发送' });
        }

        if (p === 'me') {
            const a = request.headers.get('Authorization');
            if (!a) return json({ message: '未登录' }, 401);
            try {
                const d = await verifyJWT(a.split(' ')[1]);
                const user = await getUser(d.id);
                if (!user) return json({ message: '用户不存在' }, 404);
                const role = await getUserRole(user.id, user.email);
                let profile: any = {};
                try { const rr = await sa(`/profiles?id=eq.${user.id}&select=qq,game_id,display_name`); const dd = await rr.json(); if (dd?.length) profile = dd[0]; } catch (_) {}
                return json({ user: { email: user.email, id: user.id, role, qq: profile.qq || user.user_metadata?.qq || '', game_id: profile.game_id || user.user_metadata?.game_id || '', display_name: profile.display_name || '', created_at: user.created_at, email_confirmed_at: user.email_confirmed_at } });
            } catch (_) { return json({ message: 'Token无效' }, 401); }
        }

        if (p === 'update-profile' && request.method === 'POST') {
            const a = request.headers.get('Authorization');
            if (!a) return json({ message: '未登录' }, 401);
            try {
                const d = await verifyJWT(a.split(' ')[1]);
                const body = await request.json();
                const sq = String(body.qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
                const sg = String(body.game_id || '').replace(/[<>]/g, '').slice(0, 32);
                await sa('/profiles', { method: 'POST', body: JSON.stringify({ id: d.id, qq: sq, game_id: sg, updated_at: new Date().toISOString() }), headers: { 'Prefer': 'resolution=merge-duplicates' } });
                await updUser(d.id, { user_metadata: { qq: sq, game_id: sg } });
                return json({ message: '资料已更新' });
            } catch (_) { return json({ message: 'Token无效' }, 401); }
        }

        if (p === 'change-password' && request.method === 'POST') {
            const op = await requireRole(request, 'user');
            if (!op) return json({ message: '未登录' }, 401);
            const { oldPassword, newPassword } = await request.json();
            if (!oldPassword || !newPassword || newPassword.length < 8) return json({ message: '请填写完整信息' }, 400);
            const user = await getUser(op.id);
            if (!user) return json({ message: '用户不存在' }, 404);
            const ck = await au('/token?grant_type=password', { method: 'POST', body: JSON.stringify({ email: user.email, password: oldPassword }) });
            if (!ck.ok) return json({ message: '当前密码错误' }, 400);
            await updUser(op.id, { password: newPassword });
            return json({ message: '密码已更新' });
        }

        // === Admin ===
        if (p === 'admin/users') {
            const op = await requireRole(request, 'admin');
            if (!op) return json({ message: '未登录或权限不足' }, 401);
            if (request.method === 'POST') {
                const { action, userIds } = await request.json();
                if (action === 'cleanup') return json({ message: `已清理 ${await cleanup()} 个未验证账号` });
                if (action === 'batch-delete' && Array.isArray(userIds)) {
                    let dl = 0;
                    for (const uid of userIds) { if (uid !== op.id) { try { await delUser(uid); dl++; } catch (_) {} } }
                    return json({ message: `已删除 ${dl} 个用户` });
                }
                return json({ message: '无效操作' }, 400);
            }
            const params = Object.fromEntries(url.searchParams);
            let allUsers: any[] = [];
            for (let pg = 1; pg <= 4; pg++) { const d = await listUsers(pg); const b = d.users || []; allUsers = allUsers.concat(b); if (b.length < 500) break; }
            const pr = await sa('/profiles?select=id,role,display_name,qq,game_id');
            const profiles = await pr.json();
            const rm: Record<string, any> = {};
            (profiles || []).forEach((p: any) => { rm[p.id] = { role: p.role, display_name: p.display_name, qq: p.qq, game_id: p.game_id }; });
            let list = allUsers.map((u: any) => ({
                id: u.id, email: u.email,
                role: nr(u.user_metadata?.role || rm[u.id]?.role || 'user'),
                qq: rm[u.id]?.qq || u.user_metadata?.qq || '',
                game_id: rm[u.id]?.game_id || u.user_metadata?.game_id || '',
                email_confirmed: !!u.email_confirmed_at,
                created_at: u.created_at,
                last_sign_in: u.last_sign_in_at
            }));
            if (params.verified === '1') list = list.filter((u: any) => u.email_confirmed);
            if (params.search) { const q = params.search.toLowerCase(); list = list.filter((u: any) => u.email.toLowerCase().includes(q)); }
            list.sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
            if (params.format === 'csv') return new Response('\uFEFF' + ['编号,邮箱,QQ,游戏ID,状态,角色,注册时间'].concat(list.map((u: any, i: number) => `${i + 1},"${u.email}","${u.qq || ''}","${u.game_id || ''}",${u.email_confirmed ? '已验证' : '未验证'},${u.role === 'admin' ? '管理员' : '玩家'},"${new Date(u.created_at).toLocaleDateString('zh-CN')}"`)).join('\n'), { headers: { ...cors(), 'Content-Type': 'text/csv; charset=utf-8' } });
            return json({ total: list.length, operator_role: op.role, users: list.map((u: any, i: number) => ({ ...u, user_no: i + 1 })) });
        }

        if (p === 'admin/dashboard') {
            const op = await requireRole(request, 'admin');
            if (!op) return json({ message: '未登录或权限不足' }, 401);
            let total = 0, v = 0, uv = 0, today = 0;
            const td = new Date().toISOString().slice(0, 10);
            for (let pg = 1; pg <= 4; pg++) { const d = await listUsers(pg); const uu = d.users || []; if (!uu.length) break; total += uu.length; uu.forEach((u: any) => { if (u.email_confirmed_at) v++; else uv++; if (u.created_at?.startsWith(td)) today++; }); }
            const qc = await sa('/questions?select=id', { headers: { 'Prefer': 'count=exact' } });
            const oc = await sa('/questions?select=id&status=eq.open', { headers: { 'Prefer': 'count=exact' } });
            return json({ stats: { totalUsers: total, verified: v, unverified: uv, todayReg: today, totalQuestions: parseInt(qc.headers.get('content-range')?.split('/')[1] || '0'), openQuestions: parseInt(oc.headers.get('content-range')?.split('/')[1] || '0') } });
        }

        if (p === 'admin/delete-user' && request.method === 'POST') {
            const op = await requireRole(request, 'admin');
            if (!op) return json({ message: '未登录或权限不足' }, 401);
            const { userId } = await request.json();
            if (!userId || userId === op.id) return json({ message: '无效操作' }, 400);
            const u = await getUser(userId);
            if (!u) return json({ message: '用户不存在' }, 404);
            await delUser(userId);
            await logTable('audit_logs', { operator_email: op.email, operator_id: op.id, action: '删除用户', target: u.email, created_at: new Date().toISOString() });
            return json({ message: `已删除用户 ${u.email}` });
        }

        if (p === 'admin/reset-user-password' && request.method === 'POST') {
            const op = await requireRole(request, 'admin');
            if (!op) return json({ message: '未登录或权限不足' }, 401);
            const { userId, newPassword } = await request.json();
            if (!userId || !newPassword || newPassword.length < 8) return json({ message: '请提供有效信息' }, 400);
            const u = await getUser(userId);
            if (!u) return json({ message: '用户不存在' }, 404);
            await updUser(userId, { password: newPassword });
            return json({ message: `已重置用户 ${u.email} 的密码` });
        }

        if (p === 'admin/set-role' && request.method === 'POST') {
            const op = await requireRole(request, 'admin');
            if (!op) return json({ message: '未登录或权限不足' }, 401);
            const { userId, role } = await request.json();
            if (!userId || !role || !['admin', 'user'].includes(role) || userId === op.id) return json({ message: '无效操作' }, 400);
            const u = await getUser(userId);
            if (!u) return json({ message: '用户不存在' }, 404);
            await updUser(userId, { user_metadata: { role } });
            await sa('/profiles', { method: 'POST', body: JSON.stringify({ id: userId, role, updated_at: new Date().toISOString() }), headers: { 'Prefer': 'resolution=merge-duplicates' } });
            return json({ message: `已将用户 ${u.email} 的角色更新为 ${role}` });
        }

        // === QA ===
        if (p === 'qa/questions') {
            if (request.method === 'POST') {
                const op = await requireRole(request, 'user');
                if (!op) return json({ message: '请先登录' }, 401);
                const { title, content } = await request.json();
                if (!title || !content || title.length > 200 || content.length > 5000) return json({ message: '请填写有效内容' }, 400);
                const mr = await sa('/questions?select=question_number&order=question_number.desc&limit=1');
                const mRows = await mr.json();
                const next = (mRows?.[0]?.question_number || 0) + 1;
                const r = await sa('/questions', { method: 'POST', body: JSON.stringify({ question_number: next, author_id: op.id, author_email: op.email, title, content }) });
                const q = await r.json();
                return json({ question: q?.[0] || q, message: '问题已发布' }, 201);
            }
            const qid = url.searchParams.get('id');
            if (qid) {
                const qr = await sa(`/questions?id=eq.${qid}`);
                const q = await qr.json();
                if (!q?.length) return json({ message: '问题不存在' }, 404);
                const ar = await sa(`/answers?question_id=eq.${qid}&order=created_at.asc`);
                const cr = await sa(`/comments?question_id=eq.${qid}&order=created_at.asc`);
                const aa = await ar.json(); const cc = await cr.json();
                const all = [q[0], ...(aa || []), ...(cc || [])];
                const enr = await enrichNames(all);
                return json({ question: enr[0], answers: enr.slice(1, 1 + (aa || []).length), comments: enr.slice(1 + (aa || []).length) });
            }
            const params = Object.fromEntries(url.searchParams);
            const page = parseInt(params.page) || 1;
            const limit = Math.min(parseInt(params.limit) || 20, 50);
            const offset = (page - 1) * limit;
            let qPath = '/questions?select=*&order=created_at.desc';
            if (params.search) qPath += `&title=ilike.*${encodeURIComponent(params.search)}*`;
            if (params.my === '1') {
                const a = request.headers.get('Authorization');
                if (!a) return json({ message: '请先登录' }, 401);
                try { const d = await verifyJWT(a.split(' ')[1]); qPath += `&author_id=eq.${d.id}`; } catch (_) { return json({ message: 'Token无效' }, 401); }
            }
            if (params.author) qPath += `&author_id=eq.${params.author}`;
            const totalR = await sa(qPath + '&limit=0', { headers: { 'Prefer': 'count=exact' } });
            const total = parseInt(totalR.headers.get('content-range')?.split('/')[1] || '0');
            const qr = await sa(qPath + `&limit=${limit}&offset=${offset}`);
            const qs = await qr.json();
            const enr = await enrichNames(qs || []);
            for (const q of enr) {
                const ac = await sa(`/answers?question_id=eq.${q.id}&select=id`, { headers: { 'Prefer': 'count=exact' } });
                const cc = await sa(`/comments?question_id=eq.${q.id}&select=id`, { headers: { 'Prefer': 'count=exact' } });
                q.answer_count = parseInt(ac.headers.get('content-range')?.split('/')[1] || '0');
                q.comment_count = parseInt(cc.headers.get('content-range')?.split('/')[1] || '0');
            }
            return json({ questions: enr, total, page, limit, totalPages: Math.ceil(total / limit) || 1 });
        }

        if (p === 'qa/answer' && request.method === 'POST') {
            const op = await requireRole(request, 'admin');
            if (!op) return json({ message: '未登录或权限不足' }, 401);
            const { question_id, content } = await request.json();
            if (!question_id || !content || content.length > 5000) return json({ message: '请填写有效内容' }, 400);
            await sa('/answers', { method: 'POST', body: JSON.stringify({ question_id, author_id: op.id, author_email: op.email, content, is_admin_answer: true }) });
            await sa(`/questions?id=eq.${question_id}`, { method: 'PATCH', body: JSON.stringify({ status: 'answered', updated_at: new Date().toISOString() }) });
            return json({ message: '回答已发布' });
        }

        if (p === 'qa/comment' && request.method === 'POST') {
            const a = request.headers.get('Authorization');
            if (!a) return json({ message: '请先登录' }, 401);
            let d;
            try { d = await verifyJWT(a.split(' ')[1]); } catch (_) { return json({ message: 'Token无效' }, 401); }
            const { question_id, content } = await request.json();
            if (!question_id || !content || content.length > 2000) return json({ message: '请填写有效内容' }, 400);
            await sa('/comments', { method: 'POST', body: JSON.stringify({ question_id, author_id: d.id, author_email: d.email, content }) });
            return json({ message: '评论已发布' });
        }

        if (p === 'qa/delete' && request.method === 'POST') {
            const op = await requireRole(request, 'admin');
            if (!op) return json({ message: '未登录或权限不足' }, 401);
            const { question_id } = await request.json();
            if (!question_id) return json({ message: '请提供问题ID' }, 400);
            await sa(`/questions?id=eq.${question_id}`, { method: 'DELETE' });
            return json({ message: '问题已删除' });
        }

        return json({ message: '未知接口: ' + p }, 404);
    } catch (e) {
        return json({ message: '错误: ' + (e instanceof Error ? e.message : '') }, 500);
    }
});
