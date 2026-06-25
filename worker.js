/**
 * 灯雪镇 Cloudflare Workers 后端
 */

import { createClient } from '@supabase/supabase-js';
import * as jose from 'jose';

// ===== 初始化 Supabase =====
function getSupabase(env) {
    return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
}

// ===== JWT 工具 (使用 Web Crypto) =====
function getSecretKey(env) {
    return new TextEncoder().encode(env.JWT_SECRET);
}

async function signToken(userId, email, env) {
    return await new jose.SignJWT({ id: userId, email })
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('7d')
        .sign(getSecretKey(env));
}

async function verifyToken(token, env) {
    const { payload } = await jose.jwtVerify(token, getSecretKey(env));
    return payload;
}

// ===== CORS 处理 =====
function corsHeaders() {
    return {
        'Access-Control-Allow-Origin': 'https://tr114512.github.io',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
    };
}

function jsonRes(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders(), 'Content-Type': 'application/json; charset=utf-8' }
    });
}

// ===== 邮件发送 (MailChannels，Cloudflare Workers 免费) =====
async function sendEmail(to, subject, html, env) {
    try {
        const resp = await fetch('https://api.mailchannels.net/tx/v1/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                personalizations: [{ to: [{ email: to }] }],
                from: { email: env.EMAIL_FROM || 'noreply@lighttown.dev', name: '灯雪镇' },
                subject,
                content: [{ type: 'text/html', value: html }]
            })
        });
        return resp.ok;
    } catch (_) {
        // MailChannels 失败时记录但不阻塞
        console.error('Email send failed for:', to);
        return false;
    }
}

async function sendVerificationEmail(email, code, env) {
    await sendEmail(email,
        '【灯雪镇】邮箱验证码',
        `<p>您的验证码是：<strong style="font-size:24px;letter-spacing:4px;">${code}</strong></p><p>10分钟内有效，请勿透露给他人。</p>`,
        env
    );
}

// ===== 角色系统 =====
const ROLE_LEVEL = { 'user': 0, 'admin': 1 };
const ROLE_CAN_MANAGE = { 'admin': ['admin', 'user'], 'user': [] };

function normalizeRole(role) {
    if (role === 'super_admin' || role === 'admin') return 'admin';
    return 'user';
}

async function getUserRole(supabase, userId, email, env) {
    try {
        const { data: { user }, error } = await supabase.auth.admin.getUserById(userId);
        if (!error && user?.user_metadata?.role) return normalizeRole(user.user_metadata.role);
    } catch (_) { }
    try {
        const { data } = await supabase.from('profiles').select('role').eq('id', userId).single();
        if (data?.role) return normalizeRole(data.role);
    } catch (_) { }
    const adminEmails = (env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase());
    if (adminEmails.includes((email || '').toLowerCase())) return 'admin';
    return 'user';
}

async function requireRole(supabase, request, env, minRole) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) return null;
    try {
        const token = authHeader.split(' ')[1];
        const decoded = await verifyToken(token, env);
        const role = await getUserRole(supabase, decoded.id, decoded.email, env);
        if (ROLE_LEVEL[role] < ROLE_LEVEL[minRole]) return null;
        return { ...decoded, role };
    } catch (_) { return null; }
}

// ===== IP 获取 =====
function getIP(request) {
    return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
}

// ===== 辅助 =====
function escHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ===== 邮箱验证码 =====
function generateCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

// ===== 批量查找作者名称 =====
async function enrichAuthorNames(supabase, items) {
    if (!items || !items.length) return items;
    const authorIds = [...new Set(items.map(i => i.author_id).filter(Boolean))];
    if (!authorIds.length) return items;
    const { data: profiles } = await supabase.from('profiles').select('id, game_id, display_name').in('id', authorIds);
    const nameMap = {};
    if (profiles) profiles.forEach(p => { nameMap[p.id] = p.game_id || p.display_name || ''; });
    for (const id of authorIds) {
        if (nameMap[id]) continue;
        try {
            const { data: { user } } = await supabase.auth.admin.getUserById(id);
            if (user?.user_metadata) nameMap[id] = user.user_metadata.game_id || user.user_metadata.display_name || '';
        } catch (_) { }
    }
    return items.map(item => ({ ...item, author_name: nameMap[item.author_id] || (item.author_email || '').split('@')[0] }));
}

// ===== 辅助：记录IP尝试 =====
async function recordAttempt(supabase, ip, email) {
    try {
        await supabase.from('reg_attempts').insert({ ip, email, created_at: new Date().toISOString() });
    } catch (_) { }
}

async function checkRateLimit(supabase, ip) {
    try {
        const now = new Date();
        const tenMinAgo = new Date(now - 10 * 60 * 1000).toISOString();
        const { count: recent } = await supabase.from('reg_attempts').select('*', { count: 'exact', head: true }).eq('ip', ip).gte('created_at', tenMinAgo);
        if ((recent || 0) >= 5) return { blocked: true, reason: '操作太频繁，请10分钟后再试' };
        const dayAgo = new Date(now - 24 * 60 * 60 * 1000).toISOString();
        const { count: daily } = await supabase.from('reg_attempts').select('*', { count: 'exact', head: true }).eq('ip', ip).gte('created_at', dayAgo);
        if ((daily || 0) >= 15) return { blocked: true, reason: '该IP注册过于频繁，已封禁24小时' };
        return { blocked: false };
    } catch (_) { return { blocked: false }; }
}

// ===== 辅助：日志记录 =====
async function logLogin(supabase, email, ip, success, reason) {
    try { await supabase.from('login_logs').insert({ email, ip, success, reason: reason || null, created_at: new Date().toISOString() }); } catch (_) { }
}

async function logAudit(supabase, operator, action, target) {
    try { await supabase.from('audit_logs').insert({ operator_email: operator.email, operator_id: operator.id, action, target: target || null, created_at: new Date().toISOString() }); } catch (_) { }
}

// ===== 清理未验证 =====
async function cleanupUnverified(supabase) {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    let deleted = 0;
    const { data } = await supabase.auth.admin.listUsers({ page: 1, perPage: 100 });
    for (const u of (data?.users || [])) {
        if (!u.email_confirmed_at && u.created_at < fiveMinAgo) {
            try { await supabase.auth.admin.deleteUser(u.id); deleted++; } catch (_) { }
        }
    }
    return deleted;
}

// ===== 主路由 =====
export default {
    async fetch(request, env, ctx) {
        const supabase = getSupabase(env);
        const url = new URL(request.url);
        const path = url.pathname.replace(/^\/api\//, '').replace(/\/$/, '');

        // CORS 预检
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders() });
        }

        try {
            // ===== Auth 路由 =====
            if (path === 'login' && request.method === 'POST') {
                const { email, password } = await request.json();
                if (!email || !password) return jsonRes({ message: '请填写完整信息' }, 400);
                const ip = getIP(request);
                const { data, error } = await supabase.auth.signInWithPassword({ email, password });
                if (error) {
                    await logLogin(supabase, email, ip, false, error.message);
                    return jsonRes({ message: error.message }, 400);
                }
                await logLogin(supabase, email, ip, true);
                const token = await signToken(data.user.id, data.user.email, env);
                return jsonRes({ message: '登录成功', user: { email: data.user.email, id: data.user.id }, token });
            }

            if (path === 'register' && request.method === 'POST') {
                const { email, password, qq, game_id, _website, _ts } = await request.json();
                if (!email || !password) return jsonRes({ message: '请填写完整信息' }, 400);
                // 蜜罐
                if (_website && _website.length > 0) return jsonRes({ message: '注册成功！验证码已发送至您的邮箱', user: { email, id: 'fake' } }, 201);
                // 时间戳
                const now = Date.now();
                if (_ts && (now - parseInt(_ts) < 2000 || now - parseInt(_ts) > 600000)) return jsonRes({ message: '请稍后再试' }, 400);
                // IP限流
                const ip = getIP(request);
                const rateCheck = await checkRateLimit(supabase, ip);
                if (rateCheck.blocked) return jsonRes({ message: rateCheck.reason }, 429);
                // 安全化
                const safeQQ = String(qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
                const safeGameId = String(game_id || '').replace(/[<>]/g, '').slice(0, 32);

                const { data, error } = await supabase.auth.admin.createUser({
                    email, password, email_confirm: false,
                    user_metadata: { qq: safeQQ, game_id: safeGameId }
                });
                if (error) {
                    if (error.message?.includes('already been registered')) {
                        const { data: users } = await supabase.auth.admin.listUsers();
                        const existing = (users.users || []).find(u => u.email === email);
                        if (existing) {
                            if (existing.email_confirmed_at) return jsonRes({ message: '该邮箱已注册并验证，请直接登录' }, 400);
                            const code = generateCode();
                            await supabase.from('verification_codes').insert({
                                user_id: existing.id, code, type: 'email_verify',
                                expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString()
                            });
                            await sendVerificationEmail(email, code, env);
                            return jsonRes({ message: '重新发送了验证码', user: { email: existing.email, id: existing.id } });
                        }
                    }
                    return jsonRes({ message: error.message }, 400);
                }
                await recordAttempt(supabase, ip, email);
                const code = generateCode();
                await supabase.from('verification_codes').insert({
                    user_id: data.user.id, code, type: 'email_verify',
                    expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString()
                });
                await sendVerificationEmail(email, code, env);
                return jsonRes({ message: '注册成功！验证码已发送至您的邮箱', user: { email: data.user.email, id: data.user.id } }, 201);
            }

            if (path === 'verify-email' && request.method === 'POST') {
                const { email, code } = await request.json();
                if (!email || !code) return jsonRes({ message: '请提供邮箱和验证码' }, 400);
                const { data: users, error } = await supabase.auth.admin.listUsers();
                if (error) return jsonRes({ message: error.message }, 500);
                const user = (users.users || []).find(u => u.email === email);
                if (!user) return jsonRes({ message: '用户不存在' }, 404);
                const { data: vcode } = await supabase.from('verification_codes').select('*').eq('user_id', user.id).eq('code', code).eq('type', 'email_verify').gt('expires_at', new Date().toISOString()).order('created_at', { ascending: false }).limit(1).single();
                if (!vcode) return jsonRes({ message: '验证码无效或已过期' }, 400);
                await supabase.auth.admin.updateUserById(user.id, { email_confirm: true });
                await supabase.from('verification_codes').delete().eq('id', vcode.id);
                return jsonRes({ message: '邮箱验证成功！' });
            }

            if (path === 'reset-password' && request.method === 'POST') {
                const { email } = await request.json();
                if (!email) return jsonRes({ message: '请输入邮箱' }, 400);
                const siteUrl = env.SITE_URL || 'https://tr114512.github.io/light-snow-town/';
                const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo: siteUrl + '?reset=true' });
                if (error) return jsonRes({ message: error.message }, 400);
                return jsonRes({ message: '重置邮件已发送' });
            }

            if (path === 'change-password' && request.method === 'POST') {
                const authHeader = request.headers.get('Authorization');
                if (!authHeader) return jsonRes({ message: '未登录' }, 401);
                const token = authHeader.split(' ')[1];
                let decoded;
                try { decoded = await verifyToken(token, env); } catch (_) { return jsonRes({ message: 'Token无效' }, 401); }
                const { oldPassword, newPassword } = await request.json();
                if (!oldPassword || !newPassword) return jsonRes({ message: '请填写完整信息' }, 400);
                if (newPassword.length < 8) return jsonRes({ message: '新密码至少8位' }, 400);
                const { data: { user }, error: ue } = await supabase.auth.admin.getUserById(decoded.id);
                if (ue || !user) return jsonRes({ message: '用户不存在' }, 400);
                const { error: signInErr } = await supabase.auth.signInWithPassword({ email: user.email, password: oldPassword });
                if (signInErr) return jsonRes({ message: '当前密码错误' }, 400);
                const { error: updateErr } = await supabase.auth.admin.updateUserById(decoded.id, { password: newPassword });
                if (updateErr) return jsonRes({ message: updateErr.message }, 400);
                return jsonRes({ message: '密码已更新' });
            }

            if (path === 'me') {
                const authHeader = request.headers.get('Authorization');
                if (!authHeader) return jsonRes({ message: '未登录' }, 401);
                try {
                    const token = authHeader.split(' ')[1];
                    const decoded = await verifyToken(token, env);
                    const { data: { user }, error } = await supabase.auth.admin.getUserById(decoded.id);
                    if (error || !user) return jsonRes({ message: '用户不存在' }, 404);
                    const role = await getUserRole(supabase, user.id, user.email, env);
                    const { data: profile } = await supabase.from('profiles').select('qq, game_id, display_name').eq('id', user.id).single();
                    return jsonRes({ user: {
                        email: user.email, id: user.id, role,
                        qq: profile?.qq || user.user_metadata?.qq || '',
                        game_id: profile?.game_id || user.user_metadata?.game_id || '',
                        display_name: profile?.display_name || '',
                        created_at: user.created_at,
                        email_confirmed_at: user.email_confirmed_at
                    }});
                } catch (_) { return jsonRes({ message: 'Token无效' }, 401); }
            }

            if (path === 'update-profile' && request.method === 'POST') {
                const authHeader = request.headers.get('Authorization');
                if (!authHeader) return jsonRes({ message: '未登录' }, 401);
                const token = authHeader.split(' ')[1];
                let decoded;
                try { decoded = await verifyToken(token, env); } catch (_) { return jsonRes({ message: 'Token无效' }, 401); }
                const body = await request.json();
                const safeQQ = String(body.qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
                const safeGameId = String(body.game_id || '').replace(/[<>]/g, '').slice(0, 32);
                await supabase.from('profiles').upsert({ id: decoded.id, qq: safeQQ, game_id: safeGameId, updated_at: new Date().toISOString() });
                await supabase.auth.admin.updateUserById(decoded.id, { user_metadata: { qq: safeQQ, game_id: safeGameId } });
                return jsonRes({ message: '资料已更新' });
            }

            // ===== Admin 路由 =====
            if (path === 'admin/users') {
                const operator = await requireRole(supabase, request, env, 'admin');
                if (!operator) return jsonRes({ message: '未登录或权限不足' }, 401);

                if (request.method === 'POST') {
                    const { action, userIds } = await request.json();
                    if (action === 'cleanup') {
                        const count = await cleanupUnverified(supabase);
                        return jsonRes({ message: `已清理 ${count} 个未验证账号` });
                    }
                    if (action === 'batch-delete' && Array.isArray(userIds)) {
                        let deleted = 0;
                        for (const uid of userIds) {
                            if (uid === operator.id) continue;
                            try { await supabase.auth.admin.deleteUser(uid); deleted++; } catch (_) { }
                        }
                        return jsonRes({ message: `已删除 ${deleted} 个用户` });
                    }
                    return jsonRes({ message: '无效操作' }, 400);
                }

                // GET: 用户列表
                const { search, verified } = Object.fromEntries(url.searchParams);
                let allUsers = [];
                for (let page = 1; page <= 4; page++) {
                    const { data } = await supabase.auth.admin.listUsers({ page, perPage: 500 });
                    const batch = data?.users || [];
                    allUsers = allUsers.concat(batch);
                    if (batch.length < 500) break;
                }
                const { data: profiles } = await supabase.from('profiles').select('id, role, display_name, qq, game_id');
                const roleMap = {};
                if (profiles) profiles.forEach(p => { roleMap[p.id] = { role: p.role, display_name: p.display_name, qq: p.qq, game_id: p.game_id }; });

                let userList = allUsers.map(u => {
                    const rawRole = u.user_metadata?.role || roleMap[u.id]?.role || 'user';
                    return {
                        id: u.id, email: u.email,
                        role: normalizeRole(rawRole),
                        qq: roleMap[u.id]?.qq || u.user_metadata?.qq || '',
                        game_id: roleMap[u.id]?.game_id || u.user_metadata?.game_id || '',
                        display_name: roleMap[u.id]?.display_name || '',
                        email_confirmed: !!u.email_confirmed_at,
                        created_at: u.created_at,
                        last_sign_in: u.last_sign_in_at
                    };
                });

                if (verified === '1') userList = userList.filter(u => u.email_confirmed);
                if (search) { const q = search.toLowerCase(); userList = userList.filter(u => u.email.toLowerCase().includes(q)); }
                userList.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

                // CSV 导出
                if (url.searchParams.get('format') === 'csv') {
                    const header = '编号,邮箱,QQ,游戏ID,状态,角色,注册时间\n';
                    const rows = userList.map((u, i) => `${i+1},"${u.email}","${u.qq||''}","${u.game_id||''}",${u.email_confirmed?'已验证':'未验证'},${u.role==='admin'?'管理员':'玩家'},"${new Date(u.created_at).toLocaleDateString('zh-CN')}"`).join('\n');
                    return new Response('\uFEFF' + header + rows, {
                        headers: { ...corsHeaders(), 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename=users.csv' }
                    });
                }

                return jsonRes({ total: userList.length, operator_role: operator.role, users: userList.map((u, i) => ({ ...u, user_no: i + 1 })) });
            }

            if (path === 'admin/dashboard') {
                const operator = await requireRole(supabase, request, env, 'admin');
                if (!operator) return jsonRes({ message: '未登录或权限不足' }, 401);
                let totalUsers = 0, verified = 0, unverified = 0, todayReg = 0;
                const today = new Date().toISOString().slice(0, 10);
                for (let page = 1; page <= 4; page++) {
                    const { data } = await supabase.auth.admin.listUsers({ page, perPage: 500 });
                    const users = data?.users || [];
                    if (!users.length) break;
                    totalUsers += users.length;
                    for (const u of users) {
                        if (u.email_confirmed_at) verified++; else unverified++;
                        if (u.created_at?.startsWith(today)) todayReg++;
                    }
                }
                const { count: totalQ } = await supabase.from('questions').select('*', { count: 'exact', head: true });
                const { count: openQ } = await supabase.from('questions').select('*', { count: 'exact', head: true }).eq('status', 'open');
                return jsonRes({ stats: { totalUsers, verified, unverified, todayReg, totalQuestions: totalQ || 0, openQuestions: openQ || 0 } });
            }

            if (path === 'admin/delete-user' && request.method === 'POST') {
                const operator = await requireRole(supabase, request, env, 'admin');
                if (!operator) return jsonRes({ message: '未登录或权限不足' }, 401);
                const { userId } = await request.json();
                if (!userId || userId === operator.id) return jsonRes({ message: '无效操作' }, 400);
                const { data: { user } } = await supabase.auth.admin.getUserById(userId);
                if (!user) return jsonRes({ message: '用户不存在' }, 404);
                const { error } = await supabase.auth.admin.deleteUser(userId);
                if (error) return jsonRes({ message: error.message }, 500);
                await logAudit(supabase, operator, '删除用户', user.email);
                return jsonRes({ message: `已删除用户 ${user.email}` });
            }

            if (path === 'admin/reset-user-password' && request.method === 'POST') {
                const operator = await requireRole(supabase, request, env, 'admin');
                if (!operator) return jsonRes({ message: '未登录或权限不足' }, 401);
                const { userId, newPassword } = await request.json();
                if (!userId || !newPassword || newPassword.length < 8) return jsonRes({ message: '请提供有效信息' }, 400);
                const { data: { user } } = await supabase.auth.admin.getUserById(userId);
                if (!user) return jsonRes({ message: '用户不存在' }, 404);
                const { error } = await supabase.auth.admin.updateUserById(userId, { password: newPassword });
                if (error) return jsonRes({ message: error.message }, 500);
                await logAudit(supabase, operator, '重置密码', user.email);
                return jsonRes({ message: `已重置用户 ${user.email} 的密码` });
            }

            if (path === 'admin/set-role' && request.method === 'POST') {
                const operator = await requireRole(supabase, request, env, 'admin');
                if (!operator) return jsonRes({ message: '未登录或权限不足' }, 401);
                const { userId, role } = await request.json();
                const VALID_ROLES = ['admin', 'user'];
                if (!userId || !role || !VALID_ROLES.includes(role) || userId === operator.id) return jsonRes({ message: '无效操作' }, 400);
                const { data: { user } } = await supabase.auth.admin.getUserById(userId);
                if (!user) return jsonRes({ message: '用户不存在' }, 404);
                await supabase.auth.admin.updateUserById(userId, { user_metadata: { role } });
                await supabase.from('profiles').upsert({ id: userId, role, updated_at: new Date().toISOString() });
                await logAudit(supabase, operator, `设置角色为${role}`, user.email);
                return jsonRes({ message: `已将用户 ${user.email} 的角色更新为 ${role}` });
            }

            // ===== QA 路由 =====
            if (path === 'qa/questions') {
                if (request.method === 'POST') {
                    const authHeader = request.headers.get('Authorization');
                    if (!authHeader) return jsonRes({ message: '请先登录' }, 401);
                    let decoded;
                    try { decoded = await verifyToken(authHeader.split(' ')[1], env); } catch (_) { return jsonRes({ message: 'Token无效' }, 401); }
                    const { title, content } = await request.json();
                    if (!title || !content || title.length > 200 || content.length > 5000) return jsonRes({ message: '请填写有效内容' }, 400);
                    const { data: maxRow } = await supabase.from('questions').select('question_number').order('question_number', { ascending: false }).limit(1).single();
                    const nextNum = (maxRow?.question_number || 0) + 1;
                    const { data, error } = await supabase.from('questions').insert({ question_number: nextNum, author_id: decoded.id, author_email: decoded.email, title, content }).select().single();
                    if (error) return jsonRes({ message: error.message }, 500);
                    return jsonRes({ question: data, message: '问题已发布' }, 201);
                }

                // GET
                const qid = url.searchParams.get('id');
                if (qid) {
                    const { data: q, error } = await supabase.from('questions').select('*').eq('id', qid).single();
                    if (error || !q) return jsonRes({ message: '问题不存在' }, 404);
                    const { data: answers } = await supabase.from('answers').select('*').eq('question_id', qid).order('created_at', { ascending: true });
                    const { data: comments } = await supabase.from('comments').select('*').eq('question_id', qid).order('created_at', { ascending: true });
                    const allItems = [q, ...(answers || []), ...(comments || [])];
                    const enriched = await enrichAuthorNames(supabase, allItems);
                    return jsonRes({ question: enriched[0], answers: enriched.slice(1, 1 + (answers || []).length), comments: enriched.slice(1 + (answers || []).length) });
                }

                // 列表
                const { search, my, author, page: rawPage, limit: rawLimit } = Object.fromEntries(url.searchParams);
                const page = parseInt(rawPage) || 1;
                const limit = Math.min(parseInt(rawLimit) || 20, 50);
                const offset = (page - 1) * limit;
                let query = supabase.from('questions').select('*', { count: 'exact' }).order('created_at', { ascending: false });
                if (search) query = query.ilike('title', `%${search}%`);
                if (my === '1') {
                    const authHeader = request.headers.get('Authorization');
                    if (!authHeader) return jsonRes({ message: '请先登录' }, 401);
                    try { const decoded = await verifyToken(authHeader.split(' ')[1], env); query = query.eq('author_id', decoded.id); }
                    catch (_) { return jsonRes({ message: 'Token无效' }, 401); }
                }
                if (author) query = query.eq('author_id', author);
                const { data: questions, count: total, error: qErr } = await query.range(offset, offset + limit - 1);
                if (qErr) return jsonRes({ message: qErr.message }, 500);
                const enriched = await enrichAuthorNames(supabase, questions || []);
                for (const q of enriched) {
                    const { count: ac } = await supabase.from('answers').select('*', { count: 'exact', head: true }).eq('question_id', q.id);
                    const { count: cc } = await supabase.from('comments').select('*', { count: 'exact', head: true }).eq('question_id', q.id);
                    q.answer_count = ac || 0; q.comment_count = cc || 0;
                }
                return jsonRes({ questions: enriched, total: total || 0, page, limit, totalPages: Math.ceil((total || 0) / limit) });
            }

            if (path === 'qa/answer' && request.method === 'POST') {
                const operator = await requireRole(supabase, request, env, 'admin');
                if (!operator) return jsonRes({ message: '未登录或权限不足' }, 401);
                const { question_id, content } = await request.json();
                if (!question_id || !content || content.length > 5000) return jsonRes({ message: '请填写有效内容' }, 400);
                const { data, error } = await supabase.from('answers').insert({ question_id, author_id: operator.id, author_email: operator.email, content, is_admin_answer: true }).select().single();
                if (error) return jsonRes({ message: error.message }, 500);
                await supabase.from('questions').update({ status: 'answered', updated_at: new Date().toISOString() }).eq('id', question_id);
                return jsonRes({ answer: data, message: '回答已发布' });
            }

            if (path === 'qa/comment' && request.method === 'POST') {
                const authHeader = request.headers.get('Authorization');
                if (!authHeader) return jsonRes({ message: '请先登录' }, 401);
                let decoded;
                try { decoded = await verifyToken(authHeader.split(' ')[1], env); } catch (_) { return jsonRes({ message: 'Token无效' }, 401); }
                const { question_id, content } = await request.json();
                if (!question_id || !content || content.length > 2000) return jsonRes({ message: '请填写有效内容' }, 400);
                const { data, error } = await supabase.from('comments').insert({ question_id, author_id: decoded.id, author_email: decoded.email, content }).select().single();
                if (error) return jsonRes({ message: error.message }, 500);
                return jsonRes({ comment: data, message: '评论已发布' });
            }

            if (path === 'qa/delete' && request.method === 'POST') {
                const operator = await requireRole(supabase, request, env, 'admin');
                if (!operator) return jsonRes({ message: '未登录或权限不足' }, 401);
                const { question_id } = await request.json();
                if (!question_id) return jsonRes({ message: '请提供问题ID' }, 400);
                const { error } = await supabase.from('questions').delete().eq('id', question_id);
                if (error) return jsonRes({ message: error.message }, 500);
                return jsonRes({ message: '问题已删除' });
            }

            if (path === 'ping' || path === '') {
                return jsonRes({ ok: true, time: new Date().toISOString(), platform: 'Cloudflare Workers' });
            }

            return jsonRes({ message: `未知接口: ${path}` }, 404);

        } catch (e) {
            console.error(e);
            return jsonRes({ message: '服务器内部错误' }, 500);
        }
    }
};
