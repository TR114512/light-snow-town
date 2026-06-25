const { supabase, signToken, jsonRes, sendVerificationEmail, getUserRole } = require('../_utils');
const jwt = require('jsonwebtoken');

// ===== 登录 =====
async function login(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { email, password } = req.body;
    if (!email || !password) return jsonRes(res, 400, { message: '请填写完整信息' });

    try {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) return jsonRes(res, 400, { message: error.message });

        const token = signToken(data.user.id, data.user.email);
        jsonRes(res, 200, {
            message: '登录成功',
            user: { email: data.user.email, id: data.user.id },
            token
        });
    } catch (err) {
        console.error(err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 注册反机器人保护 =====
const BLOCKED_DOMAINS = ['mailinator.com','tempmail.com','10minutemail.com','guerrillamail.com','sharklasers.com','yopmail.com','throwaway.email','trashmail.com','temp-mail.org','fakeinbox.com'];

async function checkRateLimit(ip) {
    try {
        const now = new Date();

        // 10分钟限制：最多5次
        const tenMinAgo = new Date(now - 10 * 60 * 1000).toISOString();
        const { count: recent } = await supabase.from('reg_attempts').select('*', { count: 'exact', head: true }).eq('ip', ip).gte('created_at', tenMinAgo);
        if ((recent || 0) >= 5) return { blocked: true, reason: '操作太频繁，请10分钟后再试' };

        // 24小时限制：最多15次，超过则封禁24小时
        const dayAgo = new Date(now - 24 * 60 * 60 * 1000).toISOString();
        const { count: daily } = await supabase.from('reg_attempts').select('*', { count: 'exact', head: true }).eq('ip', ip).gte('created_at', dayAgo);
        if ((daily || 0) >= 15) return { blocked: true, reason: '该IP注册过于频繁，已封禁24小时' };

        return { blocked: false };
    } catch (_) { return { blocked: false }; }
}

async function recordAttempt(ip, email) {
    try {
        // 同时清理24小时前的旧记录，避免表无限增长
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        await supabase.from('reg_attempts').delete().lt('created_at', dayAgo);
        await supabase.from('reg_attempts').insert({ ip, email, created_at: new Date().toISOString() });
    } catch (_) { /* 表不存在则跳过 */ }
}

// ===== 注册 =====
async function register(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { email, password, qq, game_id, _website, _ts } = req.body;
    if (!email || !password) return jsonRes(res, 400, { message: '请填写完整信息' });

    // 蜜罐字段：机器人会自动填写隐藏字段
    if (_website && _website.length > 0) {
        // 静默返回成功，迷惑机器人
        return jsonRes(res, 201, { message: '注册成功！验证码已发送至您的邮箱', user: { email, id: 'fake' } });
    }

    // 时间戳检查：表单提交必须花费至少2秒（机器人通常瞬间提交）
    const now = Date.now();
    if (_ts && (now - parseInt(_ts) < 2000 || now - parseInt(_ts) > 600000)) {
        return jsonRes(res, 400, { message: '请稍后再试' });
    }

    // 邮箱域名检查
    const domain = (email || '').split('@')[1]?.toLowerCase();
    if (domain && BLOCKED_DOMAINS.includes(domain)) {
        return jsonRes(res, 400, { message: '请使用常用邮箱注册' });
    }

    // IP 频率限制
    const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
    const rateCheck = await checkRateLimit(ip);
    if (rateCheck.blocked) {
        return jsonRes(res, 429, { message: rateCheck.reason });
    }

    // 输入验证：防注入 + 长度限制
    const safeQQ = String(qq || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
    const safeGameId = String(game_id || '').replace(/[<>]/g, '').slice(0, 32);

    try {
        await recordAttempt(ip, email);

        const { data, error } = await supabase.auth.admin.createUser({
            email,
            password,
            email_confirm: false,
            user_metadata: { qq: safeQQ, game_id: safeGameId }
        });

        if (error) {
            if (error.message && error.message.includes('already been registered')) {
                const { data: users } = await supabase.auth.admin.listUsers();
                const existing = (users.users || []).find(u => u.email === email);
                if (existing) {
                    if (existing.email_confirmed_at) {
                        return jsonRes(res, 400, { message: '该邮箱已注册并验证，请直接登录' });
                    }
                    const code = String(Math.floor(100000 + Math.random() * 900000));
                    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
                    await supabase.from('verification_codes').insert({
                        user_id: existing.id,
                        code: code,
                        type: 'email_verify',
                        expires_at: expiresAt.toISOString()
                    });
                    await sendVerificationEmail(email, code);
                    return jsonRes(res, 200, {
                        message: '该邮箱已注册但未验证，新的验证码已发送至您的邮箱',
                        user: { email: existing.email, id: existing.id }
                    });
                }
            }
            console.error('Supabase createUser error:', error);
            return jsonRes(res, 400, { message: error.message });
        }

        const newUser = data.user;
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
        await supabase.from('verification_codes').insert({
            user_id: newUser.id,
            code: code,
            type: 'email_verify',
            expires_at: expiresAt.toISOString()
        });
        await sendVerificationEmail(email, code);

        jsonRes(res, 201, {
            message: '注册成功！验证码已发送至您的邮箱',
            user: { email: newUser.email, id: newUser.id }
        });
    } catch (err) {
        console.error('Register error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 验证邮箱 =====
async function verifyEmail(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { email, code } = req.body;
    if (!email || !code) return jsonRes(res, 400, { message: '请提供邮箱和验证码' });

    try {
        const { data: users, error: listError } = await supabase.auth.admin.listUsers();
        if (listError) return jsonRes(res, 500, { message: listError.message });

        const user = users.users.find(u => u.email === email);
        if (!user) return jsonRes(res, 404, { message: '用户不存在' });

        const { data: vcode, error: codeError } = await supabase
            .from('verification_codes')
            .select('*')
            .eq('user_id', user.id)
            .eq('code', code)
            .eq('type', 'email_verify')
            .gt('expires_at', new Date().toISOString())
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (codeError || !vcode) return jsonRes(res, 400, { message: '验证码无效或已过期' });

        await supabase.auth.admin.updateUserById(user.id, { email_confirm: true });
        await supabase.from('verification_codes').delete().eq('id', vcode.id);

        jsonRes(res, 200, { message: '✅ 邮箱验证成功！' });
    } catch (err) {
        console.error('Verify email error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 重置密码（发送重置邮件）=====
async function resetPassword(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { email } = req.body;
    if (!email) return jsonRes(res, 400, { message: '请输入邮箱' });

    try {
        const siteUrl = process.env.SITE_URL || 'https://tr114512.github.io/light-snow-town/';
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: siteUrl + '?reset=true'
        });

        if (error) return jsonRes(res, 400, { message: error.message });

        jsonRes(res, 200, { message: '重置邮件已发送' });
    } catch (err) {
        console.error(err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 修改密码 =====
async function changePassword(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return jsonRes(res, 400, { message: '请填写完整信息' });
    if (newPassword.length < 8) return jsonRes(res, 400, { message: '新密码至少8位' });

    const authHeader = req.headers.authorization;
    if (!authHeader) return jsonRes(res, 401, { message: '未登录' });

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
        return jsonRes(res, 401, { message: 'Token 无效' });
    }

    try {
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(decoded.id);
        if (userError || !user) return jsonRes(res, 400, { message: '用户不存在' });

        const { error: signInError } = await supabase.auth.signInWithPassword({
            email: user.email,
            password: oldPassword
        });
        if (signInError) return jsonRes(res, 400, { message: '当前密码错误' });

        const { error: updateError } = await supabase.auth.admin.updateUserById(decoded.id, {
            password: newPassword
        });

        if (updateError) return jsonRes(res, 400, { message: updateError.message });

        jsonRes(res, 200, { message: '密码已更新' });
    } catch (err) {
        console.error('Change password error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 获取当前用户信息 =====
async function me(req, res) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return jsonRes(res, 401, { message: '未登录' });

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { data: { user }, error } = await supabase.auth.admin.getUserById(decoded.id);
        if (error || !user) return jsonRes(res, 404, { message: '用户不存在' });

        const role = await getUserRole(user.id, user.email);
        const { data: profile } = await supabase
            .from('profiles')
            .select('qq, game_id, display_name')
            .eq('id', user.id)
            .single();

        jsonRes(res, 200, {
            user: {
                email: user.email,
                id: user.id,
                role: role,
                qq: (profile && profile.qq) || (user.user_metadata && user.user_metadata.qq) || '',
                game_id: (profile && profile.game_id) || (user.user_metadata && user.user_metadata.game_id) || '',
                display_name: (profile && profile.display_name) || '',
                created_at: user.created_at,
                email_confirmed_at: user.email_confirmed_at
            }
        });
    } catch (e) {
        jsonRes(res, 401, { message: 'Token 无效' });
    }
}

// ===== 更新资料 =====
async function updateProfile(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const authHeader = req.headers.authorization;
    if (!authHeader) return jsonRes(res, 401, { message: '未登录' });

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
        return jsonRes(res, 401, { message: 'Token 无效' });
    }

    const rawQQ = qq || '';
    const rawGameId = game_id || '';
    const safeQQ = String(rawQQ).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20);
    const safeGameId = String(rawGameId).replace(/[<>]/g, '').slice(0, 32);

    try {
        const { error } = await supabase
            .from('profiles')
            .upsert({
                id: decoded.id,
                qq: safeQQ,
                game_id: safeGameId,
                updated_at: new Date().toISOString()
            });

        if (error) return jsonRes(res, 500, { message: error.message });

        await supabase.auth.admin.updateUserById(decoded.id, {
            user_metadata: { qq: safeQQ, game_id: safeGameId }
        });

        jsonRes(res, 200, { message: '资料已更新' });
    } catch (err) {
        console.error('Update profile error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

module.exports = { login, register, verifyEmail, resetPassword, changePassword, me, updateProfile };
