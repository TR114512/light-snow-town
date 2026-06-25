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

// ===== 注册 =====
async function register(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { email, password, qq, game_id } = req.body;
    if (!email || !password) return jsonRes(res, 400, { message: '请填写完整信息' });

    try {
        const { data, error } = await supabase.auth.admin.createUser({
            email,
            password,
            email_confirm: false,
            user_metadata: { qq: qq || '', game_id: game_id || '' }
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

    const { qq, game_id } = req.body;

    try {
        const { error } = await supabase
            .from('profiles')
            .upsert({
                id: decoded.id,
                qq: qq || '',
                game_id: game_id || '',
                updated_at: new Date().toISOString()
            });

        if (error) return jsonRes(res, 500, { message: error.message });

        await supabase.auth.admin.updateUserById(decoded.id, {
            user_metadata: { qq: qq || '', game_id: game_id || '' }
        });

        jsonRes(res, 200, { message: '资料已更新' });
    } catch (err) {
        console.error('Update profile error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

module.exports = { login, register, verifyEmail, resetPassword, changePassword, me, updateProfile };
