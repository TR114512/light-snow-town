const { supabase, jsonRes, handleOptions, sendVerificationEmail } = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { email, password, qq, game_id } = req.body;
    if (!email || !password) {
        return jsonRes(res, 400, { message: '请填写完整信息' });
    }

    try {
        // admin.createUser：创建用户但不发 Supabase 确认邮件
        const { data, error } = await supabase.auth.admin.createUser({
            email,
            password,
            email_confirm: false,
            user_metadata: { qq: qq || '', game_id: game_id || '' }
        });

        if (error) {
            // 用户已存在 → 如果未验证，重新发验证码
            if (error.message && error.message.includes('already been registered')) {
                // 找到已有用户
                const { data: users } = await supabase.auth.admin.listUsers();
                const existing = (users.users || []).find(u => u.email === email);
                if (existing) {
                    if (existing.email_confirmed_at) {
                        return jsonRes(res, 400, { message: '该邮箱已注册并验证，请直接登录' });
                    }
                    // 未验证 → 重新发码
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

        // 存 QQ 和游戏 ID 到 profiles
        await supabase.from('profiles').upsert({
            id: data.user.id,
            email: email,
            qq: qq || '',
            game_id: game_id || '',
            updated_at: new Date().toISOString()
        });

        // 生成6位验证码并发邮件
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        await supabase.from('verification_codes').insert({
            user_id: data.user.id,
            code: code,
            type: 'email_verify',
            expires_at: expiresAt.toISOString()
        });

        // 发邮件
        await sendVerificationEmail(email, code);

        jsonRes(res, 200, {
            message: '注册成功！验证码已发送至您的邮箱，请输入验证码完成激活',
            user: { email: data.user.email, id: data.user.id, qq: qq || '', game_id: game_id || '' }
        });
    } catch (err) {
        console.error('Register error:', err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};