const { supabase, jsonRes, handleOptions } = require('./_utils');

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
        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                emailRedirectTo: process.env.SITE_URL || '/',
                data: { qq: qq || '', game_id: game_id || '' }
            }
        });

        if (error) {
            console.error('Supabase signUp error:', error);
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

        // 生成6位验证码
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        await supabase.from('verification_codes').insert({
            user_id: data.user.id,
            code: code,
            type: 'email_verify',
            expires_at: expiresAt.toISOString()
        });

        jsonRes(res, 200, {
            message: '注册成功！请输入下方验证码完成激活',
            code: code,
            user: { email: data.user.email, id: data.user.id, qq: qq || '', game_id: game_id || '' }
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};