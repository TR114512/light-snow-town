const { supabase, jsonRes, handleOptions } = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { email, password } = req.body;
    if (!email || !password) {
        return jsonRes(res, 400, { message: '请填写完整信息' });
    }

    try {
        // Supabase signUp 会自动发送确认邮件（无需自己写 SMTP）
        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                emailRedirectTo: process.env.SITE_URL || 'https://tr114512.github.io/light-snow-town/'
            }
        });

        if (error) {
            console.error('Supabase signUp error:', error);
            return jsonRes(res, 400, { message: error.message });
        }

        jsonRes(res, 200, {
            message: '注册成功！请检查邮箱并点击确认链接完成激活',
            user: { email: data.user.email, id: data.user.id }
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};