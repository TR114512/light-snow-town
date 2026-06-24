const { supabase, jsonRes } = require('./_utils');

module.exports = async (req, res) => {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });
    const { email, password } = req.body;

    if (!email || !password) {
        return jsonRes(res, 400, { message: '请填写完整' });
    }

    // 使用 Supabase Auth 注册（会发送确认邮件）
    const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
            emailRedirectTo: 'https://tr114512.github.io/auth.html' // 确认后跳转
        }
    });

    if (error) return jsonRes(res, 400, { message: error.message });

    // 注册成功，返回用户信息（但未确认）
    jsonRes(res, 200, {
        message: '注册成功，请查看邮箱并点击确认链接',
        user: { email: data.user.email, id: data.user.id }
    });
};