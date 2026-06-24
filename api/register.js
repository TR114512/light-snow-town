const { supabase, jsonRes, handleOptions } = require('./_utils');

module.exports = async (req, res) => {
    // 处理 OPTIONS 预检请求
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { email, password } = req.body;
    if (!email || !password) {
        return jsonRes(res, 400, { message: '请填写完整' });
    }

    const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: { emailRedirectTo: 'https://tr114512.github.io/light-snow-town/index.html' } // 替换为您的真实前端地址
    });

    if (error) return jsonRes(res, 400, { message: error.message });

    jsonRes(res, 200, {
        message: '注册成功，请查收确认邮件',
        user: { email: data.user.email, id: data.user.id }
    });
};