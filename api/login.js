const { jsonRes, handleOptions } = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;  // 处理 OPTIONS 请求
    // ... 原有逻辑
};
module.exports = async (req, res) => {
    if (req.method !== 'POST') return jsonRes(res, 405, {});
    const { email, password } = req.body;

    const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password
    });

    if (error) return jsonRes(res, 400, { message: error.message });

    // 自定义 JWT（也可直接返回 supabase 的 access_token）
    const token = signToken(data.user.id, data.user.email);
    jsonRes(res, 200, {
        message: '登录成功',
        user: { email: data.user.email, id: data.user.id },
        token
    });
};