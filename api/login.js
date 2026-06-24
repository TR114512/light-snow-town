const { supabase, signToken, jsonRes, handleOptions } = require('./_utils');

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
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) {
            return jsonRes(res, 400, { message: error.message });
        }

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
};