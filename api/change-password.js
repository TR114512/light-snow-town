const { supabase, jsonRes, handleOptions } = require('./_utils');
const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { oldPassword, newPassword } = req.body;
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return jsonRes(res, 401, { message: '未登录' });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
        return jsonRes(res, 401, { message: 'Token 无效' });
    }

    try {
        // 获取用户信息
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(decoded.id);
        if (userError || !user) {
            return jsonRes(res, 400, { message: '用户不存在' });
        }

        // 验证旧密码
        const { error: signInError } = await supabase.auth.signInWithPassword({
            email: user.email,
            password: oldPassword
        });
        if (signInError) {
            return jsonRes(res, 400, { message: '当前密码错误' });
        }

        // 更新密码
        const { error: updateError } = await supabase.auth.admin.updateUserById(decoded.id, {
            password: newPassword
        });

        if (updateError) {
            return jsonRes(res, 400, { message: updateError.message });
        }

        jsonRes(res, 200, { message: '密码已更新' });
    } catch (err) {
        console.error(err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
};