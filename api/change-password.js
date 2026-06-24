const { supabase, jsonRes } = require('./_utils');
const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
    if (req.method !== 'POST') return jsonRes(res, 405, {});
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

    // 获取当前用户
    const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(decoded.id);
    if (userError || !user) return jsonRes(res, 400, { message: '用户不存在' });

    // 验证旧密码（用登录方式验证）
    const { error: signInError } = await supabase.auth.signInWithPassword({
        email: user.email,
        password: oldPassword
    });
    if (signInError) return jsonRes(res, 400, { message: '当前密码错误' });

    // 更新密码（admin 方式可强制更新，但推荐使用用户自己的 update）
    // 注意：这里使用 admin 接口需谨慎，更好的做法是让用户自己更新，但需要 session。
    // 为了简便，我们直接使用 admin 更新，但建议先用用户 session 的 update。
    // 但 session 需要用户的 refresh token，我们用 admin 直接改（需谨慎）
    const { error: updateError } = await supabase.auth.admin.updateUserById(decoded.id, {
        password: newPassword
    });

    if (updateError) return jsonRes(res, 400, { message: updateError.message });

    jsonRes(res, 200, { message: '密码已更新' });
};