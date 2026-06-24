const { supabase, jsonRes, handleOptions, requireRole } = require('../_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) {
        return jsonRes(res, 400, { message: '请提供 userId 和 newPassword' });
    }
    if (newPassword.length < 8) {
        return jsonRes(res, 400, { message: '密码至少8位' });
    }

    try {
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
        if (userError || !user) {
            return jsonRes(res, 404, { message: '用户不存在' });
        }

        const { error: updateError } = await supabase.auth.admin.updateUserById(userId, {
            password: newPassword
        });

        if (updateError) {
            return jsonRes(res, 500, { message: updateError.message });
        }

        jsonRes(res, 200, {
            message: `已重置用户 ${user.email} 的密码`
        });
    } catch (err) {
        console.error('Reset password error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
};
