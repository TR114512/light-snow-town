const { supabase, jsonRes, handleOptions, requireRole, getUserRole } = require('../_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    // 需要 admin 或以上才能删除用户
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { userId } = req.body;
    if (!userId) {
        return jsonRes(res, 400, { message: '请提供 userId' });
    }

    // 不能删除自己
    if (userId === operator.id) {
        return jsonRes(res, 400, { message: '不能删除自己的账号' });
    }

    try {
        // 查目标用户
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
        if (userError || !user) {
            return jsonRes(res, 404, { message: '用户不存在' });
        }

        // 查目标用户角色
        const targetRole = await getUserRole(userId, user.email);

        // 只有 super_admin 能删除 admin/super_admin
        if ((targetRole === 'admin' || targetRole === 'super_admin') && operator.role !== 'super_admin') {
            return jsonRes(res, 403, { message: '只有超级管理员才能删除管理员账号' });
        }

        // 删除用户
        const { error: deleteError } = await supabase.auth.admin.deleteUser(userId);
        if (deleteError) {
            return jsonRes(res, 500, { message: deleteError.message });
        }

        jsonRes(res, 200, {
            message: `已删除用户 ${user.email}（原角色: ${targetRole}）`
        });
    } catch (err) {
        console.error('Delete user error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
};
