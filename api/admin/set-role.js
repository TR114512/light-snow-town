const { supabase, jsonRes, handleOptions, requireRole, getUserRole } = require('../_utils');

const VALID_ROLES = ['super_admin', 'admin', 'user'];

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { userId, role } = req.body;
    if (!userId || !role) {
        return jsonRes(res, 400, { message: '请提供 userId 和 role' });
    }
    if (!VALID_ROLES.includes(role)) {
        return jsonRes(res, 400, { message: '角色只能是: ' + VALID_ROLES.join(', ') });
    }
    if (userId === operator.id) {
        return jsonRes(res, 400, { message: '不能修改自己的角色' });
    }

    try {
        // 查目标用户
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
        if (userError || !user) {
            return jsonRes(res, 404, { message: '用户不存在: ' + (userError?.message || '') });
        }

        // 目标用户当前角色
        const targetRole = await getUserRole(userId, user.email);

        // super_admin 保护
        if ((targetRole === 'admin' || targetRole === 'super_admin') && operator.role !== 'super_admin') {
            return jsonRes(res, 403, { message: '只有超级管理员才能管理管理员账号' });
        }
        if (role === 'super_admin') {
            return jsonRes(res, 403, { message: '超级管理员只能通过数据库设置' });
        }

        // 直接用 admin API 更新 user_metadata 存储角色（绕过 RLS）
        const { error: updateError } = await supabase.auth.admin.updateUserById(userId, {
            user_metadata: { role: role }
        });

        // 同时也更新 profiles 表
        const { error: upsertError } = await supabase
            .from('profiles')
            .upsert({ id: userId, email: user.email, role: role, updated_at: new Date().toISOString() });

        if (upsertError) {
            console.error('Profiles upsert error:', upsertError);
            // profiles 更新失败不影响，metadata 已更新
        }

        if (updateError) {
            console.error('Update user error:', updateError);
            return jsonRes(res, 500, { message: updateError.message });
        }

        jsonRes(res, 200, {
            message: `已将 ${user.email} 的角色从 ${targetRole} 改为 ${role}`,
            user: { id: userId, email: user.email, role: role }
        });
    } catch (err) {
        console.error('Set role error:', err);
        jsonRes(res, 500, { message: '服务器错误: ' + (err.message || '') });
    }
};
