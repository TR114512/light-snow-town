const { supabase, jsonRes, handleOptions, requireRole, getUserRole, canManageRole, ROLE_LEVEL } = require('../_utils');

const VALID_ROLES = ['super_admin', 'admin', 'moderator', 'user'];

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    // 需要 admin 或以上
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
        return jsonRes(res, 400, { message: `角色只能是: ${VALID_ROLES.join(', ')}` });
    }

    // 操作者不能给自己改角色（防止锁死）
    if (userId === operator.id) {
        return jsonRes(res, 400, { message: '不能修改自己的角色' });
    }

    try {
        // 查目标用户
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
        if (userError || !user) {
            return jsonRes(res, 404, { message: '用户不存在' });
        }

        // 查目标用户当前角色
        const targetRole = await getUserRole(userId, user.email);

        // 只有 super_admin 能管理 admin 角色
        if (targetRole === 'admin' || targetRole === 'super_admin') {
            if (operator.role !== 'super_admin') {
                return jsonRes(res, 403, { message: '只有超级管理员才能管理管理员账号' });
            }
        }

        // 不能设置比自己层级高或相等的角色
        if (ROLE_LEVEL[role] >= ROLE_LEVEL[operator.role] && operator.role !== 'super_admin') {
            return jsonRes(res, 403, { message: `不能设置 ${role} 角色，权限不足` });
        }

        // 超级管理员也不能把别人设成 super_admin（只能通过 SQL）
        if (role === 'super_admin' && operator.role === 'super_admin') {
            return jsonRes(res, 403, { message: '超级管理员只能通过数据库直接设置' });
        }

        // 更新角色
        const { error: upsertError } = await supabase
            .from('profiles')
            .upsert({
                id: userId,
                email: user.email,
                role: role,
                updated_at: new Date().toISOString()
            });

        if (upsertError) {
            return jsonRes(res, 500, { message: upsertError.message });
        }

        jsonRes(res, 200, {
            message: `已将 ${user.email} 的角色从 ${targetRole} 改为 ${role}`,
            user: { id: userId, email: user.email, role: role, previous_role: targetRole }
        });
    } catch (err) {
        console.error('Set role error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
};
