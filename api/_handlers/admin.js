const { supabase, jsonRes, requireRole, getUserRole } = require('../_utils');

// ===== 用户列表 =====
async function users(req, res) {
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    try {
        const { data: { users }, error } = await supabase.auth.admin.listUsers();

        if (error) return jsonRes(res, 500, { message: error.message });

        const { data: profiles } = await supabase
            .from('profiles')
            .select('id, role, display_name, qq, game_id');

        const roleMap = {};
        if (profiles) {
            profiles.forEach(p => { roleMap[p.id] = { role: p.role, display_name: p.display_name, qq: p.qq, game_id: p.game_id }; });
        }

        const userList = users.map(u => ({
            id: u.id,
            email: u.email,
            role: (u.user_metadata && u.user_metadata.role) || roleMap[u.id]?.role || 'user',
            qq: roleMap[u.id]?.qq || (u.user_metadata && u.user_metadata.qq) || '',
            game_id: roleMap[u.id]?.game_id || (u.user_metadata && u.user_metadata.game_id) || '',
            display_name: roleMap[u.id]?.display_name || '',
            email_confirmed: !!u.email_confirmed_at,
            created_at: u.created_at,
            last_sign_in: u.last_sign_in_at
        }));

        const { search } = req.query || {};
        let filtered = userList;
        if (search) {
            const q = search.toLowerCase();
            filtered = userList.filter(u => u.email.toLowerCase().includes(q));
        }

        jsonRes(res, 200, {
            total: filtered.length,
            operator_role: operator.role,
            users: filtered
        });
    } catch (err) {
        console.error('List users error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 删除用户 =====
async function deleteUser(req, res) {
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { userId } = req.body;
    if (!userId) return jsonRes(res, 400, { message: '请提供 userId' });

    if (userId === operator.id) return jsonRes(res, 400, { message: '不能删除自己的账号' });

    try {
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
        if (userError || !user) return jsonRes(res, 404, { message: '用户不存在' });

        const targetRole = await getUserRole(userId, user.email);

        const { error: deleteError } = await supabase.auth.admin.deleteUser(userId);
        if (deleteError) return jsonRes(res, 500, { message: deleteError.message });

        jsonRes(res, 200, {
            message: `已删除用户 ${user.email}（原角色: ${targetRole}）`
        });
    } catch (err) {
        console.error('Delete user error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 重置用户密码 =====
async function resetUserPassword(req, res) {
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) return jsonRes(res, 400, { message: '请提供 userId 和 newPassword' });
    if (newPassword.length < 8) return jsonRes(res, 400, { message: '密码至少8位' });

    try {
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
        if (userError || !user) return jsonRes(res, 404, { message: '用户不存在' });

        const { error: updateError } = await supabase.auth.admin.updateUserById(userId, {
            password: newPassword
        });

        if (updateError) return jsonRes(res, 500, { message: updateError.message });

        jsonRes(res, 200, {
            message: `已重置用户 ${user.email} 的密码`
        });
    } catch (err) {
        console.error('Reset password error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 设置角色 =====
async function setRole(req, res) {
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const VALID_ROLES = ['admin', 'user'];
    const { userId, role } = req.body;
    if (!userId || !role) return jsonRes(res, 400, { message: '请提供 userId 和 role' });
    if (!VALID_ROLES.includes(role)) return jsonRes(res, 400, { message: '角色只能是: ' + VALID_ROLES.join(', ') });
    if (userId === operator.id) return jsonRes(res, 400, { message: '不能修改自己的角色' });

    try {
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
        if (userError || !user) return jsonRes(res, 404, { message: '用户不存在: ' + (userError?.message || '') });

        const targetRole = await getUserRole(userId, user.email);

        const { error: updateError } = await supabase.auth.admin.updateUserById(userId, {
            user_metadata: { role: role }
        });

        const { error: upsertError } = await supabase
            .from('profiles')
            .upsert({ id: userId, role: role, updated_at: new Date().toISOString() });

        if (updateError) return jsonRes(res, 500, { message: updateError.message });
        if (upsertError) console.error('Upsert profile role error:', upsertError);

        jsonRes(res, 200, { message: `已将用户 ${user.email} 的角色更新为 ${role}` });
    } catch (err) {
        console.error('Set role error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

module.exports = { users, deleteUser, resetUserPassword, setRole };
