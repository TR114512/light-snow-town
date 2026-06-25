const { supabase, jsonRes, requireRole, getUserRole } = require('../_utils');

// ===== 操作日志 =====
async function logAudit(operator, action, target) {
    try {
        await supabase.from('audit_logs').insert({
            operator_email: operator.email,
            operator_id: operator.id,
            action,
            target: target || null,
            created_at: new Date().toISOString()
        });
    } catch (_) { /* 表不存在则跳过 */ }
}

// ===== 辅助：清理超过5分钟未验证的账号 =====
async function cleanupUnverified() {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    let deleted = 0;
    // 只检查最新100个用户
    const { data } = await supabase.auth.admin.listUsers({ page: 1, perPage: 100 });
    const users = data?.users || [];
    for (const u of users) {
        if (!u.email_confirmed_at && u.created_at < fiveMinAgo) {
            try {
                await supabase.auth.admin.deleteUser(u.id);
                deleted++;
            } catch (_) { /* skip */ }
        }
    }
    return deleted;
}

// ===== 用户列表 =====
async function users(req, res) {
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    // POST：批量删除或清理
    if (req.method === 'POST') {
        const { action, userIds } = req.body || {};
        if (action === 'cleanup') {
            const count = await cleanupUnverified();
            return jsonRes(res, 200, { message: `已清理 ${count} 个未验证账号` });
        }
        if (action === 'batch-delete' && Array.isArray(userIds) && userIds.length) {
            let deleted = 0;
            for (const uid of userIds) {
                if (uid === operator.id) continue; // 不能删自己
                try { await supabase.auth.admin.deleteUser(uid); deleted++; }
                catch (_) { /* skip */ }
            }
            return jsonRes(res, 200, { message: `已删除 ${deleted} 个用户` });
        }
        return jsonRes(res, 400, { message: '无效操作' });
    }

    try {
        // 分页拉取全部用户（默认仅 50 条）
        let allUsers = [];
        let page = 1;
        const perPage = 500;
        while (true) {
            const { data, error } = await supabase.auth.admin.listUsers({ page, perPage });
            if (error) return jsonRes(res, 500, { message: error.message });
            const batch = data?.users || [];
            allUsers = allUsers.concat(batch);
            if (batch.length < perPage) break;
            page++;
        }

        const { data: profiles } = await supabase
            .from('profiles')
            .select('id, role, display_name, qq, game_id');

        const roleMap = {};
        if (profiles) {
            profiles.forEach(p => { roleMap[p.id] = { role: p.role, display_name: p.display_name, qq: p.qq, game_id: p.game_id }; });
        }

        const userList = allUsers.map(u => {
            const rawRole = (u.user_metadata && u.user_metadata.role) || roleMap[u.id]?.role || 'user';
            // 兼容旧 super_admin
            const role = (rawRole === 'super_admin') ? 'admin' : rawRole;
            return {
            id: u.id,
            email: u.email,
            role,
            qq: roleMap[u.id]?.qq || (u.user_metadata && u.user_metadata.qq) || '',
            game_id: roleMap[u.id]?.game_id || (u.user_metadata && u.user_metadata.game_id) || '',
            display_name: roleMap[u.id]?.display_name || '',
            email_confirmed: !!u.email_confirmed_at,
            created_at: u.created_at,
            last_sign_in: u.last_sign_in_at
        };
        });

        const { search, all, verified } = req.query || {};
        let filtered = userList;

        // ?verified=1 只看已验证
        if (verified === '1') {
            filtered = filtered.filter(u => u.email_confirmed);
        }

        if (search) {
            const q = search.toLowerCase();
            filtered = filtered.filter(u => u.email.toLowerCase().includes(q));
        }

        // 按注册时间排序，保证编号稳定
        filtered.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

        // CSV 导出
        if ((req.query || {}).format === 'csv') {
            const header = '编号,邮箱,QQ,游戏ID,状态,角色,注册时间\n';
            const rows = filtered.map((u, i) => {
                const status = u.email_confirmed ? '已验证' : '未验证';
                const role = u.role === 'admin' ? '管理员' : '玩家';
                return `${i+1},"${u.email}","${u.qq||''}","${u.game_id||''}",${status},${role},"${new Date(u.created_at).toLocaleDateString('zh-CN')}"`;
            }).join('\n');
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename=users.csv');
            // 添加 BOM 让 Excel 识别中文
            return res.status(200).send('\uFEFF' + header + rows);
        }

        jsonRes(res, 200, {
            total: filtered.length,
            operator_role: operator.role,
            users: filtered.map((u, i) => ({ ...u, user_no: i + 1 }))
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

        await logAudit(operator, '删除用户', user.email);
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

        await logAudit(operator, '重置密码', user.email);
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

        await logAudit(operator, `设置角色为${role}`, user.email);
        jsonRes(res, 200, { message: `已将用户 ${user.email} 的角色更新为 ${role}` });
    } catch (err) {
        console.error('Set role error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 仪表盘 =====
async function dashboard(req, res) {
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    try {
        // 总用户数
        let totalUsers = 0, verified = 0, unverified = 0, todayReg = 0;
        const today = new Date().toISOString().slice(0, 10);
        for (let page = 1; page <= 4; page++) {
            const { data } = await supabase.auth.admin.listUsers({ page, perPage: 500 });
            const users = data?.users || [];
            if (!users.length) break;
            totalUsers += users.length;
            for (const u of users) {
                if (u.email_confirmed_at) verified++;
                else unverified++;
                if (u.created_at?.startsWith(today)) todayReg++;
            }
        }

        // 问题统计
        const { count: totalQuestions } = await supabase.from('questions').select('*', { count: 'exact', head: true });
        const { count: openQuestions } = await supabase.from('questions').select('*', { count: 'exact', head: true }).eq('status', 'open');

        jsonRes(res, 200, {
            stats: {
                totalUsers, verified, unverified, todayReg,
                totalQuestions: totalQuestions || 0,
                openQuestions: openQuestions || 0
            }
        });
    } catch (e) {
        jsonRes(res, 500, { message: '服务器错误' });
    }
}

module.exports = { users, dashboard, deleteUser, resetUserPassword, setRole };
