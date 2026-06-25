const { supabase, jsonRes, requireRole, getUserRole } = require('../_utils');

// ===== 退信检测（QQ邮箱 IMAP） =====
async function checkBounces() {
    let bounces = [];
    try {
        const { ImapFlow } = require('imapflow');
        const client = new ImapFlow({
            host: 'imap.qq.com',
            port: 993,
            secure: true,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
            logger: false
        });

        await client.connect();
        // 打开收件箱
        await client.mailboxOpen('INBOX');

        // 搜索最近7天内来自 PostMaster@qq.com 的邮件
        const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const list = [];
        for await (const msg of client.fetch({ from: 'postmaster@qq.com', since }, { uid: true, envelope: true, bodyStructure: true })) {
            list.push(msg);
        }

        // 只取最近20封
        const recent = list.slice(-20);
        for (const msg of recent) {
            try {
                const { data } = await client.download(msg.uid, '1');
                const text = data.toString('utf8');
                // 从退信内容中提取无效的收件人邮箱
                const bounced = extractBouncedEmail(text);
                if (bounced) {
                    bounces.push({
                        email: bounced.email,
                        reason: bounced.reason || '邮箱不存在',
                        time: msg.envelope.date?.toISOString() || ''
                    });
                }
            } catch (_) { /* skip */ }
        }

        await client.logout();
    } catch (e) {
        console.error('IMAP bounce check error:', e.message);
    }
    return bounces;
}

// 从退信正文提取无效收件人邮箱
function extractBouncedEmail(text) {
    // QQ退信格式: "无法发送到 xxx@xxx.com" 或 "收件人邮件地址（xxx@xxx.com）不存在"
    const patterns = [
        /无法发送到[：:\s]*([^\s<]+@[^\s>]+)/,
        /收件人[邮件地址]*[（(]([^\s)]+@[^\s)]+)/,
        /<([^>]+@[^>]+)>[^<]*不存在/,
        /投递失败[：:]\s*([^\s]+@[^\s]+)/,
        /mailbox\s+not\s+found.*?([^\s]+@[^\s]+)/i,
        /user\s+not\s+found.*?([^\s]+@[^\s]+)/i,
        /address\s+rejected.*?([^\s]+@[^\s]+)/i,
    ];
    for (const re of patterns) {
        const m = text.match(re);
        if (m) return { email: m[1].replace(/[<>]/g, ''), reason: '邮箱不存在或无法接收' };
    }
    // 也尝试匹配 Subject 行中的邮箱
    const subjMatch = text.match(/Subject:.*?([^\s<>]+@[^\s<>]+)/);
    if (subjMatch) return { email: subjMatch[1], reason: '投递失败' };
    return null;
}

// ===== 辅助：清理超过5分钟未验证的账号 =====
async function cleanupUnverified() {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    let deleted = 0;
    let page = 1;
    while (true) {
        const { data } = await supabase.auth.admin.listUsers({ page, perPage: 500 });
        const users = data?.users || [];
        if (!users.length) break;
        for (const u of users) {
            if (!u.email_confirmed_at && u.created_at < fiveMinAgo) {
                try {
                    await supabase.auth.admin.deleteUser(u.id);
                    deleted++;
                } catch (_) { /* skip */ }
            }
        }
        if (users.length < 500) break;
        page++;
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
        }        if (action === 'check-bounces') {
            const bounces = await checkBounces();
            return jsonRes(res, 200, { bounces, message: `检测到 ${bounces.length} 封退信` });
        }        return jsonRes(res, 400, { message: '无效操作' });
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
