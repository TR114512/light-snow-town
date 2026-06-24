const { supabase, jsonRes, handleOptions, requireRole } = require('../_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    // admin 及以上可查看用户列表
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    try {
        const { data: { users }, error } = await supabase.auth.admin.listUsers();

        if (error) {
            return jsonRes(res, 500, { message: error.message });
        }

        // 获取 profiles 表
        const { data: profiles } = await supabase
            .from('profiles')
            .select('id, role, display_name');

        const roleMap = {};
        if (profiles) {
            profiles.forEach(p => { roleMap[p.id] = { role: p.role, display_name: p.display_name }; });
        }

        const userList = users.map(u => ({
            id: u.id,
            email: u.email,
            role: roleMap[u.id]?.role || 'user',
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
        console.error('Admin users error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
};
