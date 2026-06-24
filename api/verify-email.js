const { supabase, jsonRes, handleOptions } = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { email } = req.body;
    if (!email) {
        return jsonRes(res, 400, { message: '请提供邮箱' });
    }

    try {
        // 通过 Supabase Admin API 查找用户并检查邮箱确认状态
        const { data: users, error: listError } = await supabase.auth.admin.listUsers();
        if (listError) {
            return jsonRes(res, 500, { message: listError.message });
        }

        const user = users.users.find(u => u.email === email);
        if (!user) {
            return jsonRes(res, 404, { message: '用户不存在' });
        }

        if (user.email_confirmed_at) {
            jsonRes(res, 200, { message: '邮箱已确认', confirmed: true });
        } else {
            jsonRes(res, 200, { message: '邮箱尚未确认，请检查邮箱点击确认链接', confirmed: false });
        }
    } catch (err) {
        console.error('Unexpected error:', err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};