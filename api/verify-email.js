const { supabase, jsonRes, handleOptions } = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { email, code } = req.body;
    if (!email || !code) {
        return jsonRes(res, 400, { message: '请提供邮箱和验证码' });
    }

    try {
        // 先通过邮箱找用户
        const { data: users, error: listError } = await supabase.auth.admin.listUsers();
        if (listError) {
            return jsonRes(res, 500, { message: listError.message });
        }
        const user = users.users.find(u => u.email === email);
        if (!user) {
            return jsonRes(res, 404, { message: '用户不存在' });
        }

        // 查验证码
        const { data: vcode, error: codeError } = await supabase
            .from('verification_codes')
            .select('*')
            .eq('user_id', user.id)
            .eq('code', code)
            .eq('type', 'email_verify')
            .gt('expires_at', new Date().toISOString())
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (codeError || !vcode) {
            return jsonRes(res, 400, { message: '验证码无效或已过期' });
        }

        // 标记邮箱已确认
        await supabase.auth.admin.updateUserById(user.id, {
            email_confirm: true
        });

        // 删除已用验证码
        await supabase.from('verification_codes').delete().eq('id', vcode.id);

        jsonRes(res, 200, { message: '✅ 邮箱验证成功！' });
    } catch (err) {
        console.error('Verify error:', err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};