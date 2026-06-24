const {
    supabase,
    jsonRes,
    handleOptions,
    verifyAndDeleteCode
} = require('./_utils');

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
        // 根据邮箱获取用户 ID
        const { data: user, error: userError } = await supabase
            .from('auth.users')
            .select('id')
            .eq('email', email)
            .single();

        if (userError || !user) {
            return jsonRes(res, 404, { message: '用户不存在' });
        }

        const isValid = await verifyAndDeleteCode(user.id, code, 'email_verification');
        if (!isValid) {
            return jsonRes(res, 400, { message: '验证码无效或已过期' });
        }

        // 更新邮箱确认状态
        const { error: updateError } = await supabase.auth.admin.updateUserById(user.id, {
            email_confirm: true
        });

        if (updateError) {
            console.error('Update error:', updateError);
            return jsonRes(res, 400, { message: updateError.message });
        }

        jsonRes(res, 200, { message: '邮箱验证成功' });
    } catch (err) {
        console.error('Unexpected error:', err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};