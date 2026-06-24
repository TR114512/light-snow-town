const {
    supabase,
    jsonRes,
    handleOptions,
    sendVerificationEmail,
    saveVerificationCode
} = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { email, password } = req.body;
    if (!email || !password) {
        return jsonRes(res, 400, { message: '请填写完整信息' });
    }

    try {
        const { data, error } = await supabase.auth.signUp({ email, password });
        if (error) {
            console.error('Supabase signUp error:', error);
            return jsonRes(res, 400, { message: error.message });
        }

        const code = String(Math.floor(100000 + Math.random() * 900000));
        await saveVerificationCode(data.user.id, code, 'email_verification');
        await sendVerificationEmail(email, code);

        jsonRes(res, 200, {
            message: '注册成功，验证码已发送至您的邮箱',
            user: { email: data.user.email, id: data.user.id }
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};