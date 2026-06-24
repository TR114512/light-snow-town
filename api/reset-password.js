const { supabase, jsonRes, handleOptions } = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const { email } = req.body;
    if (!email) {
        return jsonRes(res, 400, { message: '请输入邮箱' });
    }

    try {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: 'https://tr114512.github.io/light-snow-town/index.html?reset=true'
        });

        if (error) {
            return jsonRes(res, 400, { message: error.message });
        }

        jsonRes(res, 200, { message: '重置邮件已发送' });
    } catch (err) {
        console.error(err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
};