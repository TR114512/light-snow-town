const { supabase, jsonRes } = require('./_utils');

module.exports = async (req, res) => {
    if (req.method !== 'POST') return jsonRes(res, 405, {});
    const { email } = req.body;

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: 'https://tr114512.github.io/light-snow-town/auth.html?reset=true'
    });

    if (error) return jsonRes(res, 400, { message: error.message });

    jsonRes(res, 200, { message: '重置邮件已发送' });
};