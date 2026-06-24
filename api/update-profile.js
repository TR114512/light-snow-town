const { supabase, jsonRes, handleOptions } = require('./_utils');
const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    if (req.method !== 'POST') {
        return jsonRes(res, 405, { message: 'Method not allowed' });
    }

    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return jsonRes(res, 401, { message: '未登录' });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
        return jsonRes(res, 401, { message: 'Token 无效' });
    }

    const { qq, game_id } = req.body;

    try {
        const { error } = await supabase
            .from('profiles')
            .upsert({
                id: decoded.id,
                qq: qq || '',
                game_id: game_id || '',
                updated_at: new Date().toISOString()
            });

        if (error) {
            return jsonRes(res, 500, { message: error.message });
        }

        // 同步到 user_metadata
        await supabase.auth.admin.updateUserById(decoded.id, {
            user_metadata: { qq: qq || '', game_id: game_id || '' }
        });

        jsonRes(res, 200, { message: '资料已更新' });
    } catch (err) {
        console.error('Update profile error:', err);
        jsonRes(res, 500, { message: '服务器错误' });
    }
};
