const { supabase, jsonRes, handleOptions, getUserRole } = require('./_utils');
const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return jsonRes(res, 401, { message: '未登录' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { data: { user }, error } = await supabase.auth.admin.getUserById(decoded.id);
        if (error || !user) {
            return jsonRes(res, 404, { message: '用户不存在' });
        }
        const role = await getUserRole(user.id, user.email);
        // 也查 profiles 获取 QQ 和游戏 ID
        const { data: profile } = await supabase
            .from('profiles')
            .select('qq, game_id, display_name')
            .eq('id', user.id)
            .single();

        jsonRes(res, 200, {
            user: {
                email: user.email,
                id: user.id,
                role: role,
                qq: (profile && profile.qq) || (user.user_metadata && user.user_metadata.qq) || '',
                game_id: (profile && profile.game_id) || (user.user_metadata && user.user_metadata.game_id) || '',
                display_name: (profile && profile.display_name) || '',
                created_at: user.created_at,
                email_confirmed_at: user.email_confirmed_at
            }
        });
    } catch (e) {
        jsonRes(res, 401, { message: 'Token 无效' });
    }
};