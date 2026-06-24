const { jsonRes, handleOptions } = require('./_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;  // 处理 OPTIONS 请求
    // ... 原有逻辑
};

module.exports = async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return jsonRes(res, 401, { message: '未登录' });

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { data: { user }, error } = await supabase.auth.admin.getUserById(decoded.id);
        if (error || !user) return jsonRes(res, 404, { message: '用户不存在' });
        jsonRes(res, 200, { user: { email: user.email, id: user.id, created_at: user.created_at } });
    } catch (e) {
        jsonRes(res, 401, { message: 'Token 无效' });
    }
};