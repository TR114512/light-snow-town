const { supabase, jsonRes, handleOptions } = require('../_utils');
const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const authHeader = req.headers.authorization;
    if (!authHeader) return jsonRes(res, 401, { message: '请先登录' });

    const token = authHeader.split(' ')[1];
    let decoded;
    try { decoded = jwt.verify(token, process.env.JWT_SECRET); }
    catch (_) { return jsonRes(res, 401, { message: 'Token 无效' }); }

    const { question_id, content } = req.body;
    if (!question_id || !content) return jsonRes(res, 400, { message: '请提供问题ID和评论内容' });

    try {
        const { data, error } = await supabase
            .from('comments')
            .insert({
                question_id,
                author_id: decoded.id,
                author_email: decoded.email,
                content
            })
            .select()
            .single();

        if (error) return jsonRes(res, 500, { message: error.message });
        return jsonRes(res, 200, { comment: data, message: '评论已发布' });
    } catch (e) {
        return jsonRes(res, 500, { message: '服务器错误' });
    }
};
