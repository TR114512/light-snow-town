const { supabase, jsonRes, handleOptions, requireRole } = require('../_utils');
const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    // 只有管理员能回答
    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    const { question_id, content } = req.body;
    if (!question_id || !content) return jsonRes(res, 400, { message: '请提供问题ID和回答内容' });

    try {
        const { data, error } = await supabase
            .from('answers')
            .insert({
                question_id,
                author_id: operator.id,
                author_email: operator.email,
                content,
                is_admin_answer: true
            })
            .select()
            .single();

        if (error) return jsonRes(res, 500, { message: error.message });

        // 标记问题为已回复
        await supabase.from('questions').update({ status: 'answered', updated_at: new Date().toISOString() }).eq('id', question_id);

        return jsonRes(res, 200, { answer: data, message: '回答已发布' });
    } catch (e) {
        return jsonRes(res, 500, { message: '服务器错误' });
    }
};
