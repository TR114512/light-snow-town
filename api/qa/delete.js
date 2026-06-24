const { supabase, jsonRes, handleOptions, requireRole } = require('../_utils');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

    const operator = await requireRole(req, res, 'admin');
    if (!operator) return;

    const { question_id } = req.body;
    if (!question_id) return jsonRes(res, 400, { message: '请提供问题ID' });

    try {
        const { error } = await supabase.from('questions').delete().eq('id', question_id);
        if (error) return jsonRes(res, 500, { message: error.message });
        return jsonRes(res, 200, { message: '问题已删除' });
    } catch (e) {
        return jsonRes(res, 500, { message: '服务器错误' });
    }
};
