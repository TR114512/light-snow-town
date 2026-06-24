const { supabase, jsonRes, handleOptions } = require('../_utils');
const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
    if (handleOptions(req, res)) return;

    // GET = 列表 或 详情(?id=X)
    if (req.method === 'GET') {
        const qid = (req.query || {}).id;
        if (qid) {
            // 详情
            try {
                const { data: q, error } = await supabase.from('questions').select('*').eq('id', qid).single();
                if (error || !q) return jsonRes(res, 404, { message: '问题不存在' });
                const { data: answers } = await supabase.from('answers').select('*').eq('question_id', qid).order('created_at', { ascending: true });
                const { data: comments } = await supabase.from('comments').select('*').eq('question_id', qid).order('created_at', { ascending: true });
                return jsonRes(res, 200, { question: q, answers: answers || [], comments: comments || [] });
            } catch (e) { return jsonRes(res, 500, { message: '服务器错误' }); }
        }

        // 列表
        try {
            const { data: questions, error } = await supabase
                .from('questions')
                .select('*')
                .order('created_at', { ascending: false });

            if (error) return jsonRes(res, 500, { message: error.message });

            // 每个问题附带回答数和评论数
            for (const q of questions) {
                const { count: ac } = await supabase.from('answers').select('*', { count: 'exact', head: true }).eq('question_id', q.id);
                const { count: cc } = await supabase.from('comments').select('*', { count: 'exact', head: true }).eq('question_id', q.id);
                q.answer_count = ac || 0;
                q.comment_count = cc || 0;
            }

            return jsonRes(res, 200, { questions });
        } catch (e) {
            return jsonRes(res, 500, { message: '服务器错误' });
        }
    }

    if (req.method === 'POST') {
        const authHeader = req.headers.authorization;
        if (!authHeader) return jsonRes(res, 401, { message: '请先登录' });

        const token = authHeader.split(' ')[1];
        let decoded;
        try { decoded = jwt.verify(token, process.env.JWT_SECRET); }
        catch (_) { return jsonRes(res, 401, { message: 'Token 无效' }); }

        const { title, content } = req.body;
        if (!title || !content) return jsonRes(res, 400, { message: '请填写标题和内容' });

        try {
            const { data, error } = await supabase
                .from('questions')
                .insert({
                    author_id: decoded.id,
                    author_email: decoded.email,
                    title,
                    content,
                    status: 'open'
                })
                .select()
                .single();

            if (error) return jsonRes(res, 500, { message: error.message });
            return jsonRes(res, 200, { question: data, message: '问题已提交' });
        } catch (e) {
            return jsonRes(res, 500, { message: '服务器错误' });
        }
    }

    return jsonRes(res, 405, { message: 'Method not allowed' });
};
