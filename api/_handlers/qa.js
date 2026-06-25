const { supabase, jsonRes, requireRole } = require('../_utils');
const jwt = require('jsonwebtoken');

// ===== 辅助：批量查找用户 game_id =====
async function enrichAuthorNames(items) {
    if (!items || !items.length) return items;
    const authorIds = [...new Set(items.map(i => i.author_id).filter(Boolean))];
    if (!authorIds.length) return items;

    // 批量查 profiles
    const { data: profiles } = await supabase
        .from('profiles')
        .select('id, game_id, display_name')
        .in('id', authorIds);

    const nameMap = {};
    if (profiles) {
        profiles.forEach(p => {
            nameMap[p.id] = p.game_id || p.display_name || '';
        });
    }

    // 兜底：查 user_metadata
    for (const id of authorIds) {
        if (nameMap[id]) continue;
        try {
            const { data: { user } } = await supabase.auth.admin.getUserById(id);
            if (user?.user_metadata) {
                nameMap[id] = user.user_metadata.game_id || user.user_metadata.display_name || '';
            }
        } catch (_) { /* skip */ }
    }

    return items.map(item => ({
        ...item,
        author_name: nameMap[item.author_id] || (item.author_email || '').split('@')[0]
    }));
}

// ===== 问题列表/详情/创建 =====
async function questions(req, res) {
    if (req.method === 'GET') {
        const qid = (req.query || {}).id;
        if (qid) {
            try {
                const { data: q, error } = await supabase.from('questions').select('*').eq('id', qid).single();
                if (error || !q) return jsonRes(res, 404, { message: '问题不存在' });
                const { data: answers } = await supabase.from('answers').select('*').eq('question_id', qid).order('created_at', { ascending: true });
                const { data: comments } = await supabase.from('comments').select('*').eq('question_id', qid).order('created_at', { ascending: true });

                // 收集所有作者 ID 并批量获取 game_id
                const allItems = [q, ...(answers || []), ...(comments || [])];
                const enriched = await enrichAuthorNames(allItems);

                return jsonRes(res, 200, {
                    question: enriched[0],
                    answers: enriched.slice(1, 1 + (answers || []).length),
                    comments: enriched.slice(1 + (answers || []).length)
                });
            } catch (e) { return jsonRes(res, 500, { message: '服务器错误' }); }
        }

        // 列表
        try {
            const { data: questions, error } = await supabase
                .from('questions')
                .select('*')
                .order('created_at', { ascending: false });

            if (error) return jsonRes(res, 500, { message: error.message });

            const enriched = await enrichAuthorNames(questions);

            for (const q of enriched) {
                const { count: ac } = await supabase.from('answers').select('*', { count: 'exact', head: true }).eq('question_id', q.id);
                const { count: cc } = await supabase.from('comments').select('*', { count: 'exact', head: true }).eq('question_id', q.id);
                q.answer_count = ac || 0;
                q.comment_count = cc || 0;
            }

            return jsonRes(res, 200, { questions: enriched });
        } catch (e) {
            return jsonRes(res, 500, { message: '服务器错误' });
        }
    }

    // POST = 创建问题
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
            // 手动计算编号：取当前最大编号 + 1（删除后不会留空洞）
            const { data: maxRow } = await supabase
                .from('questions')
                .select('question_number')
                .order('question_number', { ascending: false })
                .limit(1)
                .single();

            const nextNum = (maxRow?.question_number || 0) + 1;

            const { data, error } = await supabase
                .from('questions')
                .insert({
                    question_number: nextNum,
                    author_id: decoded.id,
                    author_email: decoded.email,
                    title,
                    content
                })
                .select()
                .single();

            if (error) return jsonRes(res, 500, { message: error.message });
            return jsonRes(res, 201, { question: data, message: '问题已发布' });
        } catch (e) {
            return jsonRes(res, 500, { message: '服务器错误' });
        }
    }

    return jsonRes(res, 405, { message: 'Method not allowed' });
}

// ===== 回答问题（仅管理员）=====
async function answer(req, res) {
    if (req.method !== 'POST') return jsonRes(res, 405, { message: 'Method not allowed' });

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

        await supabase.from('questions').update({ status: 'answered', updated_at: new Date().toISOString() }).eq('id', question_id);

        return jsonRes(res, 200, { answer: data, message: '回答已发布' });
    } catch (e) {
        return jsonRes(res, 500, { message: '服务器错误' });
    }
}

// ===== 评论 =====
async function comment(req, res) {
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
}

// ===== 删除问题（仅管理员）=====
async function deleteQuestion(req, res) {
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
}

module.exports = { questions, answer, comment, deleteQuestion };
