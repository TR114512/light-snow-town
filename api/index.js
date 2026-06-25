const { handleOptions, jsonRes } = require('./_utils');
const auth = require('./_handlers/auth');
const admin = require('./_handlers/admin');
const qa = require('./_handlers/qa');

// 路径 → 处理函数映射
const routes = {
    // Auth
    'login':           auth.login,
    'register':        auth.register,
    'verify-email':    auth.verifyEmail,
    'reset-password':  auth.resetPassword,
    'change-password': auth.changePassword,
    'me':              auth.me,
    'update-profile':  auth.updateProfile,

    // Admin
    'admin/users':                 admin.users,
    'admin/dashboard':             admin.dashboard,
    'admin/delete-user':           admin.deleteUser,
    'admin/reset-user-password':   admin.resetUserPassword,
    'admin/set-role':              admin.setRole,

    // QA
    'qa/questions':  qa.questions,
    'qa/answer':     qa.answer,
    'qa/comment':    qa.comment,
    'qa/delete':     qa.deleteQuestion,
};

module.exports = async (req, res) => {
    // 处理 CORS 预检
    if (handleOptions(req, res)) return;

    // 解析路径：req.url 可能是 "/api/login" 或 "/api/admin/users"
    const url = req.url || '';
    // 去掉查询参数
    const pathname = url.split('?')[0];
    // 去掉开头的 "/api/" 得到相对路径，如 "login" 或 "admin/users"
    let route = pathname.replace(/^\/api\//, '').replace(/\/$/, '');

    // 特殊处理：/api/ping
    if (route === 'ping' || route === '') {
        if (route === 'ping') {
            return res.status(200).json({
                ok: true,
                time: new Date().toISOString(),
                env: {
                    hasSupabaseUrl: !!process.env.SUPABASE_URL,
                    hasServiceKey: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
                    hasJwtSecret: !!process.env.JWT_SECRET
                }
            });
        }
        // /api 根路径
        return jsonRes(res, 200, { message: 'Light Snow Town API', version: '1.0.0' });
    }

    const handler = routes[route];
    if (!handler) {
        return jsonRes(res, 404, { message: `未知接口: /api/${route}` });
    }

    try {
        await handler(req, res);
    } catch (err) {
        console.error(`[${route}] Error:`, err);
        jsonRes(res, 500, { message: '服务器内部错误' });
    }
};
