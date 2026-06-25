const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const jwtSecret = process.env.JWT_SECRET;

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// ===== 邮件发送（QQ邮箱） =====
const transporter = nodemailer.createTransport({
    host: 'smtp.qq.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function sendVerificationEmail(email, code) {
    await transporter.sendMail({
        from: `"灯雪镇" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: '【灯雪镇】邮箱验证码',
        html: `<p>您的验证码是：<strong style="font-size:24px;letter-spacing:4px;">${code}</strong></p><p>10分钟内有效，请勿透露给他人。</p>`
    });
}

function signToken(userId, email) {
    return jwt.sign({ id: userId, email }, jwtSecret, { expiresIn: '7d' });
}

// ===== CORS 处理 =====
function setCorsHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function jsonRes(res, status, data) {
    setCorsHeaders(res);
    res.status(status).json(data);
}

function handleOptions(req, res) {
    if (req.method === 'OPTIONS') {
        setCorsHeaders(res);
        res.status(200).end();
        return true;
    }
    return false;
}

// 注意：邮件发送完全由 Supabase Auth 接管
// - 注册确认邮件：Supabase signUp() 自动发送
// - 密码重置邮件：Supabase resetPasswordForEmail() 自动发送
// 无需配置 EMAIL_USER / EMAIL_PASS 环境变量

// ===== 角色权限系统 =====

// 角色层级（数字越大权限越高）
const ROLE_LEVEL = {
    'user':       0,
    'admin':      2,
    'super_admin': 3
};

// 角色可管理的下级角色
const ROLE_CAN_MANAGE = {
    'super_admin': ['admin', 'user'],
    'admin':       ['user'],
    'user':        []
};

// 权限对应的最低角色要求
const PERMISSION_ROLE = {
    'users.list':    'admin',
    'users.set_role': 'admin',
    'users.delete':  'admin',
    'admins.manage': 'super_admin'
};

// 查角色：user_metadata 优先（绕过 RLS），profiles 表兜底
async function getUserRole(userId, email) {
    try {
        // 1. 先查 user_metadata（set-role 写在这里，RLS 拦不住）
        const { data: { user }, error: ue } = await supabase.auth.admin.getUserById(userId);
        if (!ue && user && user.user_metadata && user.user_metadata.role) {
            return user.user_metadata.role;
        }
    } catch (_) { /* 继续 */ }

    try {
        // 2. 再查 profiles 表
        const { data, error } = await supabase
            .from('profiles')
            .select('role')
            .eq('id', userId)
            .single();
        if (!error && data && data.role) return data.role;
    } catch (_) { /* 继续 */ }

    // 3. 环境变量兜底
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase());
    if (adminEmails.includes((email || '').toLowerCase())) return 'super_admin';
    return 'user';
}

// 检查用户是否拥有某权限
async function hasPermission(userId, email, permission) {
    const requiredRole = PERMISSION_ROLE[permission];
    if (!requiredRole) return false;
    const userRole = await getUserRole(userId, email);
    return ROLE_LEVEL[userRole] >= ROLE_LEVEL[requiredRole];
}

// 检查操作者能否管理目标用户的角色
function canManageRole(operatorRole, targetRole) {
    const allowedRoles = ROLE_CAN_MANAGE[operatorRole] || [];
    return allowedRoles.includes(targetRole);
}

// 通用鉴权中间件，需要至少某角色
async function requireRole(req, res, minRole) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        jsonRes(res, 401, { message: '未登录' });
        return null;
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, jwtSecret);
        const role = await getUserRole(decoded.id, decoded.email);
        if (ROLE_LEVEL[role] < ROLE_LEVEL[minRole]) {
            jsonRes(res, 403, { message: `需要 ${minRole} 或更高权限` });
            return null;
        }
        return { ...decoded, role };
    } catch (e) {
        jsonRes(res, 401, { message: 'Token 无效' });
        return null;
    }
}

// 兼容旧代码
async function requireAdmin(req, res) {
    return requireRole(req, res, 'admin');
}

module.exports = {
    supabase,
    signToken,
    jsonRes,
    handleOptions,
    getUserRole,
    requireAdmin,
    requireRole,
    hasPermission,
    canManageRole,
    ROLE_LEVEL,
    ROLE_CAN_MANAGE,
    sendVerificationEmail
};