const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const jwtSecret = process.env.JWT_SECRET;

const supabase = createClient(supabaseUrl, supabaseServiceKey);

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

// ===== 邮件发送（使用你的 QQ 邮箱） =====
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
        html: `<p>您的验证码是：<strong>${code}</strong>，5分钟内有效。</p><p>请勿将验证码透露给他人。</p>`
    });
}

// ===== 验证码存储与校验 =====
async function saveVerificationCode(userId, code, type) {
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    const { error } = await supabase
        .from('verification_codes')
        .insert({ user_id: userId, code, type, expires_at: expiresAt.toISOString() });
    if (error) throw error;
}

async function verifyAndDeleteCode(userId, code, type) {
    const { data, error } = await supabase
        .from('verification_codes')
        .select('*')
        .eq('user_id', userId)
        .eq('code', code)
        .eq('type', type)
        .gt('expires_at', new Date().toISOString())
        .single();
    if (error || !data) return false;
    await supabase.from('verification_codes').delete().eq('id', data.id);
    return true;
}

module.exports = {
    supabase,
    signToken,
    jsonRes,
    handleOptions,
    sendVerificationEmail,
    saveVerificationCode,
    verifyAndDeleteCode
};