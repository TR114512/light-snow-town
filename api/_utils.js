const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const jwtSecret = process.env.JWT_SECRET;

// 服务端 Supabase 客户端（使用 service_role key，绕过 RLS）
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// 生成 JWT（用于自定义 session，也可直接使用 supabase 的 session）
function signToken(userId, email) {
    return jwt.sign({ id: userId, email }, jwtSecret, { expiresIn: '7d' });
}

// 统一响应
function jsonRes(res, status, data) {
    res.status(status).json(data);
}

module.exports = { supabase, signToken, jsonRes };