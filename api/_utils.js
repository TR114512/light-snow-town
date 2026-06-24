const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const jwtSecret = process.env.JWT_SECRET;

const supabase = createClient(supabaseUrl, supabaseServiceKey);

function signToken(userId, email) {
    return jwt.sign({ id: userId, email }, jwtSecret, { expiresIn: '7d' });
}

// ===== CORS 统一处理 =====
function setCorsHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');  // 生产环境可改为具体域名
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

module.exports = { supabase, signToken, jsonRes, handleOptions };