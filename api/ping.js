module.exports = (req, res) => {
    res.status(200).json({
        ok: true,
        time: new Date().toISOString(),
        env: {
            hasSupabaseUrl: !!process.env.SUPABASE_URL,
            hasServiceKey: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
            hasJwtSecret: !!process.env.JWT_SECRET
        }
    });
};
