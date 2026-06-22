-- =============================================
-- 灯雪镇社区 Supabase 数据库建表 SQL
-- 请在 Supabase 后台 SQL Editor 中运行全部内容
-- =============================================

-- 1. 用户资料表
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT,
  nickname TEXT,
  avatar TEXT,
  city TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- RLS: 允许已认证用户读取所有资料
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "任何人可查看资料" ON public.profiles
  FOR SELECT USING (true);

CREATE POLICY "用户可更新自己的资料" ON public.profiles
  FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "用户可创建自己的资料" ON public.profiles
  FOR INSERT WITH CHECK (auth.uid() = id);


-- 2. 帖子表
CREATE TABLE IF NOT EXISTS public.posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  content TEXT,
  media_urls TEXT,
  city TEXT,
  like_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "任何人可查看帖子" ON public.posts
  FOR SELECT USING (true);

CREATE POLICY "已认证用户可发帖" ON public.posts
  FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "用户可删除自己的帖子" ON public.posts
  FOR DELETE USING (auth.uid() = user_id);


-- 3. 点赞表
CREATE TABLE IF NOT EXISTS public.likes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id UUID NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(post_id, user_id)
);

ALTER TABLE public.likes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "任何人可查看点赞" ON public.likes
  FOR SELECT USING (true);

CREATE POLICY "已认证用户可点赞" ON public.likes
  FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "用户可取消自己的点赞" ON public.likes
  FOR DELETE USING (auth.uid() = user_id);


-- 4. 创建存储桶 (需要在 Storage 页面手动创建或通过 SQL)
-- post-images 存储桶 - 用于图片上传
-- post-videos 存储桶 - 用于视频上传
-- 公开访问

-- 如果通过 SQL 创建 storage bucket:
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES 
  ('post-images', 'post-images', true, 10485760, '{image/jpeg,image/png,image/gif,image/webp}'),
  ('post-videos', 'post-videos', true, 52428800, '{video/mp4,video/webm,video/ogg}')
ON CONFLICT (id) DO NOTHING;

-- Storage 权限策略
CREATE POLICY "任何人可查看媒体文件" ON storage.objects
  FOR SELECT USING (bucket_id IN ('post-images', 'post-videos'));

CREATE POLICY "已认证用户可上传媒体" ON storage.objects
  FOR INSERT WITH CHECK (bucket_id IN ('post-images', 'post-videos') AND auth.role() = 'authenticated');
