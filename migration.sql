-- ============================================================
-- ZnGuess Supabase 数据库迁移脚本 (全量版)
-- 在 Supabase 后台 → SQL Editor → 粘贴运行
-- 如果已运行过旧版，可只运行下方 "-- ★ V2 增量部分 ★" 标记的语句
-- ============================================================

-- ============================================
-- V1: 基础表结构（如已运行可跳过）
-- ============================================
CREATE TABLE IF NOT EXISTS puzzles (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id     UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  page        INT NOT NULL DEFAULT 0,
  sort_order  INT NOT NULL DEFAULT 0,
  title       TEXT DEFAULT '',
  sl          TEXT DEFAULT '',
  reward      TEXT DEFAULT '0pts',
  content     TEXT DEFAULT '',
  answer      TEXT DEFAULT '',
  cracker     TEXT DEFAULT '',
  true_reward INT DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_puzzles_page ON puzzles(page, sort_order);
CREATE INDEX IF NOT EXISTS idx_puzzles_user ON puzzles(user_id);

-- ★ V2 增量部分 ★ 添加作者名字段
ALTER TABLE puzzles ADD COLUMN IF NOT EXISTS author_name TEXT DEFAULT '游客';

-- ============================================
-- V2: 用户资料表
-- ============================================
CREATE TABLE IF NOT EXISTS profiles (
  user_id    UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  username   TEXT UNIQUE NOT NULL,
  is_admin   BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- V2: 管理员判断函数 (SECURITY DEFINER 绕过 RLS)
-- ============================================
CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE user_id = auth.uid() AND is_admin = TRUE
  );
$$ LANGUAGE sql SECURITY DEFINER STABLE;

-- ============================================
-- V2: 重设 RLS 策略（先删后建）
-- ============================================
ALTER TABLE puzzles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "public_read" ON puzzles;
DROP POLICY IF EXISTS "auth_insert" ON puzzles;
DROP POLICY IF EXISTS "auth_update" ON puzzles;
DROP POLICY IF EXISTS "auth_delete" ON puzzles;
DROP POLICY IF EXISTS "public_insert" ON puzzles;
DROP POLICY IF EXISTS "owner_admin_update" ON puzzles;
DROP POLICY IF EXISTS "owner_admin_delete" ON puzzles;

-- 任何人都可以查看
CREATE POLICY "public_read" ON puzzles
  FOR SELECT USING (true);

-- 任何人都可以新增（游客 user_id=NULL，登录用户带上自己的 uid）
CREATE POLICY "public_insert" ON puzzles
  FOR INSERT WITH CHECK (true);

-- 只有题目作者或管理员可以修改
CREATE POLICY "owner_admin_update" ON puzzles
  FOR UPDATE USING (
    auth.role() = 'authenticated'
    AND (user_id = auth.uid() OR is_admin())
  );

-- 只有题目作者或管理员可以删除
CREATE POLICY "owner_admin_delete" ON puzzles
  FOR DELETE USING (
    auth.role() = 'authenticated'
    AND (user_id = auth.uid() OR is_admin())
  );

-- ============================================
-- V2: profiles 表的 RLS
-- ============================================
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "public_read_profiles" ON profiles;
DROP POLICY IF EXISTS "owner_insert_profile" ON profiles;
DROP POLICY IF EXISTS "owner_update_profile" ON profiles;

-- 所有人可查看用户名
CREATE POLICY "public_read_profiles" ON profiles
  FOR SELECT USING (true);

-- 只能创建自己的资料
CREATE POLICY "owner_insert_profile" ON profiles
  FOR INSERT WITH CHECK (user_id = auth.uid());

-- 只能修改自己的资料（防止自己给自己提权为 admin）
CREATE POLICY "owner_update_profile" ON profiles
  FOR UPDATE USING (user_id = auth.uid());

-- ============================================
-- V2: 排名视图
-- ============================================
CREATE OR REPLACE VIEW rankings AS
  SELECT
    cracker AS name,
    SUM(true_reward) AS total_pts,
    COUNT(*) AS cracked_count
  FROM puzzles
  WHERE cracker <> ''
  GROUP BY cracker
  ORDER BY total_pts DESC;

-- ============================================
-- 修补已有数据的 author_name
-- ============================================
UPDATE puzzles SET author_name = '游客' WHERE author_name IS NULL;

-- ============================================
-- V3: 防提权触发器 —— 阻止客户端 API 设置 is_admin=TRUE
-- 只有 SQL Editor（auth.uid() IS NULL）可以授予管理员
-- ============================================
CREATE OR REPLACE FUNCTION check_admin_escalation()
RETURNS TRIGGER AS $$
BEGIN
  -- SQL Editor / 后台直接操作 → 放行
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;
  -- 客户端 API 调用：禁止将 is_admin 从 FALSE 改成 TRUE
  IF NEW.is_admin = TRUE AND (OLD IS NULL OR OLD.is_admin = FALSE) THEN
    RAISE EXCEPTION '禁止提权：只有现有管理员才能授予管理员权限';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS check_admin_escalation_insert ON profiles;
CREATE TRIGGER check_admin_escalation_insert
  BEFORE INSERT ON profiles
  FOR EACH ROW EXECUTE FUNCTION check_admin_escalation();

DROP TRIGGER IF EXISTS check_admin_escalation_update ON profiles;
CREATE TRIGGER check_admin_escalation_update
  BEFORE UPDATE ON profiles
  FOR EACH ROW EXECUTE FUNCTION check_admin_escalation();

-- ============================================
-- 设置管理员（替换 '你的用户名' 为实际值）
-- 1. 先在网页上注册并设置好用户名
-- 2. 在这里填入你的用户名，运行这一行 SQL
-- 3. 必须在 SQL Editor 中运行（不能在浏览器控制台执行）
-- 4. 设置后需要重新登录，让 JWT 拿到新的 is_admin 声明
-- ============================================
-- UPDATE profiles SET is_admin = TRUE WHERE username = '你的用户名';

-- ============================================================
-- ★ V4: Auth Hook —— 登录时自动把 is_admin 注入 JWT ★
-- 运行后需要在 Supabase 后台绑定此 Hook:
--   Authentication → Settings → Custom Access Token Hook
--   选择 public.custom_access_token_hook
-- ============================================================
CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event JSONB)
RETURNS JSONB AS $$
DECLARE
  claims JSONB;
  admin_val BOOLEAN;
BEGIN
  claims = COALESCE(event->'claims', '{}'::JSONB);

  -- 查 profiles 表获取 admin 状态
  SELECT is_admin INTO admin_val
  FROM public.profiles
  WHERE user_id = (event->>'user_id')::UUID;

  -- 注入到 app_metadata（客户端可读）和 user_metadata
  claims = jsonb_set(claims, '{app_metadata,is_admin}',
    CASE WHEN admin_val THEN 'true' ELSE 'false' END);
  claims = jsonb_set(claims, '{user_metadata,is_admin}',
    CASE WHEN admin_val THEN 'true' ELSE 'false' END);

  event = jsonb_set(event, '{claims}', claims);
  RETURN event;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- V4: 更新 RLS 策略 —— 同时检查 JWT claims 和数据库
-- JWT 为主（零查询），is_admin() 为 fallback
-- ============================================

-- 修复 INSERT 嫁祸漏洞：user_id 只能是 NULL 或自己
DROP POLICY IF EXISTS "public_insert" ON puzzles;
CREATE POLICY "public_insert" ON puzzles FOR INSERT WITH CHECK (
  user_id IS NULL
  OR user_id = auth.uid()
  OR is_admin()  -- 管理员可为他人创建
);

-- UPDATE: JWT claims 优先，is_admin() 兜底（token 未刷新时）
DROP POLICY IF EXISTS "owner_admin_update" ON puzzles;
CREATE POLICY "owner_admin_update" ON puzzles FOR UPDATE USING (
  auth.role() = 'authenticated'
  AND (
    user_id = auth.uid()
    OR auth.jwt()->'app_metadata'->>'is_admin' = 'true'
    OR is_admin()
  )
);

-- DELETE: 同上
DROP POLICY IF EXISTS "owner_admin_delete" ON puzzles;
CREATE POLICY "owner_admin_delete" ON puzzles FOR DELETE USING (
  auth.role() = 'authenticated'
  AND (
    user_id = auth.uid()
    OR auth.jwt()->'app_metadata'->>'is_admin' = 'true'
    OR is_admin()
  )
);
