-- Reversing the actions in the up migration

-- Drop foreign key constraints
ALTER TABLE "security_questions" DROP CONSTRAINT "security_questions_user_id_fkey";
ALTER TABLE "banned_users" DROP CONSTRAINT "banned_users_user_id_fkey";
ALTER TABLE "login_failures" DROP CONSTRAINT "login_failures_user_id_fkey";
ALTER TABLE "sessions" DROP CONSTRAINT "sessions_user_id_fkey";
ALTER TABLE "user_logins" DROP CONSTRAINT "user_logins_user_id_fkey";

-- Drop indexes
DROP INDEX IF EXISTS "banned_users_user_id_idx";
DROP INDEX IF EXISTS "login_failures_user_id_timestamp_idx";
DROP INDEX IF EXISTS "sessions_user_id_expires_at_idx";
DROP INDEX IF EXISTS "user_logins_user_id_login_at_idx";

-- Drop tables
DROP TABLE IF EXISTS "security_questions";
DROP TABLE IF EXISTS "banned_users";
DROP TABLE IF EXISTS "login_failures";
DROP TABLE IF EXISTS "sessions";
DROP TABLE IF EXISTS "user_logins";