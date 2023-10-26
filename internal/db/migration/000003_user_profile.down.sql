-- Drop foreign key constraints
ALTER TABLE "user_profiles" DROP CONSTRAINT IF EXISTS "user_profiles_user_id_fkey";
ALTER TABLE "user_roles" DROP CONSTRAINT IF EXISTS "user_roles_user_id_fkey";
ALTER TABLE "user_roles" DROP CONSTRAINT IF EXISTS "user_roles_role_id_fkey";
ALTER TABLE "email_verification_requests" DROP CONSTRAINT IF EXISTS "email_verification_requests_user_id_fkey";
ALTER TABLE "user_preferences" DROP CONSTRAINT IF EXISTS "user_preferences_user_id_fkey";

-- Drop indexes
DROP INDEX IF EXISTS "user_roles_role_id_idx";
DROP INDEX IF EXISTS "email_verification_requests_user_id_token_email_created_at_updated_at_idx";

-- Drop tables
DROP TABLE IF EXISTS "user_profiles";
DROP TABLE IF EXISTS "roles";
DROP TABLE IF EXISTS "user_roles";
DROP TABLE IF EXISTS "email_verification_requests";
DROP TABLE IF EXISTS "user_preferences";