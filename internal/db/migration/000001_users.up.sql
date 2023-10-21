CREATE TABLE "users" (
  "id" uuid PRIMARY KEY,
  "name" varchar,
  "email" varchar UNIQUE,
  "username" varchar UNIQUE,
  "password_hash" varchar,
  "created_at" current_timestamptz,
  "updated_at" timestamptz,
  "last_login" timestamptz,
  "is_suspended" boolean,
  "is_deleted" boolean,
  "login_attempts" int DEFAULT 0,
  "lockout_duration" int DEFAULT 60,
  "lockout_until" timestamptz
);

CREATE INDEX ON "users" ("email", "username", "created_at", "updated_at");