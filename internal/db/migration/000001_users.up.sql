CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE "users" (
  "id" uuid PRIMARY KEY NOT NULL,--DEFAULT uuid_generate_v4(),
  "name" varchar,
  "email" varchar UNIQUE NOT NULL,
  "username" varchar UNIQUE,
  "password_hash" varchar NOT NULL,
  "created_at" TIMESTAMPTZ DEFAULT (now()),
  "updated_at" timestamptz,
  -- "last_login" timestamptz,
  "is_suspended" boolean NOT NULL,
  "is_verified" BOOLEAN DEFAULT false,
  "is_email_verified" boolean DEFAULT false,
  "is_deleted" boolean NOT NULL,
  "login_attempts" int,
  "lockout_duration" int,
  "lockout_until" timestamptz,
  "password_changed_at" timestamptz,
  "deleted_at" timestamptz,
  "suspended_at" timestamptz,
  "email_verified_at" timestamptz
);

CREATE INDEX ON "users" ("email", "username", "created_at", "updated_at");