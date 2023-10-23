CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE "users" (
  "id" uuid PRIMARY KEY NOT NULL,--DEFAULT uuid_generate_v4(),
  "name" varchar,
  "email" varchar UNIQUE,
  "username" varchar UNIQUE,
  "password_hash" varchar NOT NULL,
  "created_at" TIMESTAMPTZ DEFAULT (now()),
  "updated_at" timestamptz,
  "last_login" timestamptz,
  "is_suspended" boolean,
  "is_verified" BOOLEAN DEFAULT FALSE,
  "is_deleted" boolean,
  "login_attempts" int DEFAULT 0,
  "lockout_duration" int DEFAULT 60,
  "lockout_until" timestamptz,
  "password_changed_at" timestamptz
);

CREATE INDEX ON "users" ("email", "username", "created_at", "updated_at");