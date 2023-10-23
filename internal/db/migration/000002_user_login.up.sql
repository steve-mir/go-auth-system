CREATE TABLE "user_logins" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "user_id" uuid NOT NULL,
  "login_at" timestamptz,
  "ip_address" inet,
  "user_agent" varchar
);

CREATE TABLE "sessions" (
  "id" uuid PRIMARY KEY NOT NULL,
  "user_id" uuid NOT NULL,
  "email" varchar,
  "refresh_token" varchar NOT NULL,
  "user_agent" text NOT NULL,
  "ip_address" inet NOT NULL,
  "is_blocked" boolean NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz,
  "last_active_at" timestamptz
);

CREATE TABLE "login_failures" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "email" VARCHAR NOT NULL,
  "timestamp" timestamptz,
  "user_agent" varchar,
  "ip_address" inet
);

CREATE TABLE "banned_users" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "user_id" uuid NOT NULL,
  "banned_at" timestamptz,
  "reason" varchar
);

CREATE TABLE "security_questions" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "user_id" uuid NOT NULL,
  "question" varchar,
  "answer" varchar,
  "expired_at" timestamptz
);

CREATE INDEX ON "user_logins" ("user_id", "login_at");
CREATE INDEX ON "sessions" ("user_id", "expires_at");

CREATE INDEX ON "login_failures" ("email", "timestamp");

CREATE INDEX ON "banned_users" ("user_id");



ALTER TABLE "user_logins" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "sessions" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");
ALTER TABLE "login_failures" ADD FOREIGN KEY ("email") REFERENCES "users" ("id");

ALTER TABLE "banned_users" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "security_questions" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");