CREATE TABLE "user_profiles" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "user_id" uuid NOT NULL,
  "first_name" varchar,
  "last_name" varchar,
  "phone" varchar,
  "image_url" VARCHAR
);

CREATE TABLE "roles" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "name" varchar NOT NULL
);

CREATE TABLE "user_roles" (
  "id" INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  "user_id" uuid NOT NULL,
  "role_id" int NOT NULL
);

CREATE TABLE "email_verification_requests" (
  "id" BIGSERIAL PRIMARY KEY,
  "user_id" uuid NOT NULL,
  "email" varchar NOT NULL,
  "token" varchar NOT NULL UNIQUE,
  "is_verified" boolean DEFAULT false,
  "created_at" timestamptz DEFAULT (now()),
  "expires_at" timestamptz NOT NULL
);

-- TODO: Use or remove
CREATE TABLE "user_preferences" (
  "user_id" uuid,
  "preferences" json
);

CREATE INDEX ON "user_roles" ("role_id");
CREATE INDEX ON "email_verification_requests" ("user_id", "token", "email", "expires_at");


ALTER TABLE "user_profiles" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "user_roles" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "user_roles" ADD FOREIGN KEY ("role_id") REFERENCES "roles" ("id");

ALTER TABLE "email_verification_requests" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "user_preferences" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");