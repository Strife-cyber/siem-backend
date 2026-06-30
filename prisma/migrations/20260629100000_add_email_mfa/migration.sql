-- Add email and mfa_enabled to users, create mfa_sessions table

ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "email" VARCHAR(255);
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "mfa_enabled" BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS "mfa_sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "code" VARCHAR(6) NOT NULL,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mfa_sessions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "mfa_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "mfa_sessions_user_id_code_idx" ON "mfa_sessions"("user_id", "code");
