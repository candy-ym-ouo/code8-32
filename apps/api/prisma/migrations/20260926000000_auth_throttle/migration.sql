-- CreateEnum
CREATE TYPE "AuthAuditAction" AS ENUM ('LOGIN_SUCCEEDED', 'LOGIN_FAILED', 'LOGIN_LOCKED', 'PASSWORD_VERIFY_FAILED', 'PASSWORD_CHANGED');

-- CreateTable
CREATE TABLE "login_throttles" (
    "email" VARCHAR(320) NOT NULL,
    "fail_count" INTEGER NOT NULL DEFAULT 0,
    "window_start" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "locked_until" TIMESTAMPTZ(3),
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "login_throttles_pkey" PRIMARY KEY ("email")
);

-- CreateTable
CREATE TABLE "auth_audit_events" (
    "id" UUID NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "user_id" UUID,
    "action" "AuthAuditAction" NOT NULL,
    "ip" VARCHAR(45),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "auth_audit_events_email_created_at_idx" ON "auth_audit_events"("email", "created_at");

-- CreateIndex
CREATE INDEX "auth_audit_events_user_id_created_at_idx" ON "auth_audit_events"("user_id", "created_at");
