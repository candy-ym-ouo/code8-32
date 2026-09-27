-- CreateEnum
CREATE TYPE "AuthAuditAction" AS ENUM ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGIN_LOCKED', 'PASSWORD_VERIFY_SUCCESS', 'PASSWORD_VERIFY_FAILED', 'PASSWORD_VERIFY_LOCKED');

-- CreateTable
CREATE TABLE "auth_throttles" (
    "id" UUID NOT NULL,
    "subject_key" VARCHAR(340) NOT NULL,
    "failures" INTEGER NOT NULL DEFAULT 0,
    "window_start_at" TIMESTAMPTZ(3) NOT NULL,
    "locked_until" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "auth_throttles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auth_audit_events" (
    "id" UUID NOT NULL,
    "subject_key" VARCHAR(340) NOT NULL,
    "user_id" UUID,
    "action" "AuthAuditAction" NOT NULL,
    "ip" VARCHAR(45),
    "user_agent" VARCHAR(300),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "auth_throttles_subject_key_key" ON "auth_throttles"("subject_key");

-- CreateIndex
CREATE INDEX "auth_audit_events_subject_key_created_at_idx" ON "auth_audit_events"("subject_key", "created_at");

-- CreateIndex
CREATE INDEX "auth_audit_events_user_id_created_at_idx" ON "auth_audit_events"("user_id", "created_at");

