/*
  Warnings:

  - You are about to drop the `User` table. If the table is not empty, all the data it contains will be lost.

*/
-- CreateEnum
CREATE TYPE "SeverityLevel" AS ENUM ('INFO', 'WARNING', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "IncidentStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "PlaybookMode" AS ENUM ('AUTO', 'CONFIRM');

-- CreateEnum
CREATE TYPE "ExecutionStatus" AS ENUM ('PENDING', 'EXECUTED', 'ABORTED', 'FAILED');

-- DropTable
DROP TABLE "User";

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "username" VARCHAR(100) NOT NULL,
    "password_hash" VARCHAR(255) NOT NULL,
    "mfa_secret" VARCHAR(255),
    "role" "UserRole" NOT NULL DEFAULT 'READER',
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL,
    "last_login" TIMESTAMPTZ,
    "is_active" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "correlation_rules" (
    "id" VARCHAR(50) NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "tactic" VARCHAR(100),
    "technique" VARCHAR(100),
    "definition" JSONB NOT NULL,
    "confidence_weight" SMALLINT NOT NULL DEFAULT 1,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "correlation_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incidents" (
    "id" UUID NOT NULL,
    "rule_id" VARCHAR(50),
    "triggered_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "severity" "SeverityLevel" NOT NULL,
    "confidence_score" SMALLINT NOT NULL,
    "status" "IncidentStatus" NOT NULL DEFAULT 'OPEN',
    "summary" TEXT,
    "related_entities" JSONB,
    "assigned_to" UUID,
    "resolved_at" TIMESTAMPTZ,
    "batch_manifest_id" UUID,

    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "playbook_executions" (
    "id" UUID NOT NULL,
    "incident_id" UUID NOT NULL,
    "playbook_name" VARCHAR(255) NOT NULL,
    "mode" "PlaybookMode" NOT NULL DEFAULT 'AUTO',
    "status" "ExecutionStatus" NOT NULL DEFAULT 'PENDING',
    "initiated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "executed_at" TIMESTAMPTZ,
    "result_payload" JSONB,
    "triggered_by_user_id" UUID,

    CONSTRAINT "playbook_executions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "batch_manifests" (
    "id" UUID NOT NULL,
    "start_time" TIMESTAMPTZ NOT NULL,
    "end_time" TIMESTAMPTZ NOT NULL,
    "sha256_hash" VARCHAR(64) NOT NULL,
    "record_count" BIGINT NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "batch_manifests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ueba_profiles" (
    "id" UUID NOT NULL,
    "user_principal" VARCHAR(255) NOT NULL,
    "risk_score" SMALLINT NOT NULL DEFAULT 0,
    "baseline_data" JSONB NOT NULL,
    "last_calculated_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "anomaly_count" SMALLINT NOT NULL DEFAULT 0,

    CONSTRAINT "ueba_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_trail" (
    "id" BIGSERIAL NOT NULL,
    "user_id" UUID NOT NULL,
    "action" VARCHAR(255) NOT NULL,
    "ip_address" INET,
    "user_agent" TEXT,
    "metadata" JSONB,
    "performed_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_trail_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "retention_policies" (
    "id" SMALLINT NOT NULL,
    "name" VARCHAR(50) NOT NULL,
    "duration_days" INTEGER NOT NULL,
    "is_default" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "retention_policies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "users"("username");

-- CreateIndex
CREATE INDEX "idx_correlation_rules_active" ON "correlation_rules"("is_active");

-- CreateIndex
CREATE INDEX "idx_incidents_severity_status" ON "incidents"("severity", "status");

-- CreateIndex
CREATE INDEX "idx_incidents_triggered_at" ON "incidents"("triggered_at");

-- CreateIndex
CREATE INDEX "idx_playbook_status" ON "playbook_executions"("status");

-- CreateIndex
CREATE UNIQUE INDEX "ueba_profiles_user_principal_key" ON "ueba_profiles"("user_principal");

-- CreateIndex
CREATE INDEX "idx_ueba_risk_score" ON "ueba_profiles"("risk_score");

-- CreateIndex
CREATE INDEX "idx_audit_performed_at" ON "audit_trail"("performed_at");

-- CreateIndex
CREATE INDEX "idx_audit_user_action" ON "audit_trail"("user_id", "action");

-- AddForeignKey
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "correlation_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_assigned_to_fkey" FOREIGN KEY ("assigned_to") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_batch_manifest_id_fkey" FOREIGN KEY ("batch_manifest_id") REFERENCES "batch_manifests"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_executions" ADD CONSTRAINT "playbook_executions_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_executions" ADD CONSTRAINT "playbook_executions_triggered_by_user_id_fkey" FOREIGN KEY ("triggered_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_trail" ADD CONSTRAINT "audit_trail_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
