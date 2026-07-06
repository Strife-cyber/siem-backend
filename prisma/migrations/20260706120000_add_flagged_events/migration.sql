-- CreateEnum
CREATE TYPE "FlaggedEventStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE');

-- CreateTable
CREATE TABLE "flagged_events" (
    "id" UUID NOT NULL,
    "ingestion_hash" VARCHAR(64) NOT NULL,
    "user_id" UUID NOT NULL,
    "reason" TEXT,
    "status" "FlaggedEventStatus" NOT NULL DEFAULT 'OPEN',
    "investigation_id" UUID,
    "event_snapshot" JSONB,
    "flagged_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolved_at" TIMESTAMPTZ,

    CONSTRAINT "flagged_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "flagged_event_links" (
    "id" UUID NOT NULL,
    "from_event_id" UUID NOT NULL,
    "to_event_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "link_type" VARCHAR(50) NOT NULL DEFAULT 'RELATED',

    CONSTRAINT "flagged_event_links_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "flagged_events_ingestion_hash_key" ON "flagged_events"("ingestion_hash");

-- CreateIndex
CREATE INDEX "flagged_events_status_idx" ON "flagged_events"("status");

-- CreateIndex
CREATE INDEX "flagged_events_investigation_id_idx" ON "flagged_events"("investigation_id");

-- CreateIndex
CREATE INDEX "flagged_events_flagged_at_idx" ON "flagged_events"("flagged_at");

-- CreateIndex
CREATE UNIQUE INDEX "flagged_event_links_from_event_id_to_event_id_key" ON "flagged_event_links"("from_event_id", "to_event_id");

-- AddForeignKey
ALTER TABLE "flagged_events" ADD CONSTRAINT "flagged_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "flagged_event_links" ADD CONSTRAINT "flagged_event_links_from_event_id_fkey" FOREIGN KEY ("from_event_id") REFERENCES "flagged_events"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "flagged_event_links" ADD CONSTRAINT "flagged_event_links_to_event_id_fkey" FOREIGN KEY ("to_event_id") REFERENCES "flagged_events"("id") ON DELETE CASCADE ON UPDATE CASCADE;
