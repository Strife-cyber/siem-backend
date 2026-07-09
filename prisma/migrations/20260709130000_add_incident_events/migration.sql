-- CreateTable
CREATE TABLE "incident_events" (
    "id" UUID NOT NULL,
    "incident_id" UUID NOT NULL,
    "es_id" VARCHAR(255),
    "collected_at" TIMESTAMPTZ NOT NULL,
    "source_ip" VARCHAR(45),
    "destination_ip" VARCHAR(45),
    "hostname" VARCHAR(255),
    "user_principal" VARCHAR(255),
    "action" VARCHAR(255),
    "outcome" VARCHAR(50),
    "source_type" VARCHAR(50),
    "raw_message" TEXT,
    "event_snapshot" JSONB,

    CONSTRAINT "incident_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "incident_events_incident_id_idx" ON "incident_events"("incident_id");

-- AddForeignKey
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
