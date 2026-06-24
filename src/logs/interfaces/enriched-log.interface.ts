import type { NormalizedLog } from './normalized-log.interface';

/**
 * Enriched log document sent to Elasticsearch.
 * Extends NormalizedLog with parsed fields extracted from raw_message.
 * No changes to the collector or NormalizedLog interface.
 */
export interface EnrichedLog extends NormalizedLog {
  /** Enrichment fields extracted from raw_message during processing */
  event_id?: number;
  logon_type?: number;
  target_user?: string;
  failure_reason?: string;
  source_network_address?: string;
  workstation?: string;
  auth_package?: string;
  service_name?: string;
  bytes_sent?: number;
  bytes_recv?: number;
  direction?: string;
  protocol?: string;
  duration_seconds?: number;
  rule_name?: string;
}
