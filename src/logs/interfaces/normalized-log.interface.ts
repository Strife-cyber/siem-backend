/**
 * Golden Schema — Normalized Log structure matching Elasticsearch mapping.
 * FR-01.3: Normalization produces this shape for every ingested log.
 */
export interface NormalizedLog {
  /** When the event occurred on the source system */
  collected_at: string;
  /** When the SIEM backend normalized the log */
  normalized_at: string;
  /** Originating source type: 'windows_security', 'linux_auth', 'firewall', 'syslog', etc. */
  source_type: string;
  /** Hostname or FQDN of the originating machine */
  hostname: string;
  /** Originating IP address */
  source_ip: string;
  /** Target IP address (if applicable) */
  destination_ip?: string;
  /** Originating port */
  source_port?: number;
  /** Target port */
  destination_port?: number;
  /** Authenticated user principal name */
  user_principal?: string;
  /** Windows security identifier or equivalent */
  user_security_id?: string;
  /** MITRE ATT&CK taxonomy or event category */
  event_taxonomy: string;
  /** Action performed: 'login', 'access', 'create', 'delete', 'modify', etc. */
  action: string;
  /** Outcome: 'success', 'failure', 'unknown' */
  outcome?: string;
  /** Severity level (0-7, mapping to INFO=0, WARNING=2, HIGH=5, CRITICAL=7) */
  severity: number;
  /** Original raw log message */
  raw_message: string;
  /** Arbitrary tags for enrichment */
  tags?: string[];
  /** SHA-256 hash of the raw message for chain of custody (FR-02.3) */
  ingestion_hash?: string;
  /** Confidence score from correlation engine (0-100) */
  confidence_score?: number;
}

/**
 * Search parameters for querying logs in Elasticsearch (FR-05.2 / S6).
 */
export interface LogSearchQuery {
  source_ip?: string;
  destination_ip?: string;
  user_principal?: string;
  hostname?: string;
  source_type?: string;
  event_taxonomy?: string;
  action?: string;
  severity_min?: number;
  severity_max?: number;
  raw_message?: string;
  tags?: string[];
  date_from?: string;
  date_to?: string;
  from?: number;
  size?: number;
  sort_field?: string;
  sort_order?: 'asc' | 'desc';
}
