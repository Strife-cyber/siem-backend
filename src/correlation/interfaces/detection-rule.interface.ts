import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type { PrismaService } from '../../prisma/prisma.service';

/**
 * A detection result produced by a rule when its threshold is exceeded.
 */
export interface DetectionResult {
  rule_id: string;
  rule_name: string;
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  confidence_score: number;
  summary: string;
  related_entities: {
    ips?: string[];
    users?: string[];
    hosts?: string[];
  };
}

/**
 * Configuration stored in the correlation_rules table's `definition` JSON field.
 */
export interface RuleDefinition {
  /** ES query time window in seconds */
  time_window_seconds: number;
  /** How often the rule runs (seconds) */
  interval_seconds: number;
  /** Threshold count to trigger */
  threshold: number;
  /** Max allowed time span between first and last event (for burst detection) */
  max_time_span_seconds?: number;
  /** Source types to filter on */
  source_types?: string[];
  /** Event taxonomies to filter on */
  event_taxonomies?: string[];
  /** Action values to filter on */
  actions?: string[];
  /** Outcome values to filter on */
  outcomes?: string[];
  /** Optional: trigger SOAR playbook on incident creation */
  trigger_playbook?: string;
  playbook_mode?: 'AUTO' | 'CONFIRM';
  /** Optional: overrides for detection-specific params */
  params?: Record<string, unknown>;
}

/**
 * Interface each detection rule must implement.
 */
export interface DetectionRule {
  /** Unique rule ID matching correlation_rules.id */
  id: string;
  /** Rule display name */
  name: string;
  /** Rule tactic code */
  definition: RuleDefinition;

  /**
   * Run detection against Elasticsearch.
   * Returns array of detection results (1 per offending entity).
   * Empty array = no threat detected.
   */
  detect(
    es: ElasticsearchService,
    since: Date,
    prisma?: PrismaService,
  ): Promise<DetectionResult[]>;
}
