import type { PrismaService } from '../../prisma/prisma.service';

export interface AttackCorrelationResult {
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
  /** Layer-1/2 incidents that form the attack sequence evidence */
  prerequisite_incident_ids: string[];
  response?: { playbook: string; mode: 'AUTO' | 'CONFIRM' };
}

/**
 * Layer-2 attack correlation rule (spec §4): consumes incidents/alerts from
 * prerequisite rules that share entities within a time window, and emits a
 * higher-severity correlation incident.
 */
export interface AttackCorrelationRule {
  readonly id: string;
  readonly name: string;
  detect(
    prisma: PrismaService,
    since: Date,
  ): Promise<AttackCorrelationResult[]>;
}

export interface RelatedEntitiesJson {
  ips?: string[];
  users?: string[];
  hosts?: string[];
}

export function entitiesOf(related: unknown): RelatedEntitiesJson {
  return (related as RelatedEntitiesJson) ?? {};
}
