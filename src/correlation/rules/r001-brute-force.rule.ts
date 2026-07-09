import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionRule,
  DetectionResult,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

/**
 * R001 — Brute Force (T1110)
 *
 * Detects rapid failed login attempts from a single source IP.
 * Works for both SSH (linux_auth) and Windows (windows_security) auth failures.
 */
export class BruteForceRule implements DetectionRule {
  readonly id = 'R001';
  readonly name = 'SSH/Windows Brute Force';
  readonly definition: RuleDefinition = {
    time_window_seconds: 60,
    interval_seconds: 60,
    threshold: 5,
    max_time_span_seconds: 120,
    source_types: [
      'linux',
      'linux_auth',
      'linux_syslog',
      'windows',
      'windows_security',
      'windows_application',
      'active_directory',
    ],
    actions: [
      'login',
      'user_login',
      'failed_login',
      'auth_failure',
      'auth_event',
    ],
    outcomes: [],
    trigger_playbook: 'block_ip',
    playbook_mode: 'AUTO',
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const now = new Date();

    const filters: any[] = [
      { terms: { source_type: this.definition.source_types! } },
      { terms: { action: this.definition.actions! } },
    ];

    // Only add outcome filter if outcomes are defined (some beat types don't populate it)
    if (this.definition.outcomes?.length) {
      filters.push({ terms: { outcome: this.definition.outcomes } });
    }

    const result = await es
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              ...filters,
              {
                range: {
                  normalized_at: {
                    gte: since.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
            ],
          },
        },
        aggs: {
          attackers: {
            terms: {
              field: 'source_ip',
              size: 100,
              order: { _count: 'desc' as const },
            },
            aggs: {
              distinct_users: {
                cardinality: { field: 'user_principal' },
              },
              first_seen: { min: { field: 'collected_at' } },
              last_seen: { max: { field: 'collected_at' } },
              hosts: {
                terms: { field: 'hostname', size: 10 },
              },
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.attackers?.buckets ?? [];
    const results: DetectionResult[] = [];

    for (const bucket of buckets) {
      const count: number = bucket.doc_count;
      if (count < this.definition.threshold) continue;

      const firstSeen = new Date(bucket.first_seen.value as string);
      const lastSeen = new Date(bucket.last_seen.value as string);
      const timeSpanSec = (lastSeen.getTime() - firstSeen.getTime()) / 1000;

      if (
        this.definition.max_time_span_seconds &&
        timeSpanSec > this.definition.max_time_span_seconds
      ) {
        continue;
      }

      const users: number = bucket.distinct_users?.value ?? 0;
      const targetHosts: string[] =
        bucket.hosts?.buckets?.map((h: any) => h.key) ?? [];

      let severity: 'WARNING' | 'HIGH' | 'CRITICAL' = 'WARNING';
      if (count >= 50) severity = 'CRITICAL';
      else if (count >= 10) severity = 'HIGH';

      let confidence = 80;
      if (users > 3) confidence += 10;
      if (count > 50) confidence += 10;

      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity,
        confidence_score: Math.min(confidence, 99),
        summary: `Brute force from ${bucket.key}: ${count} failures across ${users} accounts in ${Math.round(timeSpanSec)}s`,
        related_entities: {
          ips: [bucket.key as string],
          hosts: targetHosts,
        },
      });
    }

    return results;
  }
}
