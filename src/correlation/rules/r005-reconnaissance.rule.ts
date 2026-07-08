import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionRule,
  DetectionResult,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

/**
 * R005 — Network Reconnaissance / Port Scanning (T1046)
 *
 * Detects a single source IP connecting to multiple destination IPs
 * on different ports within a short time window — classic scanning behavior.
 * Works across firewall, web_proxy, and network sensor source types.
 */
export class ReconnaissanceRule implements DetectionRule {
  readonly id = 'R005';
  readonly name = 'Network Reconnaissance (Port Scan)';
  readonly definition: RuleDefinition = {
    time_window_seconds: 120,
    interval_seconds: 60,
    threshold: 15,
    max_time_span_seconds: 60,
    source_types: [
      'firewall',
      'web_proxy',
      'traefik',
      'linux_network',
      'syslog',
      'linux',
    ],
    actions: ['network_connect', 'network_flow', 'http_request'],
    outcomes: ['success', 'failure'],
    trigger_playbook: 'temporary_block',
    playbook_mode: 'AUTO',
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const now = new Date();

    const result = await es
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              { terms: { source_type: this.definition.source_types! } },
              { terms: { action: this.definition.actions! } },
              {
                range: {
                  collected_at: {
                    gte: since.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
            ],
          },
        },
        aggs: {
          scanners: {
            terms: {
              field: 'source_ip',
              size: 50,
              order: { _count: 'desc' as const },
              min_doc_count: this.definition.threshold,
            },
            aggs: {
              target_count: {
                cardinality: { field: 'destination_ip' },
              },
              port_count: {
                cardinality: { field: 'destination_port' },
              },
              first_seen: { min: { field: 'collected_at' } },
              last_seen: { max: { field: 'collected_at' } },
              protocols: {
                terms: { field: 'protocol', size: 10 },
              },
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.scanners?.buckets ?? [];
    const results: DetectionResult[] = [];

    for (const bucket of buckets) {
      const count: number = bucket.doc_count;
      const uniqueTargets: number = bucket.target_count?.value ?? 0;
      const uniquePorts: number = bucket.port_count?.value ?? 0;

      if (uniqueTargets < 3 || uniquePorts < 3) continue;

      const firstSeen = new Date(bucket.first_seen.value as string);
      const lastSeen = new Date(bucket.last_seen.value as string);
      const timeSpanSec = (lastSeen.getTime() - firstSeen.getTime()) / 1000;

      if (
        this.definition.max_time_span_seconds &&
        timeSpanSec > this.definition.max_time_span_seconds
      ) {
        continue;
      }

      const protocols: string[] =
        bucket.protocols?.buckets?.map((p: any) => p.key) ?? [];

      let severity: 'WARNING' | 'HIGH' | 'CRITICAL' = 'WARNING';
      if (uniqueTargets > 20 || count > 100) severity = 'HIGH';
      if (uniqueTargets > 50 || count > 500) severity = 'CRITICAL';

      let confidence = 60;
      if (uniquePorts > 10) confidence += 15;
      if (timeSpanSec < 10) confidence += 15;
      if (protocols.length > 3) confidence += 10;

      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity,
        confidence_score: Math.min(confidence, 99),
        summary:
          `Reconnaisance from ${bucket.key}: ${count} connections to ${uniqueTargets} targets (${uniquePorts} ports) ` +
          `in ${Math.round(timeSpanSec)}s [${protocols.join(', ')}]`,
        related_entities: {
          ips: [bucket.key as string],
        },
      });
    }

    return results;
  }
}
