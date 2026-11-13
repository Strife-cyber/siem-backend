import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionRule,
  DetectionResult,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

/**
 * R003 — Data Exfiltration (T1041)
 *
 * Detects abnormal outbound traffic volumes per user/host.
 * Requires the collector to embed byte counts in raw_message
 * for the firewall enricher to parse (bytes_sent field).
 *
 * Status: PARTIAL — works if collector sets byte data in raw_message.
 * Without bytes_sent, falls back to connection count (noisier).
 */
export class DataExfilRule implements DetectionRule {
  readonly id = 'R003';
  readonly name = 'Data Exfiltration';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 120,
    threshold: 1,
    source_types: [
      'firewall',
      'web_proxy',
      'traefik',
      'linux_network',
      'linux',
    ],
    trigger_playbook: 'block_port',
    playbook_mode: 'AUTO',
    params: {
      multiplier_threshold: 10,
      min_volume_mb: 10,
      baseline_days: 30,
    },
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const now = new Date();

    const results: DetectionResult[] = [];

    const byteResults = await this.detectByVolume(es, since, now);
    results.push(...byteResults);

    const flowResults = await this.detectByFlowBytes(es, since, now);
    results.push(...flowResults);

    if (byteResults.length === 0) {
      const countResults = await this.detectByConnectionCount(es, since, now);
      results.push(...countResults);
    }

    return results;
  }

  private async detectByVolume(
    es: ElasticsearchService,
    since: Date,
    now: Date,
  ): Promise<DetectionResult[]> {
    const result = await es
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              { terms: { source_type: this.definition.source_types! } },
              { term: { direction: 'outbound' } },
              { exists: { field: 'bytes_sent' } },
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
          by_user: {
            terms: { field: 'user_principal', size: 50, min_doc_count: 1 },
            aggs: {
              total_bytes: { sum: { field: 'bytes_sent' } },
              destinations: {
                terms: { field: 'destination_ip', size: 10 },
              },
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.by_user?.buckets ?? [];
    return buckets
      .filter((b: any) => {
        const totalBytes: number = b.total_bytes?.value ?? 0;
        const totalMb = totalBytes / (1024 * 1024);
        const minVolumeMb = (this.definition.params as any)
          ?.min_volume_mb as number;
        return totalMb > minVolumeMb;
      })
      .map((b: any) => {
        const totalBytes: number = b.total_bytes?.value ?? 0;
        const totalMb = (totalBytes / (1024 * 1024)).toFixed(1);
        const destinations: string[] =
          b.destinations?.buckets?.map((d: any) => d.key) ?? [];
        return {
          rule_id: this.id,
          rule_name: this.name,
          severity: 'CRITICAL' as const,
          confidence_score: 70,
          summary: `Possible exfiltration by ${b.key}: ${totalMb}MB sent outbound in 15min to ${destinations.length} destinations`,
          related_entities: {
            users: [b.key as string],
            ips: destinations,
          },
        };
      });
  }

  private async detectByConnectionCount(
    es: ElasticsearchService,
    since: Date,
    now: Date,
  ): Promise<DetectionResult[]> {
    const result = await es
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              { terms: { source_type: this.definition.source_types! } },
              { term: { direction: 'outbound' } },
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
          by_user: {
            terms: { field: 'user_principal', size: 50, min_doc_count: 100 },
            aggs: {
              destinations: {
                cardinality: { field: 'destination_ip' },
              },
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.by_user?.buckets ?? [];
    return buckets
      .filter((b: any) => {
        const uniqueDests: number = b.destinations?.value ?? 0;
        return b.doc_count > 100 && uniqueDests > 10;
      })
      .map((b: any) => ({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING' as const,
        confidence_score: 30,
        summary: `Unusual outbound traffic from ${b.key}: ${b.doc_count} connections to ${b.destinations?.value ?? '?'} unique destinations in 15min`,
        related_entities: {
          users: [b.key as string],
        },
      }));
  }

  /**
   * Flow-summary path: the collector aggregates pfSense filterlog packets
   * into per-flow FLOW_BYTES documents carrying bytes_sent/direction.
   * Groups outbound flow summaries by internal source IP and fires on
   * volume above min_volume_mb.
   */
  private async detectByFlowBytes(
    es: ElasticsearchService,
    since: Date,
    now: Date,
  ): Promise<DetectionResult[]> {
    const result = await es
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 0,
        query: {
          bool: {
            filter: [
              { terms: { source_type: this.definition.source_types! } },
              { term: { action: 'flow_bytes' } },
              { term: { direction: 'outbound' } },
              { exists: { field: 'bytes_sent' } },
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
          by_source_ip: {
            terms: { field: 'source_ip', size: 50, min_doc_count: 1 },
            aggs: {
              total_bytes: { sum: { field: 'bytes_sent' } },
              destinations: { terms: { field: 'destination_ip', size: 5 } },
            },
          },
        },
      })
      .then((r) => r as any);

    const minVolumeMb = (this.definition.params as any)
      ?.min_volume_mb as number;
    const buckets = result?.aggregations?.by_source_ip?.buckets ?? [];
    return buckets
      .filter((b: any) => {
        const totalMb = (b.total_bytes?.value ?? 0) / (1024 * 1024);
        return totalMb > minVolumeMb;
      })
      .map((b: any) => {
        const totalMb = ((b.total_bytes?.value ?? 0) / (1024 * 1024)).toFixed(
          1,
        );
        const dests: string[] =
          b.destinations?.buckets?.map((d: any) => d.key) ?? [];
        return {
          rule_id: this.id,
          rule_name: this.name,
          severity: 'CRITICAL' as const,
          confidence_score: 75,
          summary: `High-volume outbound flow from ${b.key}: ${totalMb}MB in 15min to ${dests.join(', ') || 'unknown destinations'}`,
          related_entities: {
            ips: [b.key as string, ...dests],
          },
        };
      });
  }
}
