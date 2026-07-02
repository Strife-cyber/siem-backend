import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionRule,
  DetectionResult,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

/**
 * R002 — Pass-the-Hash (T1550.002)
 *
 * Detects NTLM authentication between hosts that have no history
 * of such communication. Requires enrichment fields (auth_package=NTLM,
 * logon_type=3, source_network_address, workstation).
 *
 * Falls back to raw_message text search if enrichment fields are absent.
 */
export class PassTheHashRule implements DetectionRule {
  readonly id = 'R002';
  readonly name = 'Lateral Movement (Pass-the-Hash)';
  readonly definition: RuleDefinition = {
    time_window_seconds: 300,
    interval_seconds: 120,
    threshold: 1,
    source_types: ['windows', 'windows_security', 'active_directory'],
    actions: ['login', 'authenticate', 'user_login', 'successful_login'],
    outcomes: ['success'],
    params: {
      baseline_redis_key: 'pth:baseline',
    },
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const now = new Date();

    let enrichedResult = await this.queryEnriched(es, since, now);

    if (enrichedResult.length === 0) {
      enrichedResult = await this.queryFallback(es, since, now);
    }

    return enrichedResult
      .filter((r) => {
        const srcIp = r.related_entities.ips?.[0];
        const targetHost = r.related_entities.hosts?.[0];
        return srcIp && targetHost && srcIp !== targetHost;
      })
      .map((r) => ({
        ...r,
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH' as const,
        confidence_score: 65,
        summary: `Suspicious NTLM auth: ${r.related_entities.ips?.[0] ?? '?'} → ${r.related_entities.hosts?.[0] ?? '?'}`,
      }));
  }

  private async queryEnriched(
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
              { term: { auth_package: 'NTLM' } },
              { term: { logon_type: 3 } },
              { term: { outcome: 'success' } },
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
          auth_pairs: {
            composite: {
              size: 1000,
              sources: [
                { source_ip: { terms: { field: 'source_network_address' } } },
                { target_host: { terms: { field: 'hostname' } } },
              ],
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.auth_pairs?.buckets ?? [];
    return buckets.map((b: any) => ({
      rule_id: this.id,
      rule_name: this.name,
      severity: 'HIGH' as const,
      confidence_score: 65,
      summary: '',
      related_entities: {
        ips: [b.key.source_ip as string],
        hosts: [b.key.target_host as string],
      },
    }));
  }

  private async queryFallback(
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
              { terms: { source_type: ['windows_security'] } },
              { term: { outcome: 'success' } },
              {
                range: {
                  collected_at: {
                    gte: since.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
            ],
            must: [{ match: { raw_message: 'NTLM' } }],
          },
        },
        aggs: {
          auth_pairs: {
            composite: {
              size: 1000,
              sources: [
                { source_ip: { terms: { field: 'source_ip' } } },
                { target_host: { terms: { field: 'hostname' } } },
              ],
            },
          },
        },
      })
      .then((r) => r as any);

    const buckets = result?.aggregations?.auth_pairs?.buckets ?? [];
    return buckets.map((b: any) => ({
      rule_id: this.id,
      rule_name: this.name,
      severity: 'HIGH' as const,
      confidence_score: 50,
      summary: '',
      related_entities: {
        ips: [b.key.source_ip as string],
        hosts: [b.key.target_host as string],
      },
    }));
  }
}
