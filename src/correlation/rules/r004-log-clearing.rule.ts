import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionRule,
  DetectionResult,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

/**
 * R004 — Log Clearing / Service Stop (T1070)
 *
 * Two correlated signals:
 *   1. Direct events: Windows Event 1102/104 or Linux service stop
 *   2. Volume drop: hostname sending < 10% of its 24h baseline events
 *
 * If both signals fire for the same hostname → CRITICAL + SOAR trigger.
 */
export class LogClearingRule implements DetectionRule {
  readonly id = 'R004';
  readonly name = 'Log Clearing Attempt';
  readonly definition: RuleDefinition = {
    time_window_seconds: 300,
    interval_seconds: 120,
    threshold: 1,
    source_types: ['windows_security', 'linux_auth', 'syslog'],
    params: {
      volume_drop_threshold_pct: 10,
      volume_baseline_hours: 24,
    },
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM',
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const results: DetectionResult[] = [];

    const signal1Hosts = await this.detectDirectEvents(es, since);
    for (const host of signal1Hosts) {
      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'CRITICAL' as const,
        confidence_score: 85,
        summary: `Logging stopped/cleared on ${host.hostname}: ${host.action}`,
        related_entities: { hosts: [host.hostname] },
      });
    }

    const signal2Hosts = await this.detectVolumeDrop(es, since);
    for (const host of signal2Hosts) {
      const existingIdx = results.findIndex(
        (r) => r.related_entities.hosts?.[0] === host.hostname,
      );
      if (existingIdx >= 0) {
        results[existingIdx].confidence_score = 95;
        results[existingIdx].summary =
          `${results[existingIdx].summary} + event volume dropped ${host.dropPct}%`;
      } else {
        results.push({
          rule_id: this.id,
          rule_name: this.name,
          severity: 'WARNING' as const,
          confidence_score: 50,
          summary: `Event volume drop on ${host.hostname}: ${host.currentCount} events vs ${host.baselineAvg} avg (${host.dropPct}% decrease)`,
          related_entities: { hosts: [host.hostname] },
        });
      }
    }

    return results;
  }

  private async detectDirectEvents(
    es: ElasticsearchService,
    since: Date,
  ): Promise<Array<{ hostname: string; action: string }>> {
    const now = new Date();

    const result = await es
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 100,
        _source: ['hostname', 'action', 'raw_message', 'event_id'] as any,
        query: {
          bool: {
            filter: [
              {
                range: {
                  collected_at: {
                    gte: since.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
            ],
            should: [
              { term: { event_id: 1102 } },
              { term: { event_id: 104 } },
              { term: { event_id: 103 } },
            ],
            minimum_should_match: 1,
          },
        },
      })
      .then((r) => r as any);

    const hits = result?.hits?.hits ?? [];
    const seen = new Set<string>();
    const hosts: Array<{ hostname: string; action: string }> = [];

    for (const hit of hits) {
      const src = hit._source as Record<string, unknown> | undefined;
      if (!src) continue;
      const hostname = String(src.hostname);
      if (!hostname || seen.has(hostname)) continue;
      seen.add(hostname);
      hosts.push({
        hostname,
        action: (src.action as string) ?? 'log_cleared',
      });
    }

    return hosts;
  }

  private async detectVolumeDrop(
    es: ElasticsearchService,
    since: Date,
  ): Promise<
    Array<{
      hostname: string;
      currentCount: number;
      baselineAvg: number;
      dropPct: number;
    }>
  > {
    const now = new Date();
    const currentSince = since;

    const baselineHours =
      (this.definition.params as any)?.volume_baseline_hours ?? 24;
    const baselineEnd = new Date(
      now.getTime() - baselineHours * 60 * 60 * 1000,
    );
    const baselineStart = new Date(baselineEnd.getTime() - 300 * 1000);

    const [currentResult, baselineResult] = await Promise.all([
      es.getClient().search({
        index: 'ctu-logs',
        size: 0,
        query: {
          range: {
            collected_at: {
              gte: currentSince.toISOString(),
              lte: now.toISOString(),
            },
          },
        },
        aggs: {
          hosts: {
            terms: { field: 'hostname', size: 1000 },
          },
        },
      }),
      es.getClient().search({
        index: 'ctu-logs',
        size: 0,
        query: {
          range: {
            collected_at: {
              gte: baselineStart.toISOString(),
              lte: baselineEnd.toISOString(),
            },
          },
        },
        aggs: {
          hosts: {
            terms: { field: 'hostname', size: 1000 },
          },
        },
      }),
    ]).then(([c, b]) => [c as any, b as any]);

    const currentBuckets: Record<string, number> = {};
    for (const b of currentResult?.aggregations?.hosts?.buckets ?? []) {
      currentBuckets[b.key as string] = b.doc_count as number;
    }

    const baselineBuckets: Record<string, number> = {};
    for (const b of baselineResult?.aggregations?.hosts?.buckets ?? []) {
      baselineBuckets[b.key as string] = b.doc_count as number;
    }

    const thresholdPct =
      (this.definition.params as any)?.volume_drop_threshold_pct ?? 10;
    const results: Array<{
      hostname: string;
      currentCount: number;
      baselineAvg: number;
      dropPct: number;
    }> = [];

    for (const [hostname, currentCount] of Object.entries(currentBuckets)) {
      const baselineAvg = baselineBuckets[hostname] ?? 0;
      if (baselineAvg < 5) continue;

      const dropPct = Math.round(
        ((baselineAvg - currentCount) / baselineAvg) * 100,
      );

      if (dropPct >= thresholdPct && currentCount < baselineAvg) {
        results.push({ hostname, currentCount, baselineAvg, dropPct });
      }
    }

    return results;
  }
}
