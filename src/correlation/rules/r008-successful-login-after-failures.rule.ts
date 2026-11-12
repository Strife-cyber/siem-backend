import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionResult,
  DetectionRule,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

interface AuthEventHit {
  source_ip?: string;
  user_principal?: string;
  hostname?: string;
  action?: string;
  outcome?: string;
  collected_at?: string;
}

/**
 * R008 — Successful Login After Failures (T1078 Valid Accounts)
 *
 * Detects a successful authentication from the same source IP and account
 * shortly after a burst of failed attempts — the strongest "access achieved"
 * signal for C001/C002 correlation. Alert-only: no automatic response.
 */
export class SuccessfulLoginAfterFailuresRule implements DetectionRule {
  readonly id = 'R008';
  readonly name = 'Successful Login After Failures';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 5,
    max_time_span_seconds: 900,
    source_types: [
      'linux_auth',
      'windows_security',
      'active_directory',
      'linux',
    ],
    // Collector emits SUCCESSFUL_LOGIN / FAILED_LOGIN (lowercased on ingest)
    actions: [
      'successful_login',
      'failed_login',
      'login',
      'user_login',
      'auth_event',
      'auth_failure',
    ],
    outcomes: ['failure', 'success'],
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const now = new Date();

    const result = await es.getClient().search({
      index: 'ctu-logs',
      size: 500,
      sort: [{ collected_at: 'asc' }],
      query: {
        bool: {
          filter: [
            { terms: { source_type: this.definition.source_types! } },
            { terms: { action: this.definition.actions! } },
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
    });

    const hits = (result.hits.hits as Array<{ _source: AuthEventHit }>).map(
      (h) => h._source,
    );

    // Group by (source_ip, user_principal)
    const groups = new Map<string, AuthEventHit[]>();
    for (const ev of hits) {
      if (!ev.source_ip || !ev.user_principal) continue;
      const key = `${ev.source_ip}|${ev.user_principal}`;
      const list = groups.get(key) ?? [];
      list.push(ev);
      groups.set(key, list);
    }

    const detections: DetectionResult[] = [];
    for (const [key, events] of groups) {
      const failures = events.filter((e) => /fail/i.test(e.outcome ?? ''));
      const successes = events.filter((e) => /success/i.test(e.outcome ?? ''));
      if (failures.length < this.definition.threshold) continue;
      if (successes.length === 0) continue;

      // Success must come after the first failure
      const firstFailure = failures
        .map((e) => new Date(e.collected_at ?? 0).getTime())
        .sort((a, b) => a - b)[0];
      const firstSuccess = successes
        .map((e) => new Date(e.collected_at ?? 0).getTime())
        .sort((a, b) => a - b)[0];
      if (!(firstSuccess >= firstFailure)) continue;

      const [ip, user] = key.split('|');
      const hosts = [
        ...new Set(events.map((e) => e.hostname).filter(Boolean)),
      ] as string[];

      detections.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary:
          `Successful login for '${user}' from ${ip} after ${failures.length} failed attempts ` +
          `(possible credential compromise)`,
        related_entities: {
          ips: [ip],
          users: [user],
          hosts,
        },
        matching_events: events.slice(0, 50).map((e) => ({
          collected_at: e.collected_at ?? new Date().toISOString(),
          source_ip: e.source_ip,
          hostname: e.hostname,
          user_principal: e.user_principal,
          action: e.action,
          outcome: e.outcome,
          source_type: undefined,
          raw_message: undefined,
        })),
      });
    }

    return detections;
  }
}
