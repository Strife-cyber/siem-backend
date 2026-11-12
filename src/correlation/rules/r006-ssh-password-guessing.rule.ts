import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionResult,
  DetectionRule,
  IncidentEventPayload,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

interface AuthHit {
  collected_at?: string;
  normalized_at?: string;
  source_ip?: string;
  hostname?: string;
  user_principal?: string;
  action?: string;
  outcome?: string;
  source_type?: string;
  raw_message?: string;
}

/** Fetch auth events since `since` (ingestion-time gated) for JS analysis. */
async function fetchAuthEvents(
  es: ElasticsearchService,
  since: Date,
  sourceTypes: string[],
  actions: string[],
  size = 1000,
): Promise<AuthHit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size,
    query: {
      bool: {
        filter: [
          { terms: { source_type: sourceTypes } },
          { terms: { action: actions } },
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
  return (result.hits.hits as Array<{ _source: AuthHit }>).map(
    (h) => h._source,
  );
}

function toPayload(e: AuthHit): IncidentEventPayload {
  return {
    collected_at: e.collected_at ?? new Date().toISOString(),
    source_ip: e.source_ip,
    hostname: e.hostname,
    user_principal: e.user_principal,
    action: e.action,
    outcome: e.outcome,
    source_type: e.source_type,
    raw_message: e.raw_message,
  };
}

/**
 * R006 — SSH Password Guessing (T1110.001)
 *
 * Many failed SSH logins from one IP against the SAME account — targeted
 * password guessing, as opposed to R007 spraying (many accounts) and the
 * generic R001 burst rule. Response: block_ip AUTO.
 */
export class SshPasswordGuessingRule implements DetectionRule {
  readonly id = 'R006';
  readonly name = 'SSH Password Guessing';
  readonly definition: RuleDefinition = {
    time_window_seconds: 300,
    interval_seconds: 60,
    threshold: 5,
    max_time_span_seconds: 120,
    source_types: ['linux_auth', 'linux', 'syslog'],
    actions: ['failed_login', 'auth_failure'],
    trigger_playbook: 'block_ip',
    playbook_mode: 'AUTO',
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchAuthEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
    );

    // Only SSH-ish failures
    const ssh = events.filter((e) =>
      /sshd|ssh2|port \d+ ssh/i.test(e.raw_message ?? ''),
    );

    const groups = new Map<string, AuthHit[]>();
    for (const e of ssh) {
      if (!e.source_ip || !e.user_principal) continue;
      const key = `${e.source_ip}|${e.user_principal}`;
      const list = groups.get(key) ?? [];
      list.push(e);
      groups.set(key, list);
    }

    const detections: DetectionResult[] = [];
    for (const [key, list] of groups) {
      if (list.length < this.definition.threshold) continue;
      const times = list
        .map((e) => new Date(e.collected_at ?? 0).getTime())
        .sort((a, b) => a - b);
      const span = (times[times.length - 1] - times[0]) / 1000;
      if (
        this.definition.max_time_span_seconds &&
        span > this.definition.max_time_span_seconds
      )
        continue;

      const [ip, user] = key.split('|');
      const hosts = [
        ...new Set(list.map((e) => e.hostname).filter(Boolean)),
      ] as string[];
      detections.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary: `SSH password guessing: ${list.length} failed logins for '${user}' from ${ip} in ${Math.round(span)}s`,
        related_entities: { ips: [ip], users: [user], hosts },
        matching_events: list.slice(0, 50).map(toPayload),
      });
    }
    return detections;
  }
}

/**
 * R007 — Password Spraying (T1110.003)
 *
 * One IP attempts logins across MANY distinct accounts — spraying a common
 * password. Distinct-user cardinality separates it from R006 guessing.
 * Response: temporary_block AUTO.
 */
export class PasswordSprayingRule implements DetectionRule {
  readonly id = 'R007';
  readonly name = 'Password Spraying';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 10,
    source_types: ['linux_auth', 'linux', 'syslog', 'windows_security'],
    actions: ['failed_login', 'auth_failure'],
    params: { min_distinct_users: 3 },
    trigger_playbook: 'temporary_block',
    playbook_mode: 'AUTO',
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchAuthEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
    );

    const byIp = new Map<string, AuthHit[]>();
    for (const e of events) {
      if (!e.source_ip || !e.user_principal) continue;
      const list = byIp.get(e.source_ip) ?? [];
      list.push(e);
      byIp.set(e.source_ip, list);
    }

    const minUsers =
      (this.definition.params?.min_distinct_users as number) ?? 3;
    const detections: DetectionResult[] = [];
    for (const [ip, list] of byIp) {
      if (list.length < this.definition.threshold) continue;
      const users = [
        ...new Set(list.map((e) => e.user_principal).filter(Boolean)),
      ] as string[];
      if (users.length < minUsers) continue; // guessing, not spraying

      const hosts = [
        ...new Set(list.map((e) => e.hostname).filter(Boolean)),
      ] as string[];
      detections.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 80,
        summary: `Password spraying: ${list.length} failed logins across ${users.length} distinct accounts from ${ip}`,
        related_entities: { ips: [ip], users, hosts },
        matching_events: list.slice(0, 50).map(toPayload),
      });
    }
    return detections;
  }
}
