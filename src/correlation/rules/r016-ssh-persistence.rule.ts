import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionResult,
  DetectionRule,
  IncidentEventPayload,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

interface Hit {
  collected_at?: string;
  source_ip?: string;
  hostname?: string;
  user_principal?: string;
  action?: string;
  outcome?: string;
  source_type?: string;
  raw_message?: string;
  file_path?: string;
  file_operation?: string;
}

async function fetchFileEvents(
  es: ElasticsearchService,
  since: Date,
): Promise<Hit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size: 1000,
    query: {
      bool: {
        filter: [
          { term: { source_type: 'linux_auditd' } },
          { term: { action: 'file_access' } },
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
  return (result.hits.hits as Array<{ _source: Hit }>).map((h) => h._source);
}

function toPayload(e: Hit): IncidentEventPayload {
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
 * R016 — SSH Persistence (T1098.004)
 *
 * auditd PATH records (file_access) touching any `authorized_keys` file.
 * Creating or modifying SSH authorized_keys is a classic persistence
 * mechanism (MITRE T1098.004); deletions are also suspicious on servers
 * where key-based access is managed centrally.
 *
 * Requires auditd watch rules on ~/.ssh (see deployment docs). Alert-only:
 * the spec calls for `alert` CONFIRM, but no analyst-alert playbook exists
 * yet — same gap as R011/R012/R014.
 */
export class SshPersistenceRule implements DetectionRule {
  readonly id = 'R016';
  readonly name = 'SSH Persistence (authorized_keys)';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['linux_auditd'],
    actions: ['file_access'],
  };

  private readonly authorizedKeysRe = /authorized_keys/i;

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchFileEvents(es, since);

    const suspicious = events.filter((e) =>
      this.authorizedKeysRe.test(e.file_path ?? ''),
    );
    if (suspicious.length < this.definition.threshold) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary: `SSH persistence: ${suspicious.length} authorized_keys file event(s) (${[...new Set(suspicious.map((e) => e.file_operation).filter(Boolean))].join(', ')})`,
        related_entities: {
          ips: [
            ...new Set(suspicious.map((e) => e.source_ip).filter(Boolean)),
          ] as string[],
          users: [
            ...new Set(suspicious.map((e) => e.user_principal).filter(Boolean)),
          ] as string[],
          hosts: [
            ...new Set(suspicious.map((e) => e.hostname).filter(Boolean)),
          ] as string[],
        },
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}
