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
}

async function fetchRuleChanges(
  es: ElasticsearchService,
  since: Date,
): Promise<Hit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size: 500,
    query: {
      bool: {
        filter: [
          { term: { source_type: 'windows_network' } },
          { term: { action: 'firewall_rule_change' } },
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

const EVENT_ID_RE = /<EventID>(\d+)<\/EventID>/;
const EVENT_KIND: Record<string, string> = {
  '2004': 'added',
  '2005': 'modified',
  '2006': 'deleted',
  '2009': 'changed',
};

/**
 * R019 — Firewall Modification (T1562.004)
 *
 * Windows Firewall with Advanced Security rule-change audit events (2004
 * added, 2005 modified, 2006 deleted, 2009 changed). Changing or disabling
 * firewall rules is a classic defense-evasion step before data theft.
 *
 * Layer-1 rule: any rule change on a host is surfaced for analyst review
 * (WARNING, alert-only — the spec calls for `alert` CONFIRM, but no
 * analyst-alert playbook exists yet). "Unauthorized" judgement (allowlist
 * of change windows/admins) is a Layer-2/analyst concern.
 *
 * Requires the collector's Windows network subscription (2004–2009) and
 * Windows Firewall auditing enabled. pfSense config changes are a separate
 * signal and not covered by this rule.
 */
export class FirewallModificationRule implements DetectionRule {
  readonly id = 'R019';
  readonly name = 'Firewall Modification';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['windows_network'],
    actions: ['firewall_rule_change'],
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchRuleChanges(es, since);
    if (events.length < this.definition.threshold) return [];

    const kinds = events
      .map((e) => {
        const id = e.raw_message?.match(EVENT_ID_RE)?.[1];
        return id ? (EVENT_KIND[id] ?? 'changed') : 'unknown';
      })
      .filter((k, i, arr) => arr.indexOf(k) === i);

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 70,
        summary: `Firewall rule changes: ${events.length} event(s) (${kinds.join(', ')}) — possible defense evasion (T1562.004)`,
        related_entities: {
          ips: [
            ...new Set(events.map((e) => e.source_ip).filter(Boolean)),
          ] as string[],
          users: [
            ...new Set(events.map((e) => e.user_principal).filter(Boolean)),
          ] as string[],
          hosts: [
            ...new Set(events.map((e) => e.hostname).filter(Boolean)),
          ] as string[],
        },
        matching_events: events.slice(0, 50).map(toPayload),
      },
    ];
  }
}
