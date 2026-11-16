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
  dhcp_server_ip?: string;
  dhcp_offered_ip?: string;
}

function envSet(name: string): Set<string> {
  return new Set(
    (process.env[name] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

/**
 * R027 — Rogue DHCP server (T1557.003)
 *
 * A host offering DHCP leases that is not in DHCP_SERVERS_ALLOWED is
 * treated as a rogue server (playbook: serveur ∉ DHCP_SERVERS_AUTORISÉS
 * → HIGH). Containment isolates the *server* host, never the offered IP.
 */
export class RogueDhcpRule implements DetectionRule {
  readonly id = 'R027';
  readonly name = 'Rogue DHCP Server';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['linux_syslog', 'linux', 'syslog'],
    actions: ['dhcp_lease_offer'],
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM',
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const allowed = envSet('DHCP_SERVERS_ALLOWED');
    const result = await es.getClient().search({
      index: 'ctu-logs',
      size: 500,
      query: {
        bool: {
          filter: [
            {
              terms: { source_type: ['linux_syslog', 'linux', 'syslog'] },
            },
            { term: { action: 'dhcp_lease_offer' } },
            {
              range: {
                normalized_at: {
                  gte: since.toISOString(),
                  lte: new Date().toISOString(),
                },
              },
            },
          ],
        },
      },
    });
    const hits = (result.hits.hits as Array<{ _source: Hit }>).map(
      (h) => h._source,
    );
    const rogue = hits.filter((h) => {
      const srv = (h.dhcp_server_ip ?? h.source_ip ?? '').toLowerCase();
      return srv && !allowed.has(srv);
    });
    if (rogue.length === 0) return [];

    const events: IncidentEventPayload[] = rogue.slice(0, 50).map((e) => ({
      collected_at: e.collected_at ?? new Date().toISOString(),
      source_ip: e.source_ip,
      hostname: e.hostname,
      user_principal: e.user_principal,
      action: e.action,
      outcome: e.outcome,
      source_type: e.source_type,
      raw_message: e.raw_message,
    }));

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary:
          `Rogue DHCP server(s) offering leases: ${[...new Set(rogue.map((e) => e.dhcp_server_ip ?? e.source_ip))].join(', ')} ` +
          `(allowed: ${[...allowed].join(', ') || 'none configured'})`,
        related_entities: {
          ips: [
            ...new Set(
              rogue
                .flatMap((e) => [e.dhcp_server_ip, e.source_ip])
                .filter((x): x is string => !!x && x !== '0.0.0.0'),
            ),
          ],
          users: [],
          hosts: [
            ...new Set(rogue.map((e) => e.hostname).filter(Boolean)),
          ] as string[],
        },
        matching_events: events,
      },
    ];
  }
}
