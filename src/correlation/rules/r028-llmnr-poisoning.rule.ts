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
  destination_ip?: string;
  destination_port?: number;
}

function envSet(name: string): Set<string> {
  return new Set(
    (process.env[name] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

async function search(
  es: ElasticsearchService,
  filter: Record<string, unknown>[],
  size = 2000,
): Promise<Hit[]> {
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size,
    query: {
      bool: {
        filter: [
          ...filter,
          {
            range: {
              normalized_at: {
                gte: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
                lte: new Date().toISOString(),
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
 * R028 — LLMNR/NBT-NS poisoning (T1557.001)
 *
 * Primary signal: a host answering LLMNR/NBT-NS queries (UDP 5355/137)
 * to ≥3 distinct workstations within 10 minutes while not being a
 * legitimate name server (NAME_SERVERS_ALLOWED) — the Responder pattern.
 * Corroborating evidence: NTLM network logons (4624 type 3 / 4648 / 8004)
 * from the same source IP are attached to the incident.
 *
 * Containment blocks the responder IP — never the spoofed identities.
 */
export class LlmnrPoisoningRule implements DetectionRule {
  readonly id = 'R028';
  readonly name = 'LLMNR/NBT-NS Poisoning';
  readonly definition: RuleDefinition = {
    time_window_seconds: 600,
    interval_seconds: 300,
    threshold: 3,
    source_types: ['firewall'],
    actions: ['llmnr_nbtns_flow'],
    trigger_playbook: 'block_ip',
    playbook_mode: 'CONFIRM',
  };

  async detect(
    es: ElasticsearchService,
    _since: Date,
  ): Promise<DetectionResult[]> {
    const flows = await search(es, [
      { term: { source_type: 'firewall' } },
      { term: { action: 'llmnr_nbtns_flow' } },
    ]);

    const byResponder = new Map<string, Hit[]>();
    for (const f of flows) {
      if (!f.source_ip || f.source_ip === '0.0.0.0') continue;
      const list = byResponder.get(f.source_ip) ?? [];
      list.push(f);
      byResponder.set(f.source_ip, list);
    }

    const allowed = envSet('NAME_SERVERS_ALLOWED');
    const now = Date.now();
    const results: DetectionResult[] = [];

    for (const [responder, evs] of byResponder) {
      if (allowed.has(responder.toLowerCase())) continue;
      // Rolling 10-minute windows: ≥3 distinct destination workstations.
      const sorted = [...evs].sort(
        (a, b) =>
          new Date(a.collected_at ?? 0).getTime() -
          new Date(b.collected_at ?? 0).getTime(),
      );
      let matched: Hit[] = [];
      for (let i = 0; i < sorted.length && !matched.length; i++) {
        const t0 = new Date(sorted[i].collected_at ?? 0).getTime();
        const win = sorted.filter((e) => {
          const t = new Date(e.collected_at ?? 0).getTime();
          return t >= t0 && t - t0 <= 10 * 60 * 1000 && t <= now;
        });
        const distinct = new Set(
          win.map((e) => e.destination_ip).filter(Boolean),
        );
        if (distinct.size >= 3) matched = win;
      }
      if (!matched.length) continue;

      // Corroborating NTLM logons from the responder IP (evidence only).
      const ntlm = await search(
        es,
        [
          { term: { source_type: 'windows_security' } },
          {
            terms: { event_id: [4624, 4648, 8004] },
          },
          { term: { source_ip: responder } },
        ],
        100,
      );

      const matching = [...matched, ...ntlm].slice(0, 50);
      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary:
          `LLMNR/NBT-NS responder ${responder} answered queries from ` +
          `${new Set(matched.map((e) => e.destination_ip)).size} distinct hosts ` +
          `in 10min (${ntlm.length} NTLM logon event(s) corroborate)`,
        related_entities: {
          // SAFETY: block_ip blocks every listed IP — only the responder
          // may be listed, never the victim workstations it answered.
          ips: [responder],
          users: [
            ...new Set(ntlm.map((e) => e.user_principal).filter(Boolean)),
          ] as string[],
          hosts: [],
        },
        matching_events: matching.map(toPayload),
      });
    }
    return results;
  }
}
