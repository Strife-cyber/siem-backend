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
  arp_usurped_ip?: string;
  arp_mac_old?: string;
  arp_mac_new?: string;
  arp_iface?: string;
}

function envSet(name: string): Set<string> {
  return new Set(
    (process.env[name] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

async function fetchArpEvents(
  es: ElasticsearchService,
  _since: Date,
): Promise<Hit[]> {
  // Fixed 15-minute lookback: oscillation spans correlation cycles, and
  // `since` advances every run — a cycle-scoped window would never
  // accumulate the 3 changes the 5-minute oscillation check needs.
  const lookback = new Date(Date.now() - 15 * 60 * 1000);
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size: 2000,
    query: {
      bool: {
        filter: [
          {
            terms: {
              source_type: ['firewall', 'linux_syslog', 'linux', 'syslog'],
            },
          },
          { terms: { action: ['arp_ip_conflict', 'arp_table_change'] } },
          {
            range: {
              normalized_at: {
                gte: lookback.toISOString(),
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
 * R026 — ARP Spoofing / ARP table poisoning (T1557.002)
 *
 * pfSense kernel syslog and arpwatch report MAC changes for known IPs.
 * Per the MITM playbook: a host claiming the gateway/protected IP
 * ("is using my IP address") is CRITICAL; a protected IP moving MAC is
 * CRITICAL; ≥3 MAC changes for the same IP in 5 minutes is HIGH
 * (oscillation). Single non-protected changes are ignored — NIC/VM
 * replacement is a documented false positive handled by allowlists.
 *
 * Containment (isolate_endpoint CONFIRM) targets the reporting host/IP —
 * never the usurped IP, which is often the gateway or the DC.
 */
export class ArpSpoofingRule implements DetectionRule {
  readonly id = 'R026';
  readonly name = 'ARP Spoofing / Table Poisoning';
  readonly definition: RuleDefinition = {
    time_window_seconds: 300,
    interval_seconds: 300,
    threshold: 3,
    source_types: ['firewall', 'linux_syslog', 'linux', 'syslog'],
    actions: ['arp_ip_conflict', 'arp_table_change'],
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM',
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchArpEvents(es, since);
    if (events.length === 0) return [];

    const protectedIps = envSet('ARP_PROTECTED_IPS');

    // Oscillation: ≥3 MAC changes for the same usurped IP within 5 minutes.
    const byIp = new Map<string, Hit[]>();
    for (const e of events) {
      if (e.action !== 'arp_table_change' || !e.arp_usurped_ip) continue;
      const list = byIp.get(e.arp_usurped_ip) ?? [];
      list.push(e);
      byIp.set(e.arp_usurped_ip, list);
    }
    const oscillating = new Set<string>();
    for (const [ip, evs] of byIp) {
      const sorted = [...evs].sort(
        (a, b) =>
          new Date(a.collected_at ?? 0).getTime() -
          new Date(b.collected_at ?? 0).getTime(),
      );
      for (let i = 0; i < sorted.length; i++) {
        const window = sorted.filter(
          (e) =>
            Math.abs(
              new Date(e.collected_at ?? 0).getTime() -
                new Date(sorted[i].collected_at ?? 0).getTime(),
            ) <=
            5 * 60 * 1000,
        );
        if (window.length >= 3) {
          oscillating.add(ip);
          break;
        }
      }
    }

    const critical: Hit[] = [];
    const high: Hit[] = [];
    for (const e of events) {
      const usurped = (e.arp_usurped_ip ?? '').toLowerCase();
      if (e.action === 'arp_ip_conflict') {
        critical.push(e);
      } else if (protectedIps.has(usurped) || oscillating.has(usurped)) {
        high.push(e);
      }
      // else: single MAC change on an unprotected IP — known FP, skip.
    }

    const results: DetectionResult[] = [];
    const mk = (
      sev: 'CRITICAL' | 'HIGH',
      evs: Hit[],
      why: string,
    ): DetectionResult => ({
      rule_id: this.id,
      rule_name: this.name,
      severity: sev,
      confidence_score: sev === 'CRITICAL' ? 95 : 85,
      summary:
        `ARP spoofing indicator (${why}): ${evs.length} event(s) — ` +
        evs
          .slice(0, 5)
          .map(
            (e) =>
              `${e.arp_usurped_ip ?? '?'} ${e.arp_mac_old ?? ''}->${e.arp_mac_new ?? ''}`,
          )
          .join(', '),
      related_entities: {
        // SAFETY (MITM playbook): the usurped IP is often the gateway/DC —
        // it must never become a containment target. Only real source IPs
        // (the conflicting host, when known) are exposed to the playbook.
        ips: [
          ...new Set(
            evs
              .map((e) => e.source_ip)
              .filter(
                (x): x is string =>
                  !!x &&
                  x !== '0.0.0.0' &&
                  !evs.some((e) => e.arp_usurped_ip === x),
              ),
          ),
        ],
        users: [
          ...new Set(evs.map((e) => e.user_principal).filter(Boolean)),
        ] as string[],
        // isolate_endpoint prefers hosts over IPs — the reporting host is
        // the firewall/arpwatch box, never the attacker. Leave empty.
        hosts: [],
      },
      matching_events: evs.slice(0, 50).map(toPayload),
    });

    if (critical.length) {
      results.push(mk('CRITICAL', critical, 'host claiming a foreign IP'));
    }
    if (high.length) {
      results.push(
        mk(
          'HIGH',
          high,
          oscillating.size
            ? 'MAC oscillation ≥3/5min'
            : 'protected IP changed MAC',
        ),
      );
    }
    return results;
  }
}
