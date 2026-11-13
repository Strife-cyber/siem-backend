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
  domain?: string;
}

async function fetchDnsQueries(
  es: ElasticsearchService,
  since: Date,
): Promise<Hit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size: 2000,
    query: {
      bool: {
        filter: [
          { terms: { source_type: ['linux_syslog', 'firewall'] } },
          { term: { action: 'dns_query' } },
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
 * Parent (registered) domain of a hostname: the last two labels. DNS
 * tunneling encodes data in unique subdomains of one attacker domain, so
 * volume must be aggregated per parent, not per exact query name.
 */
function parentDomain(domain: string): string {
  const labels = domain.split('.').filter(Boolean);
  if (labels.length <= 2) return domain;
  return labels.slice(-2).join('.');
}

/** Shannon entropy (bits/char) of a string. */
function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * R024 — DNS Tunneling (T1071.004)
 *
 * Exfiltration over DNS hides data in high-entropy subdomain labels and
 * generates abnormal query volume. Per the spec, a long query alone is NOT
 * enough: a domain is suspicious only when it combines high volume with
 * either a very long name or high character entropy.
 *
 * Tunneling rotates a unique label per query under one parent domain, so
 * volume is aggregated per parent domain while length/entropy are checked
 * on the full queried names within the group.
 *
 * Requires resolver telemetry (dnsmasq/unbound) — see siem-collector#6.
 * Alert-only: the spec calls for `block_domain` CONFIRM, but no such SOAR
 * playbook exists yet (same gap as R011/R012/R016).
 */
export class DnsTunnelingRule implements DetectionRule {
  readonly id = 'R024';
  readonly name = 'DNS Tunneling';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 30,
    source_types: ['linux_syslog', 'firewall'],
    actions: ['dns_query'],
  };

  private readonly minVolume = 30;
  private readonly minLongName = 40;
  private readonly minEntropy = 3.6;

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchDnsQueries(es, since);

    const byParent = new Map<string, Hit[]>();
    for (const e of events) {
      const d = e.domain;
      if (!d) continue;
      const parent = parentDomain(d);
      const list = byParent.get(parent) ?? [];
      list.push(e);
      byParent.set(parent, list);
    }

    const suspicious = [...byParent.entries()]
      .map(([parent, evs]) => {
        const maxNameLength = Math.max(...evs.map((e) => e.domain!.length));
        const maxEntropy = Math.max(
          ...evs.map((e) => shannonEntropy(e.domain!)),
        );
        return { parent, evs, maxNameLength, maxEntropy };
      })
      .filter(
        (g) =>
          g.evs.length >= this.minVolume &&
          (g.maxNameLength >= this.minLongName ||
            g.maxEntropy >= this.minEntropy),
      )
      .sort((a, b) => b.evs.length - a.evs.length);

    if (suspicious.length === 0) return [];

    const matching = suspicious.flatMap((g) => g.evs);
    const summary = suspicious
      .slice(0, 5)
      .map(
        (g) =>
          `${g.parent} (${g.evs.length} queries, longest name ${g.maxNameLength} chars)`,
      )
      .join(', ');

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary: `Possible DNS tunneling: ${suspicious.length} domain(s) with high-volume + long/high-entropy names — ${summary}`,
        related_entities: {
          ips: [
            ...new Set(matching.map((e) => e.source_ip).filter(Boolean)),
          ] as string[],
          users: [
            ...new Set(matching.map((e) => e.user_principal).filter(Boolean)),
          ] as string[],
          hosts: [
            ...new Set(matching.map((e) => e.hostname).filter(Boolean)),
          ] as string[],
        },
        matching_events: matching.slice(0, 50).map(toPayload),
      },
    ];
  }
}
