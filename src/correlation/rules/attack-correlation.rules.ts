import type { PrismaService } from '../../prisma/prisma.service';
import type {
  AttackCorrelationResult,
  AttackCorrelationRule,
} from '../interfaces/attack-correlation.interface';
import { entitiesOf } from '../interfaces/attack-correlation.interface';

const WINDOW_MS = 30 * 60 * 1000;

interface IncidentRow {
  id: string;
  rule_id: string | null;
  severity: string;
  triggered_at: Date;
  related_entities: unknown;
}

async function loadIncidents(
  prisma: PrismaService,
  since: Date,
  ruleIds: string[],
): Promise<IncidentRow[]> {
  return prisma.incident.findMany({
    where: { triggered_at: { gte: since }, rule_id: { in: ruleIds } },
    orderBy: { triggered_at: 'asc' },
    select: {
      id: true,
      rule_id: true,
      severity: true,
      triggered_at: true,
      related_entities: true,
    },
  });
}

function ipsOf(i: IncidentRow): string[] {
  return entitiesOf(i.related_entities).ips ?? [];
}
function usersOf(i: IncidentRow): string[] {
  return entitiesOf(i.related_entities).users ?? [];
}
function hostsOf(i: IncidentRow): string[] {
  return entitiesOf(i.related_entities).hosts ?? [];
}

function overlap(a: string[], b: string[]): boolean {
  return a.some((x) => b.includes(x));
}

function union(a: string[], b: string[]): string[] {
  return [...new Set([...a, ...b])];
}

/**
 * C001 — Reconnaissance → Access (spec §4)
 * R005/R001 followed by R008 (successful login) from the same source IP
 * against the same destination host within 30 minutes → CRITICAL, isolate.
 */
export class ReconToAccessRule implements AttackCorrelationRule {
  readonly id = 'C001';
  readonly name = 'Recon to Access (Scan/Brute → Compromise)';

  async detect(
    prisma: PrismaService,
    since: Date,
  ): Promise<AttackCorrelationResult[]> {
    const incidents = await loadIncidents(prisma, since, [
      'R005',
      'R001',
      'R008',
    ]);
    const successes = incidents.filter((i) => i.rule_id === 'R008');
    const precursors = incidents.filter(
      (i) => i.rule_id === 'R005' || i.rule_id === 'R001',
    );
    const results: AttackCorrelationResult[] = [];
    const fired = new Set<string>();

    for (const s of successes) {
      const sIps = ipsOf(s);
      const sHosts = hostsOf(s);
      for (const p of precursors) {
        if (p.triggered_at > s.triggered_at) continue;
        if (s.triggered_at.getTime() - p.triggered_at.getTime() > WINDOW_MS)
          continue;
        if (!overlap(sIps, ipsOf(p))) continue;
        if (
          sHosts.length > 0 &&
          hostsOf(p).length > 0 &&
          !overlap(sHosts, hostsOf(p))
        )
          continue;

        const key = `${sIps[0]}|${sHosts.join(',')}`;
        if (fired.has(key)) continue;
        fired.add(key);

        const users = union(usersOf(s), usersOf(p));
        results.push({
          rule_id: this.id,
          rule_name: this.name,
          severity: 'CRITICAL',
          confidence_score: 90,
          summary:
            `Attack sequence: reconnaissance/brute-force (${p.rule_id}) followed by successful ` +
            `access (${s.rule_id}) from ${sIps[0] ?? 'unknown'} within 30 minutes`,
          related_entities: {
            ips: union(sIps, ipsOf(p)),
            users,
            hosts: union(sHosts, hostsOf(p)),
          },
          prerequisite_incident_ids: [p.id, s.id],
          response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
        });
        break; // one correlation per success incident
      }
    }
    return results;
  }
}

/**
 * C002 — Brute force → account compromise (spec §4)
 * R001 (brute force) followed by R008 (successful login) for the same account
 * within 30 minutes → HIGH, temporary block of the source IP.
 *
 * Deviation from spec text (which suggests account disable after analyst
 * confirmation): disable_account is a stub, so the automated response is a
 * temporary IP block; account disablement remains an analyst action.
 */
export class BruteForceToCompromiseRule implements AttackCorrelationRule {
  readonly id = 'C002';
  readonly name = 'Brute Force to Account Compromise';

  async detect(
    prisma: PrismaService,
    since: Date,
  ): Promise<AttackCorrelationResult[]> {
    const incidents = await loadIncidents(prisma, since, ['R001', 'R008']);
    const brute = incidents.filter((i) => i.rule_id === 'R001');
    const successes = incidents.filter((i) => i.rule_id === 'R008');
    const results: AttackCorrelationResult[] = [];
    const fired = new Set<string>();

    for (const s of successes) {
      const sUsers = usersOf(s);
      for (const b of brute) {
        if (b.triggered_at > s.triggered_at) continue;
        if (s.triggered_at.getTime() - b.triggered_at.getTime() > WINDOW_MS)
          continue;
        // R001 does not carry users — fall back to source-IP correlation when
        // the brute-force incident has no user entities.
        const bUsers = usersOf(b);
        const matched =
          sUsers.length > 0 && bUsers.length > 0
            ? overlap(sUsers, bUsers)
            : overlap(ipsOf(s), ipsOf(b));
        if (!matched) continue;

        const key = `${sUsers.join(',')}|${s.id}`;
        if (fired.has(key)) continue;
        fired.add(key);

        results.push({
          rule_id: this.id,
          rule_name: this.name,
          severity: 'HIGH',
          confidence_score: 85,
          summary:
            `Account compromise: brute-force activity (${b.rule_id}) followed by successful ` +
            `login for '${sUsers[0] ?? 'unknown'}' from ${ipsOf(s)[0] ?? 'unknown'} within 30 minutes`,
          related_entities: {
            ips: union(ipsOf(s), ipsOf(b)),
            users: union(sUsers, usersOf(b)),
            hosts: union(hostsOf(s), hostsOf(b)),
          },
          prerequisite_incident_ids: [b.id, s.id],
          response: { playbook: 'temporary_block', mode: 'AUTO' },
        });
        break;
      }
    }
    return results;
  }
}

/**
 * C003 — Lateral movement (spec §4)
 * The same source IP appears in authentication incidents against two or more
 * distinct destination hosts within 30 minutes → HIGH, isolate with analyst
 * confirmation.
 */
export class LateralMovementRule implements AttackCorrelationRule {
  readonly id = 'C003';
  readonly name = 'Lateral Movement Across Hosts';

  async detect(
    prisma: PrismaService,
    since: Date,
  ): Promise<AttackCorrelationResult[]> {
    const incidents = await loadIncidents(prisma, since, [
      'R001',
      'R002',
      'R008',
    ]);
    // Group incident ids by source IP
    const byIp = new Map<string, IncidentRow[]>();
    for (const inc of incidents) {
      for (const ip of ipsOf(inc)) {
        const list = byIp.get(ip) ?? [];
        list.push(inc);
        byIp.set(ip, list);
      }
    }

    const results: AttackCorrelationResult[] = [];
    for (const [ip, group] of byIp) {
      // Sliding 30-min window over triggered_at
      const sorted = [...group].sort(
        (a, b) => a.triggered_at.getTime() - b.triggered_at.getTime(),
      );
      for (let i = 0; i < sorted.length; i++) {
        const window = sorted.filter(
          (x) =>
            x.triggered_at.getTime() >= sorted[i].triggered_at.getTime() &&
            x.triggered_at.getTime() - sorted[i].triggered_at.getTime() <=
              WINDOW_MS,
        );
        const distinctHosts = new Set<string>();
        for (const w of window)
          for (const h of hostsOf(w)) distinctHosts.add(h);
        if (distinctHosts.size < 2) continue;

        const hosts = [...distinctHosts];
        const allUsers = window
          .flatMap((w) => usersOf(w))
          .filter((u, i, arr) => arr.indexOf(u) === i);
        results.push({
          rule_id: this.id,
          rule_name: this.name,
          severity: 'HIGH',
          confidence_score: 80,
          summary:
            `Lateral movement: source ${ip} triggered authentication incidents on ` +
            `${distinctHosts.size} distinct hosts (${hosts.join(', ')}) within 30 minutes`,
          related_entities: {
            ips: [ip],
            users: allUsers,
            hosts,
          },
          prerequisite_incident_ids: window.map((w) => w.id),
          response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
        });
        break; // one correlation per IP per cycle
      }
    }
    return results;
  }
}

export const ATTACK_CORRELATION_RULES: AttackCorrelationRule[] = [
  new ReconToAccessRule(),
  new BruteForceToCompromiseRule(),
  new LateralMovementRule(),
];
