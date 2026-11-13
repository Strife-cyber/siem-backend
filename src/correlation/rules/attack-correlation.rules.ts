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

interface SequenceStageConfig {
  id: string;
  name: string;
  /** Ordered prerequisite rule-id stages; each must fire within WINDOW_MS of the previous. */
  stages: string[][];
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  confidence: number;
  summary: (chain: IncidentRow[]) => string;
  response?: { playbook: string; mode: 'AUTO' | 'CONFIRM' };
}

function shareEntity(a: IncidentRow, b: IncidentRow): boolean {
  const pairs: Array<[string[], string[]]> = [
    [ipsOf(a), ipsOf(b)],
    [hostsOf(a), hostsOf(b)],
    [usersOf(a), usersOf(b)],
  ];
  return pairs.some(([x, y]) => x.length > 0 && y.length > 0 && overlap(x, y));
}

/**
 * Generic multi-stage attack correlation: finds incident chains where each
 * stage's rule fired after the previous one, within WINDOW_MS, sharing at
 * least one entity (IP, host or user) with the accumulated chain.
 */
function sequenceCorrelation(cfg: SequenceStageConfig): AttackCorrelationRule {
  return {
    id: cfg.id,
    name: cfg.name,
    async detect(prisma: PrismaService, since: Date) {
      const stageRules = cfg.stages.flat();
      const incidents = await loadIncidents(prisma, since, stageRules);
      const sorted = [...incidents].sort(
        (a, b) => a.triggered_at.getTime() - b.triggered_at.getTime(),
      );
      const results: AttackCorrelationResult[] = [];
      const fired = new Set<string>();

      for (const start of sorted) {
        if (!cfg.stages[0].includes(start.rule_id ?? '')) continue;
        const chain: IncidentRow[] = [start];
        let cursor = start;
        let matched = true;

        for (let s = 1; s < cfg.stages.length; s++) {
          // Layer-1 incidents from the same correlation cycle have no
          // guaranteed cross-rule ordering, so match on time proximity
          // (either direction) rather than strict sequence timestamps.
          const next = sorted.find(
            (i) =>
              cfg.stages[s].includes(i.rule_id ?? '') &&
              Math.abs(
                i.triggered_at.getTime() - cursor.triggered_at.getTime(),
              ) <= WINDOW_MS &&
              chain.every((c) => shareEntity(c, i)),
          );
          if (!next) {
            matched = false;
            break;
          }
          chain.push(next);
          cursor = next;
        }
        if (!matched) continue;

        const key = chain.map((c) => c.id).join('|');
        if (fired.has(key)) continue;
        fired.add(key);

        const chainIps = [...new Set(chain.flatMap((c) => ipsOf(c)))];
        const chainUsers = [...new Set(chain.flatMap((c) => usersOf(c)))];
        const chainHosts = [...new Set(chain.flatMap((c) => hostsOf(c)))];
        results.push({
          rule_id: this.id,
          rule_name: this.name,
          severity: cfg.severity,
          confidence_score: cfg.confidence,
          summary: cfg.summary(chain),
          related_entities: {
            ips: chainIps,
            users: chainUsers,
            hosts: chainHosts,
          },
          prerequisite_incident_ids: chain.map((c) => c.id),
          response: cfg.response,
        });
      }
      return results;
    },
  };
}

/**
 * C006 — Suspicious administrative account creation (spec §4, MITRE T1136+T1098+T1078)
 * R010 (admin account created) followed by R008 (successful login after
 * failures) for the same account/IP within 30 minutes → disable_account CONFIRM.
 */
const SuspiciousAdminAccountChainRule = sequenceCorrelation({
  id: 'C006',
  name: 'Suspicious Admin Account Creation Chain',
  stages: [['R010'], ['R008']],
  severity: 'HIGH',
  confidence: 80,
  summary: (chain) =>
    `Attack sequence: privileged account creation (${chain[0].rule_id}) followed by ` +
    `suspicious authentication (${chain[1].rule_id}) within 30 minutes`,
  response: { playbook: 'disable_account', mode: 'CONFIRM' },
});

/**
 * C007 — Malware execution followed by persistence (spec §4, MITRE T1059+T1053+T1543)
 * R011 (suspicious PowerShell) followed by R015 (scheduled task) or R017
 * (startup persistence) on the same host within 30 minutes → isolate CONFIRM.
 */
const MalwareToPersistenceRule = sequenceCorrelation({
  id: 'C007',
  name: 'Malware Execution to Persistence',
  stages: [['R011'], ['R015', 'R017']],
  severity: 'HIGH',
  confidence: 85,
  summary: (chain) =>
    `Attack sequence: suspicious script execution (${chain[0].rule_id}) followed by ` +
    `persistence mechanism (${chain[1].rule_id}) within 30 minutes`,
  response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
});

/**
 * C008 — Credential theft followed by lateral movement (spec §4, MITRE T1003+T1078+T1550)
 * R002 (pass-the-hash) followed by R022 (SMB lateral movement) from the same
 * source IP within 30 minutes → isolate CONFIRM.
 */
const CredentialTheftToLateralRule = sequenceCorrelation({
  id: 'C008',
  name: 'Credential Theft to Lateral Movement',
  stages: [['R002'], ['R022']],
  severity: 'HIGH',
  confidence: 85,
  summary: (chain) =>
    `Attack sequence: credential abuse (${chain[0].rule_id}) followed by SMB ` +
    `lateral movement (${chain[1].rule_id}) within 30 minutes`,
  response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
});

/**
 * C010 — Ransomware preparation and execution (spec §4, MITRE T1562+T1489+T1486)
 * R018 (security tools disabled) followed by R020 (security-artifact deletion)
 * on the same host within 30 minutes → CRITICAL, immediate isolation CONFIRM.
 *
 * Note: full ransomware staging (mass encryption) has no telemetry yet; this
 * correlates the two provable precursor behaviors.
 */
const RansomwarePreparationRule = sequenceCorrelation({
  id: 'C010',
  name: 'Ransomware Preparation Chain',
  stages: [['R018'], ['R020']],
  severity: 'CRITICAL',
  confidence: 88,
  summary: (chain) =>
    `Ransomware preparation: security monitoring disabled (${chain[0].rule_id}) ` +
    `followed by artifact deletion (${chain[1].rule_id}) within 30 minutes`,
  response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
});

/**
 * C004 — Data staging followed by exfiltration (spec §4, MITRE T1074+T1041)
 * R008 (successful access) → R025 (unusual staging) → R003 (outbound flow
 * volume) sharing entities within 30 minutes → isolate with confirmation.
 * The spec's directory-enumeration step has no dedicated rule yet; access +
 * staging + transfer is the provable chain.
 */
const StagingToExfiltrationRule = sequenceCorrelation({
  id: 'C004',
  name: 'Data Staging and Exfiltration Chain',
  stages: [['R008'], ['R025'], ['R003']],
  severity: 'HIGH',
  confidence: 85,
  summary: (chain) =>
    `Exfiltration sequence: access (${chain[0].rule_id}) → staging ` +
    `(${chain[1].rule_id}) → outbound transfer (${chain[2].rule_id}) ` +
    `within 30 minutes`,
  response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
});

/**
 * C005 — Defense evasion followed by exfiltration (spec §4, MITRE T1562+T1070+T1041)
 * R018 (security tools disabled) → R019 (firewall modified) or R004 (logs
 * cleared) → R003 (outbound flow volume) → CRITICAL, isolate CONFIRM.
 */
const DefenseEvasionToExfilRule = sequenceCorrelation({
  id: 'C005',
  name: 'Defense Evasion to Exfiltration Chain',
  stages: [['R018'], ['R019', 'R004'], ['R003']],
  severity: 'CRITICAL',
  confidence: 88,
  summary: (chain) =>
    `Exfiltration after defense evasion: ${chain[0].rule_id} → ` +
    `${chain[1].rule_id} → outbound transfer (${chain[2].rule_id}) ` +
    `within 30 minutes`,
  response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
});

/**
 * C009 — Internal recon followed by abnormal transfer (spec §4, MITRE T1018+T1046+T1041)
 * R021 (internal discovery) → R005 (reconnaissance/scan) → R003 (outbound
 * flow volume). Database-connection and query-anomaly steps have no
 * telemetry yet; this correlates the provable recon → transfer chain.
 */
const ReconToDataTransferRule = sequenceCorrelation({
  id: 'C009',
  name: 'Internal Recon to Data Transfer Chain',
  stages: [['R021'], ['R005'], ['R003']],
  severity: 'HIGH',
  confidence: 80,
  summary: (chain) =>
    `Recon-to-exfil sequence: internal discovery (${chain[0].rule_id}) → ` +
    `scan (${chain[1].rule_id}) → abnormal outbound transfer ` +
    `(${chain[2].rule_id}) within 30 minutes`,
  response: { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
});

export const ATTACK_CORRELATION_RULES: AttackCorrelationRule[] = [
  new ReconToAccessRule(),
  new BruteForceToCompromiseRule(),
  new LateralMovementRule(),
  SuspiciousAdminAccountChainRule,
  MalwareToPersistenceRule,
  CredentialTheftToLateralRule,
  RansomwarePreparationRule,
  StagingToExfiltrationRule,
  DefenseEvasionToExfilRule,
  ReconToDataTransferRule,
];
