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

interface EventBounds {
  first: number;
  last: number;
  /** Timestamps of events with outcome "success" (empty when none tagged). */
  successTimes: number[];
}

/**
 * Earliest/latest event timestamps per incident, from the stored
 * incident_events. Incident `triggered_at` is cycle-granular (all Layer-1
 * rules detected in one cycle share the same second), so ordering between
 * same-cycle incidents must use the underlying event times. Success times
 * matter for login incidents whose evidence mixes failures and successes:
 * the latest event may be a failure that says nothing about credential use.
 */
async function loadEventBounds(
  prisma: PrismaService,
  ids: string[],
): Promise<Map<string, EventBounds>> {
  const map = new Map<string, EventBounds>();
  if (ids.length === 0) return map;
  const events = await prisma.incidentEvent.findMany({
    where: { incident_id: { in: ids } },
    select: { incident_id: true, collected_at: true, outcome: true },
  });
  for (const e of events) {
    const t = e.collected_at.getTime();
    const cur = map.get(e.incident_id) ?? {
      first: t,
      last: t,
      successTimes: [],
    };
    cur.first = Math.min(cur.first, t);
    cur.last = Math.max(cur.last, t);
    if (/success/i.test(e.outcome ?? '')) cur.successTimes.push(t);
    map.set(e.incident_id, cur);
  }
  return map;
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
  /** Multiple SOAR responses (takes precedence over `response`). */
  responses?: Array<{ playbook: string; mode: 'AUTO' | 'CONFIRM' }>;
  /**
   * Drop chain hostnames from related_entities. Needed when a stage carries
   * infrastructure hostnames (e.g. the DC in R008): isolate_endpoint prefers
   * hosts over IPs and must never aim at them (MITM/AD playbook rule).
   */
  dropHosts?: boolean;
  /**
   * Lookback override: load stage incidents from now-lookbackMs instead of
   * the incremental `since`, so chains spanning correlation cycles are
   * still found. Implies cross-cycle dedup via related_entities.dedup_key.
   */
  lookbackMs?: number;
  /** When true, each stage must occur at/after the previous one. */
  ordered?: boolean;
  /** Entity predicate override (default: any IP/host/user overlap). */
  share?: ShareEntityPredicate;
}

function shareEntity(a: IncidentRow, b: IncidentRow): boolean {
  const pairs: Array<[string[], string[]]> = [
    [ipsOf(a), ipsOf(b)],
    [hostsOf(a), hostsOf(b)],
    [usersOf(a), usersOf(b)],
  ];
  return pairs.some(([x, y]) => x.length > 0 && y.length > 0 && overlap(x, y));
}

type ShareEntityPredicate = (a: IncidentRow, b: IncidentRow) => boolean;

/** Stable dedup key stored on correlation incidents (related_entities.dedup_key). */
function dedupKeyOf(i: IncidentRow): string | undefined {
  return (i.related_entities as { dedup_key?: string } | null)?.dedup_key;
}

/**
 * Depth-first stage matcher with backtracking. A greedy first-match can
 * commit to a stage candidate that dead-ends — e.g. the oldest prerequisite
 * incident shares an entity with the start but none with the terminal one,
 * while a newer candidate completes the chain — so every candidate is tried
 * before giving up on the start.
 *
 * Layer-1 incidents from the same correlation cycle have no guaranteed
 * cross-rule ordering, so stages match on time proximity (either
 * direction) rather than strict sequence timestamps.
 */
function findChain(
  start: IncidentRow,
  cfg: SequenceStageConfig,
  sorted: IncidentRow[],
  share: ShareEntityPredicate,
  bounds?: Map<string, EventBounds>,
): IncidentRow[] | null {
  const chain: IncidentRow[] = [start];
  const used = new Set<string>([start.id]);
  const search = (stage: number): boolean => {
    if (stage === cfg.stages.length) return true;
    const cursor = chain[chain.length - 1];
    for (const i of sorted) {
      if (used.has(i.id)) continue;
      if (!cfg.stages[stage].includes(i.rule_id ?? '')) continue;
      if (cfg.ordered) {
        // Stage order follows the underlying EVENT times, not triggered_at:
        // incidents created in one cycle are timestamped in rule-execution
        // order (R008 runs before R026-R028), which would invert same-cycle
        // chains. Fall back to triggered_at when an incident has no events.
        const cur = bounds?.get(cursor.id);
        const cand = bounds?.get(i.id);
        const cursorT = cur?.last ?? cursor.triggered_at.getTime();
        const candT = cand?.first ?? i.triggered_at.getTime();
        if (candT < cursorT) continue;
      }
      if (
        Math.abs(i.triggered_at.getTime() - cursor.triggered_at.getTime()) >
        WINDOW_MS
      ) {
        continue;
      }
      if (!chain.every((c) => share(c, i))) continue;
      chain.push(i);
      used.add(i.id);
      if (search(stage + 1)) return true;
      chain.pop();
      used.delete(i.id);
    }
    return false;
  };
  return search(1) ? chain : null;
}

/**
 * Generic multi-stage attack correlation: finds incident chains where each
 * stage's rule fired within WINDOW_MS of the previous one, sharing at least
 * one entity (IP, host or user) with the accumulated chain.
 */
export function sequenceCorrelation(
  cfg: SequenceStageConfig,
): AttackCorrelationRule {
  return {
    id: cfg.id,
    name: cfg.name,
    async detect(prisma: PrismaService, since: Date) {
      const stageRules = cfg.stages.flat();
      const lookback = cfg.lookbackMs
        ? new Date(Date.now() - cfg.lookbackMs)
        : since;
      const incidents = await loadIncidents(prisma, lookback, stageRules);
      const sorted = [...incidents].sort(
        (a, b) => a.triggered_at.getTime() - b.triggered_at.getTime(),
      );
      const results: AttackCorrelationResult[] = [];
      const fired = new Set<string>();
      // Cross-cycle dedup for lookback-mode rules: a chain already emitted
      // (same dedup_key on a previous cycle) must not re-fire.
      const alreadyEmitted = new Set<string>();
      if (cfg.lookbackMs) {
        for (const c of await loadIncidents(prisma, lookback, [this.id])) {
          const k = dedupKeyOf(c);
          if (k) alreadyEmitted.add(k);
        }
      }
      const share = cfg.share ?? shareEntity;
      // Event-time bounds for ordered rules (see findChain).
      const bounds = cfg.ordered
        ? await loadEventBounds(prisma, incidents.map((i) => i.id))
        : undefined;

      for (const start of sorted) {
        if (!cfg.stages[0].includes(start.rule_id ?? '')) continue;
        const chain = findChain(start, cfg, sorted, share, bounds);
        if (!chain) continue;

        const key = chain.map((c) => c.id).join('|');
        if (fired.has(key) || alreadyEmitted.has(key)) continue;
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
            hosts: cfg.dropHosts ? [] : chainHosts,
            ...(cfg.lookbackMs ? { dedup_key: key } : {}),
          },
          prerequisite_incident_ids: chain.map((c) => c.id),
          ...(cfg.responses
            ? { responses: cfg.responses }
            : { response: cfg.response }),
        });
      }
      return results;
    },
  };
}

/**
 * IP→HOST bridge through the entity graph: incidents like R003 (flow
 * bytes) carry only IPs while staging/persistence incidents carry only
 * hosts. The entity graph links an IP to the hosts it contacted, so a
 * terminal exfil incident can be matched back to the compromised host.
 */
async function bridgeIpsToHosts(
  prisma: PrismaService,
  incidents: IncidentRow[],
): Promise<Map<string, string[]>> {
  const ips = [...new Set(incidents.flatMap((i) => ipsOf(i)))];
  if (ips.length === 0) return new Map();
  const edges = await prisma.entityEdge.findMany({
    where: {
      source: { entity_type: 'IP', value: { in: ips } },
      target: { entity_type: 'HOST' },
    },
    select: {
      source: { select: { value: true } },
      target: { select: { value: true } },
    },
  });
  const ipToHosts = new Map<string, Set<string>>();
  for (const e of edges) {
    const set = ipToHosts.get(e.source.value) ?? new Set<string>();
    set.add(e.target.value);
    ipToHosts.set(e.source.value, set);
  }
  const out = new Map<string, string[]>();
  for (const i of incidents) {
    const hosts = new Set<string>();
    for (const ip of ipsOf(i)) {
      for (const h of ipToHosts.get(ip) ?? []) hosts.add(h);
    }
    if (hosts.size > 0) out.set(i.id, [...hosts]);
  }
  return out;
}

function bridgedShareEntity(
  a: IncidentRow,
  b: IncidentRow,
  bridge: Map<string, string[]>,
): boolean {
  const effectiveHosts = (i: IncidentRow) =>
    union(hostsOf(i), bridge.get(i.id) ?? []);
  const pairs: Array<[string[], string[]]> = [
    [ipsOf(a), ipsOf(b)],
    [effectiveHosts(a), effectiveHosts(b)],
    [usersOf(a), usersOf(b)],
  ];
  return pairs.some(([x, y]) => x.length > 0 && y.length > 0 && overlap(x, y));
}

/** sequenceCorrelation variant that bridges IP-only incidents to hosts via the entity graph. */
function bridgedSequenceCorrelation(
  cfg: SequenceStageConfig,
): AttackCorrelationRule {
  return {
    id: cfg.id,
    name: cfg.name,
    async detect(prisma: PrismaService, since: Date) {
      const stageRules = cfg.stages.flat();
      const incidents = await loadIncidents(prisma, since, stageRules);
      const bridge = await bridgeIpsToHosts(prisma, incidents);
      const sorted = [...incidents].sort(
        (a, b) => a.triggered_at.getTime() - b.triggered_at.getTime(),
      );
      const results: AttackCorrelationResult[] = [];
      const fired = new Set<string>();

      for (const start of sorted) {
        if (!cfg.stages[0].includes(start.rule_id ?? '')) continue;
        const chain = findChain(start, cfg, sorted, (a, b) =>
          bridgedShareEntity(a, b, bridge),
        );
        if (!chain) continue;

        const key = chain.map((c) => c.id).join('|');
        if (fired.has(key)) continue;
        fired.add(key);

        const chainIps = [...new Set(chain.flatMap((c) => ipsOf(c)))];
        const chainUsers = [...new Set(chain.flatMap((c) => usersOf(c)))];
        const chainHosts = [
          ...new Set(
            chain.flatMap((c) => union(hostsOf(c), bridge.get(c.id) ?? [])),
          ),
        ];
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
const StagingToExfiltrationRule = bridgedSequenceCorrelation({
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
const DefenseEvasionToExfilRule = bridgedSequenceCorrelation({
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
const ReconToDataTransferRule = bridgedSequenceCorrelation({
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

/**
 * C012 — AD Kerberos attack chain (ARNO_SIEM AD playbook)
 *
 * Pattern A: R030 (Kerberoasting) or R031 (AS-REP Roasting) followed within
 * 24 h by R008 (successful login after failures) from the same attacker IP —
 * the cracked credentials being used. Pattern B: an R032 (DCSync) incident
 * alone, which already proves domain-wide credential access.
 *
 * Both escalate to CRITICAL with two CONFIRM responses: isolate_endpoint
 * (attacker IP) and disable_account (compromised accounts). One C012 incident
 * per stage-1 incident (deduped against existing C012 incidents across cycles,
 * since the 24 h window far exceeds the generic 5-minute duplicate window).
 *
 * related_entities.hosts is deliberately EMPTY: the AD events are logged on
 * the DC, so R008 carries the DC hostname — unioning hosts would aim
 * isolate_endpoint at the domain controller. Containment targets the
 * attacker IP only (the playbook's "never isolate the DC" rule).
 */
export class AdAttackChainRule implements AttackCorrelationRule {
  readonly id = 'C012';
  readonly name = 'AD Kerberos Attack Chain';
  private static readonly WINDOW_MS = 24 * 60 * 60 * 1000;
  private static readonly LOOKBACK_MS = 25 * 60 * 60 * 1000;

  async detect(
    prisma: PrismaService,
    _since: Date,
  ): Promise<AttackCorrelationResult[]> {
    const lookback = new Date(Date.now() - AdAttackChainRule.LOOKBACK_MS);
    const incidents = await loadIncidents(prisma, lookback, [
      'R030',
      'R031',
      'R032',
      'R008',
    ]);
    const existing = await loadIncidents(prisma, lookback, ['C012']);

    const roastings = incidents.filter(
      (i) => i.rule_id === 'R030' || i.rule_id === 'R031',
    );
    const dcsyncs = incidents.filter((i) => i.rule_id === 'R032');
    const logins = incidents.filter((i) => i.rule_id === 'R008');

    // Dedup per ATTACK via related_entities.dedup_key = the stage-1
    // incident id (stored by build()). The prerequisite ids are NOT
    // persisted on the incident row and incident_event rows for
    // correlation results carry no es_id, so evidence-id matching cannot
    // work; entity matching remains only as a fallback for legacy C012
    // incidents created before dedup_key existed.
    const alreadyCorrelated = (
      s1: IncidentRow,
      pattern: 'roasting-then-login' | 'dcsync',
    ): boolean =>
      existing.some((c) => {
        if (c.triggered_at < s1.triggered_at) return false;
        const dk = dedupKeyOf(c);
        if (dk) return dk === s1.id;
        if (!overlap(ipsOf(c), ipsOf(s1))) return false;
        if (pattern === 'dcsync') return true;
        return usersOf(s1).length === 0 || overlap(usersOf(c), usersOf(s1));
      });

    const results: AttackCorrelationResult[] = [];
    const fired = new Set<string>();

    const build = (
      s1: IncidentRow,
      s2: IncidentRow | null,
      pattern: 'roasting-then-login' | 'dcsync',
    ): AttackCorrelationResult => ({
      rule_id: this.id,
      rule_name: this.name,
      severity: 'CRITICAL',
      confidence_score: 92,
      summary:
        pattern === 'dcsync'
          ? `AD domain compromise: DCSync (${s1.rule_id}) — directory ` +
            `replication rights abused; isolate attacker and disable ` +
            `compromised accounts`
          : `AD attack chain: ${s1.rule_id} followed by successful login ` +
            `(${s2?.rule_id}) from the same attacker IP within 24 hours — ` +
            `cracked credentials in use; isolate attacker and disable accounts`,
      related_entities: {
        ips: union(ipsOf(s1), s2 ? ipsOf(s2) : []),
        users: union(usersOf(s1), s2 ? usersOf(s2) : []),
        hosts: [],
        dedup_key: s1.id,
      },
      prerequisite_incident_ids: s2 ? [s1.id, s2.id] : [s1.id],
      responses: [
        { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
        { playbook: 'disable_account', mode: 'CONFIRM' },
      ],
    });

    // Pattern B — DCSync alone proves domain compromise
    for (const d of dcsyncs) {
      if (fired.has(d.id) || alreadyCorrelated(d, 'dcsync')) continue;
      fired.add(d.id);
      results.push(build(d, null, 'dcsync'));
    }

    // Pattern A — roasting followed by successful use of credentials.
    // Ordering uses the underlying event times, not incident triggered_at:
    // same-cycle incidents share a cycle timestamp and Layer-1 rules run in
    // array order (R008 before R030), which would invert the chain. For the
    // login incident the relevant time is its SUCCESS outcome — R008 stores
    // failures and successes mixed, and a failure after the success says
    // nothing about credential use.
    const bounds = await loadEventBounds(prisma, [
      ...roastings.map((i) => i.id),
      ...logins.map((i) => i.id),
    ]);
    const firstOf = (i: IncidentRow): number =>
      bounds.get(i.id)?.first ?? i.triggered_at.getTime();
    const lastOf = (i: IncidentRow): number =>
      bounds.get(i.id)?.last ?? i.triggered_at.getTime();
    // Earliest successful-login time after the roasting completed and
    // within the chain window, or null. The lower bound is the roasting's
    // LAST event: a login between the first and last ticket request is not
    // "roasting followed by credential use". Falls back to the incident's
    // latest event when the evidence carries no success outcome (older
    // incidents, untagged sources).
    const loginUseAfter = (
      l: IncidentRow,
      roastStart: number,
      roastEnd: number,
    ): number | null => {
      const inWindow = (x: number) =>
        x >= roastEnd && x - roastStart <= AdAttackChainRule.WINDOW_MS;
      const times = bounds.get(l.id)?.successTimes;
      if (!times || times.length === 0) {
        const t = lastOf(l);
        return inWindow(t) ? t : null;
      }
      const matches = times.filter(inWindow);
      return matches.length ? Math.min(...matches) : null;
    };

    for (const s1 of roastings) {
      if (fired.has(s1.id) || alreadyCorrelated(s1, 'roasting-then-login'))
        continue;
      const s1Ips = ipsOf(s1);
      if (s1Ips.length === 0) continue;
      const roastStart = firstOf(s1);
      const roastEnd = lastOf(s1);
      const candidates = logins
        .filter((l) => overlap(ipsOf(l), s1Ips))
        .map((l) => ({ l, use: loginUseAfter(l, roastStart, roastEnd) }))
        .filter((c): c is { l: IncidentRow; use: number } => c.use !== null)
        .sort((a, b) => a.use - b.use);
      const s2 = candidates[0]?.l;
      if (!s2) continue;
      fired.add(s1.id);
      results.push(build(s1, s2, 'roasting-then-login'));
    }

    return results;
  }
}

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
  new AdAttackChainRule(),
  /**
   * C011 — MITM to account compromise (ARNO_SIEM MITM playbook):
   * (R026 ARP spoofing | R027 rogue DHCP | R028 LLMNR/NBT-NS poisoning)
   * followed by R008 (successful login after failures — the intercepted
   * or relayed victim credentials being used) from the same attacker IP
   * within 30 minutes → CRITICAL.
   *
   * isolate_endpoint + disable_account, both CONFIRM. dropHosts: R008
   * carries the victim machine/DC hostname and isolate_endpoint prefers
   * hosts — containment must aim at the attacker IP, never infrastructure.
   */
  sequenceCorrelation({
    id: 'C011',
    name: 'MITM to Account Compromise',
    stages: [['R026', 'R027', 'R028'], ['R008']],
    severity: 'CRITICAL',
    confidence: 90,
    summary: (chain) =>
      `MITM precursor (${chain[0].rule_id ?? '?'}) followed by successful ` +
      'login after failures from the same entity within 30min — possible ' +
      'intercepted-credential use',
    responses: [
      { playbook: 'isolate_endpoint', mode: 'CONFIRM' },
      { playbook: 'disable_account', mode: 'CONFIRM' },
    ],
    dropHosts: true,
    // The playbook window is 30min measured from the MITM event; incidents
    // arrive a cycle later, so look back 35min and require the MITM stage
    // to precede the login. Same-IP-only sharing prevents unrelated
    // username-only coincidences from chaining.
    lookbackMs: 35 * 60 * 1000,
    ordered: true,
    share: (a, b) => {
      const ips = (i: typeof a) => ipsOf(i);
      return overlap(ips(a), ips(b));
    },
  }),
];
