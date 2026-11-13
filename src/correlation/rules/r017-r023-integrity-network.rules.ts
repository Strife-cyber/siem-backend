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

async function fetchEvents(
  es: ElasticsearchService,
  since: Date,
  sourceTypes: string[],
  actions: string[],
  size = 500,
): Promise<Hit[]> {
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
              // Gate on ingestion time, not event time: replayed/backdated
              // logs would otherwise be skipped forever by lastRun.
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

function entities(events: Hit[]) {
  return {
    ips: [
      ...new Set(events.map((e) => e.source_ip).filter(Boolean)),
    ] as string[],
    users: [
      ...new Set(events.map((e) => e.user_principal).filter(Boolean)),
    ] as string[],
    hosts: [
      ...new Set(events.map((e) => e.hostname).filter(Boolean)),
    ] as string[],
  };
}

/**
 * R017 — Startup Persistence (T1547)
 *
 * Registry Run/RunOnce/Startup modifications and new service installs
 * (7045) on Windows endpoints. Alert-only (no automated response).
 */
export class StartupPersistenceRule implements DetectionRule {
  readonly id = 'R017';
  readonly name = 'Startup Persistence Mechanism';
  readonly definition: RuleDefinition = {
    time_window_seconds: 3600,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['windows_security', 'windows'],
    actions: ['registry_modify', 'service_event'],
  };

  private readonly runKeyRe =
    /CurrentVersion\\Run|RunOnce|\\Startup\\|StartupApproved/i;
  private readonly newServiceRe = /<EventID>7045<\/EventID>/;

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
    );

    const suspicious = events.filter((e) => {
      const raw = e.raw_message ?? '';
      if (e.action === 'registry_modify') return this.runKeyRe.test(raw);
      if (e.action === 'service_event') return this.newServiceRe.test(raw);
      return false;
    });
    if (suspicious.length < this.definition.threshold) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 75,
        summary: `Startup persistence: ${suspicious.length} Run-key/service-install event(s) detected`,
        related_entities: entities(suspicious),
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}

/**
 * R018 — Antivirus / EDR Disablement (T1562.001)
 *
 * Security service stop events (7036) for known AV/EDR products.
 * HIGH — isolate endpoint with analyst confirmation.
 */
export class DefenseEvasionRule implements DetectionRule {
  readonly id = 'R018';
  readonly name = 'Antivirus / EDR Disablement';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 120,
    threshold: 1,
    source_types: ['windows_security', 'windows'],
    actions: ['service_event'],
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM',
  };

  private readonly stopRe = /<EventID>7036<\/EventID>[\s\S]*stopped/i;
  private readonly securityServiceRe =
    /(WinDefend|MsMpEng|SecurityHealthService|Sense|CrowdStrike|Falcon|SentinelOne|Cylance|Sophos|avast|avg|defender)/i;

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
      200,
    );

    const suspicious = events.filter(
      (e) =>
        this.stopRe.test(e.raw_message ?? '') &&
        this.securityServiceRe.test(e.raw_message ?? ''),
    );
    if (suspicious.length < this.definition.threshold) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary: `Security monitoring disabled: ${suspicious.length} AV/EDR service stop event(s)`,
        related_entities: entities(suspicious),
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}

/**
 * R020 — Suspicious File Deletion (T1070.004)
 *
 * Windows 4663 file-access events with DELETE access (AccessMask 0x10000)
 * against logs, security artifacts or credential stores. HIGH — isolate
 * endpoint with analyst confirmation.
 */
export class FileDeletionRule implements DetectionRule {
  readonly id = 'R020';
  readonly name = 'Suspicious File Deletion';
  readonly definition: RuleDefinition = {
    time_window_seconds: 3600,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['windows_security', 'windows'],
    actions: ['file_access'],
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM',
  };

  private readonly deleteMaskRe = /AccessMask">0x10000/i;
  private readonly sensitiveTargetRe =
    /(\.evtx|winevt|\\.log\b|\/var\/log|\/etc\/passwd|\/etc\/shadow|ntds\.dit|SAM$)/i;

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
      500,
    );

    const suspicious = events.filter((e) => {
      const raw = e.raw_message ?? '';
      return this.deleteMaskRe.test(raw) && this.sensitiveTargetRe.test(raw);
    });
    if (suspicious.length < this.definition.threshold) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 80,
        summary: `Suspicious deletion of security artifacts: ${suspicious.length} event(s)`,
        related_entities: entities(suspicious),
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}

const NETWORK_SOURCE_TYPES = [
  'firewall',
  'web_proxy',
  'traefik',
  'linux_network',
  'syslog',
  'linux',
];
const NETWORK_ACTIONS = [
  'network_connect',
  'network_flow',
  'http_request',
  'firewall_allow',
  'firewall_deny',
  'firewall_event',
  'connection_state',
];

interface ScanBucket {
  key: string;
  doc_count: number;
  target_count?: { value: number };
}

async function scanAggregation(
  es: ElasticsearchService,
  since: Date,
  extraFilter: Record<string, unknown>[] = [],
  minDocCount = 8,
): Promise<ScanBucket[]> {
  const now = new Date();
  const result = await es
    .getClient()
    .search({
      index: 'ctu-logs',
      size: 0,
      query: {
        bool: {
          filter: [
            { terms: { source_type: NETWORK_SOURCE_TYPES } },
            { terms: { action: NETWORK_ACTIONS } },
            {
              range: {
                normalized_at: {
                  gte: since.toISOString(),
                  lte: now.toISOString(),
                },
              },
            },
            ...extraFilter,
          ],
        },
      },
      aggs: {
        by_source: {
          terms: { field: 'source_ip', size: 50, min_doc_count: minDocCount },
          aggs: {
            target_count: { cardinality: { field: 'destination_ip' } },
          },
        },
      },
    })
    .then((r) => r as never);
  return (
    (result as { aggregations?: { by_source?: { buckets?: ScanBucket[] } } })
      ?.aggregations?.by_source?.buckets ?? []
  );
}

/**
 * R021 — Internal Network Discovery (T1018)
 *
 * One internal source contacting many distinct internal destinations on a
 * single service (host discovery / sweep) — distinct from R005 port scans.
 * Alert-only.
 */
export class InternalDiscoveryRule implements DetectionRule {
  readonly id = 'R021';
  readonly name = 'Internal Network Discovery';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 8,
    source_types: NETWORK_SOURCE_TYPES,
    actions: NETWORK_ACTIONS,
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const buckets = await scanAggregation(es, since);
    const results: DetectionResult[] = [];
    for (const b of buckets) {
      const targets = b.target_count?.value ?? 0;
      if (targets < this.definition.threshold) continue;
      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 70,
        summary: `Internal discovery: ${b.key} contacted ${targets} distinct internal destinations (${b.doc_count} connections)`,
        related_entities: { ips: [b.key] },
      });
    }
    return results;
  }
}

/**
 * R022 — SMB Lateral Movement (T1021.002)
 *
 * One internal source opening SMB (445) sessions to multiple internal
 * destinations. Alert-only.
 */
export class SmbLateralMovementRule implements DetectionRule {
  readonly id = 'R022';
  readonly name = 'SMB Lateral Movement';
  readonly definition: RuleDefinition = {
    time_window_seconds: 1800,
    interval_seconds: 300,
    threshold: 3,
    source_types: NETWORK_SOURCE_TYPES,
    actions: NETWORK_ACTIONS,
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const buckets = await scanAggregation(
      es,
      since,
      [{ term: { destination_port: 445 } }],
      3,
    );
    const results: DetectionResult[] = [];
    for (const b of buckets) {
      const targets = b.target_count?.value ?? 0;
      if (targets < this.definition.threshold) continue;
      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 80,
        summary: `SMB lateral movement: ${b.key} connected to ${targets} internal hosts over port 445`,
        related_entities: { ips: [b.key] },
      });
    }
    return results;
  }
}

/**
 * R023 — RDP Lateral Movement (T1021.001)
 *
 * One internal source opening RDP (3389) sessions to multiple internal
 * destinations. Alert-only.
 */
export class RdpLateralMovementRule implements DetectionRule {
  readonly id = 'R023';
  readonly name = 'RDP Lateral Movement';
  readonly definition: RuleDefinition = {
    time_window_seconds: 1800,
    interval_seconds: 300,
    threshold: 3,
    source_types: NETWORK_SOURCE_TYPES,
    actions: NETWORK_ACTIONS,
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const buckets = await scanAggregation(
      es,
      since,
      [{ term: { destination_port: 3389 } }],
      3,
    );
    const results: DetectionResult[] = [];
    for (const b of buckets) {
      const targets = b.target_count?.value ?? 0;
      if (targets < this.definition.threshold) continue;
      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 80,
        summary: `RDP lateral movement: ${b.key} connected to ${targets} internal hosts over port 3389`,
        related_entities: { ips: [b.key] },
      });
    }
    return results;
  }
}
