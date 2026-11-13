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
  sourceTypes: string[],
): Promise<Hit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size: 2000,
    query: {
      bool: {
        filter: [
          { terms: { source_type: sourceTypes } },
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

/** Compression/archive container extensions attackers stage data into. */
const ARCHIVE_RE = /\.(zip|zipx|7z|rar|tar|gz|tgz|bz2|xz|lz4|zst)$/i;

/** Operations that indicate a file being created or appended to. */
const STAGING_OPERATIONS = new Set(['create', 'write']);

/**
 * R025 — Unusual Data Staging (T1074)
 *
 * Before exfiltration, attackers aggregate collected data into archives.
 * This rule detects bursts of archive-file creation/write events on a single
 * host within the correlation window, using the structured file-operation
 * telemetry from auditd PATH records (Linux) and Windows 4663 object-access
 * events.
 *
 * Deliberately narrow: only `create`/`write` operations on archive
 * extensions count, so log rotation, package installs and single backup
 * archives stay below the volume threshold. Content-level staging (reading
 * sensitive files) still needs FIM/content telemetry — see simulation/README.
 *
 * Alert-only: the spec calls for `alert` CONFIRM, but no analyst-alert
 * playbook exists yet (same gap as R011/R012/R016/R024).
 */
export class DataStagingRule implements DetectionRule {
  readonly id = 'R025';
  readonly name = 'Unusual Data Staging';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 5,
    source_types: ['linux_auditd', 'windows_security', 'windows_fim'],
    actions: ['file_access'],
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchFileEvents(
      es,
      since,
      this.definition.source_types!,
    );

    const staging = events.filter(
      (e) =>
        e.file_path &&
        ARCHIVE_RE.test(e.file_path) &&
        STAGING_OPERATIONS.has(e.file_operation ?? ''),
    );

    // Aggregate per host: staging is a per-endpoint behavior.
    const byHost = new Map<string, Hit[]>();
    for (const e of staging) {
      const host = e.hostname ?? 'unknown';
      const list = byHost.get(host) ?? [];
      list.push(e);
      byHost.set(host, list);
    }

    const suspiciousHosts = [...byHost.entries()]
      .filter(([, evs]) => evs.length >= this.definition.threshold)
      .sort((a, b) => b[1].length - a[1].length);

    if (suspiciousHosts.length === 0) return [];

    const matching = suspiciousHosts.flatMap(([, evs]) => evs);
    const hostSummary = suspiciousHosts
      .slice(0, 5)
      .map(([host, evs]) => `${host} (${evs.length} archives)`)
      .join(', ');
    const samplePaths = [...new Set(matching.map((e) => e.file_path))]
      .slice(0, 5)
      .join(', ');

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 80,
        summary: `Unusual data staging: ${suspiciousHosts.length} host(s) created/wrote multiple archive files in 15min — ${hostSummary}; e.g. ${samplePaths}`,
        related_entities: {
          ips: [
            ...new Set(matching.map((e) => e.source_ip).filter(Boolean)),
          ] as string[],
          users: [
            ...new Set(matching.map((e) => e.user_principal).filter(Boolean)),
          ] as string[],
          hosts: suspiciousHosts.map(([host]) => host),
        },
        matching_events: matching.slice(0, 50).map(toPayload),
      },
    ];
  }
}
