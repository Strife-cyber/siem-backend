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
  command_line?: string;
  process_name?: string;
}

async function fetchExecEvents(
  es: ElasticsearchService,
  since: Date,
): Promise<Hit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size: 1000,
    query: {
      bool: {
        filter: [
          { term: { source_type: 'linux_auditd' } },
          { term: { action: 'process_exec' } },
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
 * R012 — Linux Shell Abuse (T1059.004)
 *
 * Auditd EXECVE records whose command line shows interactive/reverse shells,
 * download-and-execute cradles, encoded payloads, or socket-based tooling.
 * Matches the structured `command_line` field emitted by the collector's
 * auditd parser, falling back to `raw_message` for older records.
 *
 * Alert-only: no automated response (no process-kill playbook exists yet).
 */
export class LinuxShellAbuseRule implements DetectionRule {
  readonly id = 'R012';
  readonly name = 'Linux Shell Abuse';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['linux_auditd'],
    actions: ['process_exec'],
  };

  private readonly suspiciousRe =
    /(\bbash\s+-(i|c)\b.*\b(bash|sh)\b|\/dev\/tcp\/|\bnc(at)?\s+[^|]*-[a-z]*[el]\b|\bsocat\b|python[0-9.]*\s+-c\b[^|]*\bsocket\b|perl\s+-e\b[^|]*\bsocket\b|ruby\s+-e\b[^|]*\bsocket\b|\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?\/?(?:[\w.~-]+\/)*(?:ba)?sh\b|\bbase64\s+(-d|--decode)\b|\bmkfifo\b[^|]*\bsocat\b)/i;

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchExecEvents(es, since);

    const suspicious = events.filter((e) => {
      const haystack = `${e.command_line ?? ''}\n${e.raw_message ?? ''}`;
      return this.suspiciousRe.test(haystack);
    });
    if (suspicious.length < this.definition.threshold) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary: `Linux shell abuse: ${suspicious.length} process execution(s) with reverse-shell/download-execute/encoded-payload patterns`,
        related_entities: {
          ips: [
            ...new Set(suspicious.map((e) => e.source_ip).filter(Boolean)),
          ] as string[],
          users: [
            ...new Set(suspicious.map((e) => e.user_principal).filter(Boolean)),
          ] as string[],
          hosts: [
            ...new Set(suspicious.map((e) => e.hostname).filter(Boolean)),
          ] as string[],
        },
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}
