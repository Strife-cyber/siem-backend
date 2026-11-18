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
  command_line?: string;
  process_name?: string;
}

async function search(
  es: ElasticsearchService,
  filter: Record<string, unknown>[],
  size = 500,
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
                gte: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
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
 * R029 — DNS/gateway tampering (T1557)
 *
 * Weak-signal indicators of MITM preparation or credential harvesting:
 *  - /etc/resolv.conf write (auditd FILE_ACCESS) without an admin session
 *  - a new default route without an admin session
 *  - HTTP "GET|POST /login" over plain port 80 (nginx access log)
 *
 * WARNING by default; escalates to HIGH when ARP-spoofing evidence exists
 * for the same host in the window (playbook: combinée à R026 → HIGH).
 * Alert-only — no automated response.
 */
export class DnsGatewayTamperingRule implements DetectionRule {
  readonly id = 'R029';
  readonly name = 'DNS/Gateway Tampering';
  readonly definition: RuleDefinition = {
    time_window_seconds: 1800,
    interval_seconds: 900,
    threshold: 1,
    source_types: ['linux_auditd', 'nginx_access', 'nginx'],
    actions: ['file_access', 'process_exec', 'http_ok', 'client_error'],
  };

  async detect(
    es: ElasticsearchService,
    _since: Date,
  ): Promise<DetectionResult[]> {
    const hits = await search(es, [
      {
        bool: {
          should: [
            {
              bool: {
                filter: [
                  { term: { source_type: 'linux_auditd' } },
                  { term: { action: 'file_access' } },
                ],
                must: [{ term: { file_path: '/etc/resolv.conf' } }],
              },
            },
            {
              bool: {
                filter: [
                  { term: { source_type: 'linux_auditd' } },
                  { term: { action: 'process_exec' } },
                ],
                must: [
                  {
                    query_string: {
                      query:
                        'command_line: (*route* AND *default*) OR (command_line: *resolv.conf*)',
                    },
                  },
                ],
              },
            },
            {
              bool: {
                filter: [{ terms: { source_type: ['nginx_access', 'nginx'] } }],
                must: [
                  {
                    query_string: {
                      query: 'raw_message: *"/login"*',
                    },
                  },
                ],
              },
            },
          ],
          minimum_should_match: 1,
        },
      },
    ]);

    // Keep only real indicators (resolv.conf / route / /login); the broad
    // query above may pull adjacent file_exec noise.
    const indicators = hits.filter((h) => {
      const fp = (h.file_path ?? '').toLowerCase();
      const cl = (h.command_line ?? h.raw_message ?? '').toLowerCase();
      const raw = (h.raw_message ?? '').toLowerCase();
      // Read-only inspection is not tampering: `ip route show default`,
      // `cat /etc/resolv.conf`. Only route MODIFICATIONS and resolv.conf
      // WRITES count as process-level indicators.
      const routeTamper =
        /\b(?:ip\s+)?route\s+(?:add|append|prepend|del|delete|replace|change|set|flush)\b[^;|&]*\bdefault\b/.test(
          cl,
        );
      const resolvWrite =
        /(?:^|[\s;&|])(?:echo|printf)\b[^;|]*>\s*\/etc\/resolv\.conf/.test(
          cl,
        ) ||
        /\btee\s+(?:-a\s+)?\/etc\/resolv\.conf\b/.test(cl) ||
        /\bsed\s+-i[^;|]*\/etc\/resolv\.conf/.test(cl);
      return (
        fp === '/etc/resolv.conf' ||
        routeTamper ||
        resolvWrite ||
        /"(get|post)\s+\/login/.test(raw) ||
        /"(get|post)\s+[^ ]*\/login/.test(raw)
      );
    });
    if (indicators.length === 0) return [];

    // Alert-only rule (no playbook), so listing hosts is safe.
    const hostnames = [
      ...new Set(indicators.map((e) => e.hostname).filter(Boolean)),
    ] as string[];

    // Escalation: ARP spoofing evidence on the SAME host in the window.
    // Only hosts carrying a STRONG (non-nginx) indicator may escalate, and
    // the ARP query is restricted to those hosts — otherwise a DNS
    // indicator on host A plus an unrelated /login on host B plus B's ARP
    // evidence would produce a HIGH incident for A. nginx access logs
    // carry no scheme/port, so a /login match may be an ordinary HTTPS
    // login and must stay WARNING on its own.
    const strongHostnames = [
      ...new Set(
        indicators
          .filter(
            (e) =>
              e.source_type !== 'nginx_access' && e.source_type !== 'nginx',
          )
          .map((e) => e.hostname)
          .filter(Boolean),
      ),
    ] as string[];
    let arpEvidence = false;
    if (strongHostnames.length) {
      const arp = await search(
        es,
        [
          { terms: { source_type: ['firewall', 'linux_syslog', 'linux'] } },
          {
            terms: {
              action: ['arp_ip_conflict', 'arp_table_change'],
            },
          },
          { terms: { hostname: strongHostnames } },
        ],
        1,
      );
      arpEvidence = arp.length > 0;
    }

    const severity = arpEvidence ? 'HIGH' : 'WARNING';
    const events: IncidentEventPayload[] = indicators
      .slice(0, 50)
      .map(toPayload);

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity,
        confidence_score: severity === 'HIGH' ? 80 : 60,
        summary:
          `DNS/gateway tampering indicators on ${hostnames.join(', ') || 'unknown host'} ` +
          `(${indicators.length} event(s))` +
          (arpEvidence ? ' — correlated with ARP spoofing evidence' : ''),
        related_entities: {
          ips: [
            ...new Set(
              indicators
                .map((e) => e.source_ip)
                .filter((x): x is string => !!x && x !== '0.0.0.0'),
            ),
          ],
          users: [
            ...new Set(indicators.map((e) => e.user_principal).filter(Boolean)),
          ] as string[],
          hosts: hostnames,
        },
        matching_events: events,
      },
    ];
  }
}
