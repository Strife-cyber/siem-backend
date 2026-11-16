import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';

/**
 * Shared helpers for the AD attack rules (R030–R032, C012) from the
 * ARNO_SIEM Active Directory playbook. Windows Security Kerberos and
 * directory-service events are enriched backend-side from raw XML
 * (see enrichers/windows-security.enricher.ts).
 */

export interface AdHit {
  collected_at: string;
  normalized_at?: string;
  source_ip?: string;
  hostname?: string;
  user_principal?: string;
  event_id?: number;
  spn?: string;
  ticket_encryption_type?: string;
  preauth_type?: number;
  status_code?: string;
  logon_id?: string;
  subject_user_name?: string;
  replication_right?: boolean;
  raw_message?: string;
  [key: string]: unknown;
}

/** Fetch Windows Security events for the given event IDs, ingestion-time gated. */
export async function fetchAdEvents(
  es: ElasticsearchService,
  since: Date,
  eventIds: number[],
  size = 1000,
): Promise<AdHit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size,
    query: {
      bool: {
        filter: [
          { terms: { source_type: ['windows_security', 'active_directory'] } },
          { terms: { event_id: eventIds } },
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
  // Sort chronologically: R030/R031 compute group time spans from the
  // first/last hit, which is only meaningful on ordered events.
  return (result.hits.hits as Array<{ _source: AdHit }>)
    .map((h) => h._source)
    .sort(
      (a, b) =>
        Date.parse(a.normalized_at ?? a.collected_at ?? '') -
        Date.parse(b.normalized_at ?? b.collected_at ?? ''),
    );
}

/**
 * Resolve the source IP of a directory-service access (4662) via the
 * matching logon-success event (4624) carrying the same logon session ID.
 * Searches a 24 h lookback — the logon typically precedes the replication.
 */
export async function resolveLogonSourceIp(
  es: ElasticsearchService,
  logonId: string | undefined,
): Promise<string | undefined> {
  if (!logonId) return undefined;
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size: 1,
    query: {
      bool: {
        filter: [
          { terms: { source_type: ['windows_security', 'active_directory'] } },
          { term: { event_id: 4624 } },
          { term: { logon_id: logonId } },
          {
            range: {
              normalized_at: {
                gte: since.toISOString(),
              },
            },
          },
        ],
      },
    },
    sort: [{ normalized_at: 'desc' }],
  });
  const hit = result.hits.hits[0] as { _source: AdHit } | undefined;
  const ip = hit?._source?.source_ip;
  return ip && ip !== '0.0.0.0' ? ip : undefined;
}

function envList(name: string): Set<string> {
  return new Set(
    (process.env[name] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

/** Accounts whose service tickets must never be requested legitimately (canary). */
export function adHoneyAccounts(): Set<string> {
  return envList('AD_HONEY_ACCOUNTS');
}

/** ServiceName values allowed to use legacy RC4 encryption. */
export function adRc4AllowedServices(): Set<string> {
  return envList('AD_RC4_ALLOWED_SERVICES');
}

/** Accounts allowed to authenticate without Kerberos pre-authentication. */
export function adNoPreAuthAllowed(): Set<string> {
  return envList('AD_NOPREAUTH_ALLOWED');
}

/** Accounts explicitly allowed directory-replication rights (beyond DCs). */
export function adReplicationAllowed(): Set<string> {
  return envList('AD_REPLICATION_ALLOWED');
}

/** Whether a name looks like a machine/DC account (…$). */
export function isMachineAccount(name: string | undefined): boolean {
  return !!name && name.trim().endsWith('$');
}
