import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';
import { parseWindowsSecurity } from './windows-security.enricher';
import { parseLinuxAuth } from './linux-auth.enricher';
import { parseFirewall } from './firewall.enricher';

/**
 * Enricher function signature.
 * Takes the raw message + normalized log, returns extra ES fields.
 */
export type EnricherFn = (
  raw_message: string,
  log: NormalizedLog,
) => Partial<EnrichedLog>;

/**
 * Registry mapping source_type to its enricher.
 * Add new enrichers here as they're created.
 */
const enricherRegistry: Record<string, EnricherFn> = {
  windows_security: parseWindowsSecurity,
  linux_auth: parseLinuxAuth,
  firewall: parseFirewall,
  web_proxy: parseFirewall,
  syslog: parseLinuxAuth,
};

/**
 * Run enrichment on a normalized log.
 * Returns the enriched fields to merge into the ES document.
 */
export function enrichLog(log: NormalizedLog): Partial<EnrichedLog> {
  const enricher = enricherRegistry[log.source_type];
  if (!enricher) {
    return {};
  }
  try {
    return enricher(log.raw_message, log);
  } catch {
    // Parsing errors are non-fatal — log without enrichment
    return {};
  }
}
