import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';
import { parseWindowsSecurity } from './windows-security.enricher';
import { parseLinuxAuth } from './linux-auth.enricher';
import { parseFirewall } from './firewall.enricher';
import { parseLinuxGeneric } from './linux-generic.enricher';

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
  linux: parseLinuxGeneric,
  firewall: parseFirewall,
  web_proxy: parseFirewall,
  syslog: parseLinuxAuth,
  linux_syslog: parseLinuxAuth,
  linux_network: parseLinuxGeneric,
  linux_process: parseLinuxGeneric,
  linux_kernel: parseLinuxGeneric,
  linux_systemd_journal: parseLinuxGeneric,
  app: parseLinuxGeneric,
  active_directory: parseWindowsSecurity,
  windows_application: parseWindowsSecurity,
  traefik: parseFirewall,
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
