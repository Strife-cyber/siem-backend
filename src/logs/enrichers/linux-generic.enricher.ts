import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';
import { parseLinuxAuth } from './linux-auth.enricher';
import { parseFirewall } from './firewall.enricher';

/**
 * Generic Linux enricher — dispatches to specialized parsers based on
 * the raw_message content when source_type is just "linux".
 */
export function parseLinuxGeneric(
  raw: string,
  log: NormalizedLog,
): Partial<EnrichedLog> {
  const lower = raw.toLowerCase();

  // SSH/pam auth messages
  if (lower.includes('sshd') || lower.includes('pam_') || lower.includes('sudo:')) {
    return parseLinuxAuth(raw, log);
  }

  // Firewall-like messages (iptables, nftables, etc.)
  if (lower.includes('iptables') || lower.includes('nftables') || lower.includes('firewall')) {
    return parseFirewall(raw, log);
  }

  // Try linux auth as fallback — it handles many patterns
  return parseLinuxAuth(raw, log);
}
