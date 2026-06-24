import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';

/**
 * Parse Linux auth / syslog raw_message to extract structured fields.
 *
 * Supports:
 * - SSH auth failures ("Failed password for root from 192.168.1.50")
 * - SSH auth successes ("Accepted password for jdoe from 192.168.1.50")
 * - Service stop events ("Stopped System Logging Service")
 * - Generic syslog patterns
 */
export function parseLinuxAuth(
  raw: string,
  _log: NormalizedLog,
): Partial<EnrichedLog> {
  const enriched: Partial<EnrichedLog> = {};

  const lower = raw.toLowerCase();

  // ---- SSH Authentication ----
  if (lower.includes('sshd') || lower.includes('ssh')) {
    enriched.service_name = 'sshd';

    // Failed password
    const failedMatch = raw.match(
      /Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)/i,
    );
    if (failedMatch) {
      enriched.target_user = failedMatch[1];
      enriched.source_network_address = failedMatch[2];
      return enriched;
    }

    // Accepted password
    const acceptedMatch = raw.match(
      /Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)/i,
    );
    if (acceptedMatch) {
      enriched.target_user = acceptedMatch[1];
      enriched.source_network_address = acceptedMatch[2];
      return enriched;
    }
  }

  // ---- Service operations (log clearing / service stop) ----
  if (
    lower.includes('stopped') ||
    lower.includes('stop') ||
    lower.includes('journalctl') ||
    lower.includes('logrotate')
  ) {
    // Try to extract service name
    const serviceMatch = raw.match(/(?:Stopped|stopped|stop)\s+(.+?)(?:\.|$)/i);
    if (serviceMatch) {
      enriched.service_name = (serviceMatch[1] ?? '').trim();
    }
  }

  return enriched;
}
