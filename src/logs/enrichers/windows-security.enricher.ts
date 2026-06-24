import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';

/**
 * Parse Windows Security Event raw_message to extract structured fields.
 *
 * Supports:
 * - Event 4625 (logon failure) → logon_type, target_user, failure_reason, source_ip
 * - Event 4624 (logon success) → logon_type, auth_package, workstation, source_ip
 * - Event 1102 (log cleared)   → event_id
 * - Event 104 (log stopped)    → event_id
 * - Generic Event NNNN         → event_id only
 */
export function parseWindowsSecurity(
  raw: string,
  _log: NormalizedLog,
): Partial<EnrichedLog> {
  const enriched: Partial<EnrichedLog> = {};

  // Extract Event ID (most structured field)
  const eventIdMatch = raw.match(/Event\s+(\d+)/i);
  if (eventIdMatch) {
    enriched.event_id = parseInt(eventIdMatch[1], 10);
  }

  // ---- Event 4625: Logon Failure ----
  if (enriched.event_id === 4625) {
    // Logon Type
    const logonTypeMatch = raw.match(/Logon\s+Type:\s*(\d+)/i);
    if (logonTypeMatch) {
      enriched.logon_type = parseInt(logonTypeMatch[1], 10);
    }
    // Target Account Name
    const targetUserMatch = raw.match(/Account\s+Name:\s*(\S+)/i);
    if (targetUserMatch) {
      enriched.target_user =
        targetUserMatch[1] !== '-' ? targetUserMatch[1] : undefined;
    }
    // Failure Reason
    const reasonMatch = raw.match(/Failure\s+Reason:\s*(.+?)(?:\.|$)/i);
    if (reasonMatch) {
      enriched.failure_reason = reasonMatch[1].trim();
    }
    // Source Network Address
    const sourceMatch = raw.match(/Source\s+Network\s+Address:\s*(\S+)/i);
    if (sourceMatch) {
      const val = sourceMatch[1].replace(/\.+$/, '').trim();
      enriched.source_network_address = val !== '-' ? val : undefined;
    }
    // Workstation Name
    const wsMatch = raw.match(/Workstation\s+Name:\s*(\S+)/i);
    if (wsMatch) {
      const val = wsMatch[1].replace(/\.+$/, '').trim();
      enriched.workstation = val !== '-' ? val : undefined;
    }
  }

  // ---- Event 4624: Logon Success ----
  if (enriched.event_id === 4624) {
    // Logon Type
    const logonTypeMatch = raw.match(/Logon\s+Type:\s*(\d+)/i);
    if (logonTypeMatch) {
      enriched.logon_type = parseInt(logonTypeMatch[1], 10);
    }
    // Authentication Package (PtH detection: look for NTLM)
    const authMatch = raw.match(/Authentication\s+Package:\s*(\S+)/i);
    if (authMatch) {
      enriched.auth_package = authMatch[1];
    }
    // Logon Process
    const procMatch = raw.match(/Logon\s+Process:\s*(\S+)/i);
    if (procMatch) {
      enriched.service_name = procMatch[1];
    }
    // Workstation Name
    const wsMatch = raw.match(/Workstation\s+Name:\s*(\S+)/i);
    if (wsMatch) {
      enriched.workstation = wsMatch[1] !== '-' ? wsMatch[1] : undefined;
    }
    // Source Network Address
    const sourceMatch = raw.match(/Source\s+Network\s+Address:\s*(\S+)/i);
    if (sourceMatch) {
      const val = sourceMatch[1].replace(/\.+$/, '').trim();
      enriched.source_network_address = val !== '-' ? val : undefined;
    }
  }

  return enriched;
}
