import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';

/**
 * Parse Windows Security Event raw_message to extract structured fields.
 *
 * Supports both formats:
 * - XML format (Winlogbeat with include_xml: true) — modern
 *   e.g. <Data Name='IpAddress'>192.168.243.10</Data>
 * - Legacy "Key: Value" format — older beats/collectors
 *
 * Events:
 * - 4625 (logon failure) → logon_type, target_user, failure_reason, source_ip
 * - 4624 (logon success) → logon_type, auth_package, workstation, source_ip
 * - 1102 (log cleared)   → event_id
 * - 104 (log stopped)    → event_id
 */

/**
 * Helper: extract a single XML <Data Name='...'> value from raw_message.
 * Returns the text content or undefined.
 */
function xmlField(raw: string, name: string): string | undefined {
  const re = new RegExp(`<Data\\s+Name=['"]${name}['"]>([^<]+)</Data>`, 'i');
  const m = raw.match(re);
  if (m) {
    const val = m[1].trim();
    return val && val !== '-' ? val : undefined;
  }
  return undefined;
}

export function parseWindowsSecurity(
  raw: string,
  _log: NormalizedLog,
): Partial<EnrichedLog> {
  const enriched: Partial<EnrichedLog> = {};

  // Extract Event ID (works for both XML and legacy formats)
  let eventIdMatch = raw.match(/EventID>(\d+)<\/EventID>/i);
  if (!eventIdMatch) {
    eventIdMatch = raw.match(/Event\s+(\d+)/i);
  }
  if (eventIdMatch) {
    enriched.event_id = parseInt(eventIdMatch[1], 10);
  }

  // ---- Event 4625: Logon Failure ----
  if (enriched.event_id === 4625) {
    // Logon Type — try XML first, then legacy
    let lt = xmlField(raw, 'LogonType');
    if (!lt) {
      const m = raw.match(/Logon\s+Type:\s*(\d+)/i);
      if (m) lt = m[1];
    }
    if (lt) enriched.logon_type = parseInt(lt, 10);

    // Target Account Name
    let user = xmlField(raw, 'TargetUserName');
    if (!user) {
      const m = raw.match(/Account\s+Name:\s*(\S+)/i);
      if (m) user = m[1];
    }
    enriched.target_user = user;

    // Failure Reason
    let reason = xmlField(raw, 'FailureReason');
    if (!reason) {
      const m = raw.match(/Failure\s+Reason:\s*(.+?)(?:\.|$)/i);
      if (m) reason = m[1].trim();
    }
    enriched.failure_reason = reason;

    // Source Network Address / IP
    let src = xmlField(raw, 'IpAddress');
    if (!src) {
      const m = raw.match(/Source\s+Network\s+Address:\s*(\S+)/i);
      if (m) {
        src = m[1].replace(/\.+$/, '').trim();
        src = src !== '-' ? src : undefined;
      }
    }
    enriched.source_network_address = src;

    // Override source_ip with the real attacker IP when available
    if (src && src !== '0.0.0.0' && src !== '127.0.0.1') {
      enriched.source_ip = src;
    }

    // Workstation Name
    let ws = xmlField(raw, 'WorkstationName');
    if (!ws) {
      const m = raw.match(/Workstation\s+Name:\s*(\S+)/i);
      if (m) {
        ws = m[1].replace(/\.+$/, '').trim();
        ws = ws !== '-' ? ws : undefined;
      }
    }
    enriched.workstation = ws;
  }

  // ---- Event 4624: Logon Success ----
  if (enriched.event_id === 4624) {
    // Logon Type — try XML first, then legacy
    let lt = xmlField(raw, 'LogonType');
    if (!lt) {
      const m = raw.match(/Logon\s+Type:\s*(\d+)/i);
      if (m) lt = m[1];
    }
    if (lt) enriched.logon_type = parseInt(lt, 10);

    // Authentication Package (PtH detection: look for NTLM)
    let pkg = xmlField(raw, 'AuthenticationPackageName');
    if (!pkg) {
      const m = raw.match(/Authentication\s+Package:\s*(\S+)/i);
      if (m) pkg = m[1];
    }
    enriched.auth_package = pkg;

    // Logon Process
    let proc = xmlField(raw, 'LogonProcessName');
    if (!proc) {
      const m = raw.match(/Logon\s+Process:\s*(\S+)/i);
      if (m) proc = m[1];
    }
    enriched.service_name = proc;

    // Workstation Name
    let ws = xmlField(raw, 'WorkstationName');
    if (!ws) {
      const m = raw.match(/Workstation\s+Name:\s*(\S+)/i);
      if (m) {
        ws = m[1].trim();
        ws = ws !== '-' ? ws : undefined;
      }
    }
    enriched.workstation = ws;

    // Source Network Address
    let src = xmlField(raw, 'IpAddress');
    if (!src) {
      const m = raw.match(/Source\s+Network\s+Address:\s*(\S+)/i);
      if (m) {
        src = m[1].replace(/\.+$/, '').trim();
        src = src !== '-' ? src : undefined;
      }
    }
    enriched.source_network_address = src;

    // Override source_ip with real IP when available
    if (src && src !== '0.0.0.0' && src !== '127.0.0.1') {
      enriched.source_ip = src;
    }
  }

  return enriched;
}
