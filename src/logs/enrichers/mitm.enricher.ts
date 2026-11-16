import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';

/**
 * MITM / ARP-spoofing / rogue-DHCP / LLMNR-poisoning extraction.
 *
 * Parses the raw_message of already-collected telemetry (no new collector
 * source needed — ARNO_SIEM MITM playbook §3):
 *  - pfSense kernel syslog ARP lines ("arp: … moved from … to … on …",
 *    "arp: <mac> is using my IP address <ip> on <iface>!")
 *  - arpwatch lines ("changed ethernet address", "flip flop", "new station")
 *  - dhclient offers ("DHCPOFFER of <ip> from <ip>")
 *  - pfSense filterlog UDP 5355/137 (LLMNR/NBT-NS) flows
 *
 * Returns action/severity overrides plus structured fields; returns {} when
 * the line carries no MITM indicator so callers can compose with other
 * enrichers.
 */

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;

function isMac(s: string | undefined): boolean {
  return !!s && MAC_RE.test(s);
}

/** pfSense ARP kernel messages + arpwatch host messages. */
export function parseArpMitm(
  raw: string,
  _log: NormalizedLog,
): Partial<EnrichedLog> {
  const enriched: Partial<EnrichedLog> = {};

  // Motif B — a host claims an IP that is not its own (very reliable):
  // "arp: bb:.. is using my IP address 192.168.189.2 on em1!"
  const claim = raw.match(
    /arp:\s+(\S+)\s+is using my IP address\s+(\S+)\s+on\s+(\S+?)(?:\s+from\s+(\d{1,3}(?:\.\d{1,3}){3}))?!?\s*$/i,
  );
  if (claim && isMac(claim[1])) {
    enriched.action = 'arp_ip_conflict';
    enriched.severity = 4; // CRITICAL candidate — rule applies final severity
    enriched.arp_mac_new = claim[1].toLowerCase();
    enriched.arp_usurped_ip = claim[2];
    enriched.arp_iface = claim[3];
    // Some pfSense builds append the conflicting sender's IP — that is the
    // attacker's real address and the only safe containment target.
    if (claim[4]) enriched.source_ip = claim[4];
    return enriched;
  }

  // Motif A — IP moved from one MAC to another:
  // "arp: 192.168.189.10 moved from aa:.. to bb:.. on em1"
  const moved = raw.match(
    /arp:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+moved from\s+(\S+)\s+to\s+(\S+)\s+on\s+(\S+)/i,
  );
  if (moved && isMac(moved[2]) && isMac(moved[3])) {
    enriched.action = 'arp_table_change';
    enriched.severity = 3;
    enriched.arp_usurped_ip = moved[1];
    enriched.arp_mac_old = moved[2].toLowerCase();
    enriched.arp_mac_new = moved[3].toLowerCase();
    enriched.arp_iface = moved[4];
    return enriched;
  }

  // arpwatch host telemetry: MAC change / flip-flop / new station for a
  // known IP — oscillation is the spoofing signal.
  const watch = raw.match(
    /arpwatch:\s*(changed ethernet address|flip flop|new station)\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+(\S+))?/i,
  );
  if (watch) {
    enriched.action = 'arp_table_change';
    enriched.severity = 3;
    enriched.arp_usurped_ip = watch[2];
    if (watch[3] && isMac(watch[3])) {
      enriched.arp_mac_new = watch[3].toLowerCase();
    }
    return enriched;
  }

  return enriched;
}

/** dhclient rogue-DHCP offers received by a Linux host. */
export function parseDhcpMitm(
  raw: string,
  _log: NormalizedLog,
): Partial<EnrichedLog> {
  const enriched: Partial<EnrichedLog> = {};
  // "dhclient: DHCPOFFER of 192.168.189.50 from 192.168.189.50"
  const m = raw.match(/DHCP(?:OFFER|ACK)\s+of\s+(\S+)\s+from\s+(\S+)/i);
  if (!m) return enriched;
  enriched.action = 'dhcp_lease_offer';
  enriched.severity = 3;
  enriched.dhcp_offered_ip = m[1];
  enriched.dhcp_server_ip = m[2];
  return enriched;
}

const LLMNR_PORTS = new Set(['5355', '137']);
const MULTICAST_RE = /^(224\.|239\.|255\.)/;

/**
 * pfSense filterlog CSV: flag UDP flows touching LLMNR (5355) or NBT-NS
 * (137) and normalize the flow tuple — normalize_firewall's generic IP/port
 * extraction does not understand the filterlog CSV layout.
 */
export function parseLlmnrFilterlog(
  raw: string,
  _log: NormalizedLog,
): Partial<EnrichedLog> {
  const pos = raw.indexOf('filterlog:');
  if (pos === -1) return {};
  const f = raw
    .slice(pos + 'filterlog:'.length)
    .split(',')
    .map((s) => s.trim());
  if (f.length < 23) return {};
  if (f[8] !== '4') return {}; // IPv4 only
  if (f[15] !== '17') return {}; // UDP only
  if (!LLMNR_PORTS.has(f[20]) && !LLMNR_PORTS.has(f[21])) return {};
  const src = f[18];
  const dst = f[19];
  if (MULTICAST_RE.test(dst) || src === dst) return {}; // queries, not answers

  return {
    action: 'llmnr_nbtns_flow',
    severity: 3,
    source_ip: src,
    destination_ip: dst,
    source_port: parseInt(f[20], 10) || undefined,
    destination_port: parseInt(f[21], 10) || undefined,
    protocol: 'UDP',
    arp_iface: f[4], // reuse iface slot for the filterlog interface
  };
}
