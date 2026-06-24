import type { EnrichedLog } from '../interfaces/enriched-log.interface';
import type { NormalizedLog } from '../interfaces/normalized-log.interface';

/**
 * Parse firewall / proxy / netflow raw_message to extract traffic fields.
 *
 * Supports:
 * - Generic "ALLOW TCP x.x.x.x:port -> y.y.y.y:port bytes_sent=N bytes_recv=N"
 * - Proxy logs with HTTP method + URL + byte counts
 * - Netflow with src_ip/dst_ip/bytes/protocol
 */
export function parseFirewall(
  raw: string,
  _log: NormalizedLog,
): Partial<EnrichedLog> {
  const enriched: Partial<EnrichedLog> = {};

  const upper = raw.toUpperCase();

  // ---- Direction ----
  if (upper.includes('OUTBOUND') || raw.includes('->')) {
    enriched.direction = 'outbound';
  } else if (upper.includes('INBOUND') || raw.includes('<-')) {
    enriched.direction = 'inbound';
  }

  // ---- Protocol ----
  if (upper.includes('TCP')) enriched.protocol = 'TCP';
  else if (upper.includes('UDP')) enriched.protocol = 'UDP';
  else if (upper.includes('ICMP')) enriched.protocol = 'ICMP';
  else if (upper.includes('HTTP')) enriched.protocol = 'HTTP';
  else if (upper.includes('HTTPS')) enriched.protocol = 'HTTPS';
  else if (upper.includes('DNS')) enriched.protocol = 'DNS';
  else if (upper.includes('FTP')) enriched.protocol = 'FTP';
  else if (upper.includes('SMB')) enriched.protocol = 'SMB';

  // ---- Byte counts ----
  // Supports: bytes_sent=52428800, bytes: 1024, bytes_recv=8192
  const bytesSentMatch = raw.match(/bytes(?:_sent|=|:)\s*[=:]?\s*(\d+)/i);
  if (bytesSentMatch) {
    enriched.bytes_sent = parseInt(bytesSentMatch[1], 10);
  }

  const bytesRecvMatch = raw.match(
    /bytes(?:_recv|received|=|:)\s*[=:]?\s*(\d+)/i,
  );
  if (bytesRecvMatch) {
    enriched.bytes_recv = parseInt(bytesRecvMatch[1], 10);
  }

  // ---- Duration (seconds) ----
  const durationMatch = raw.match(/duration(?:\s*[:=]\s*)(\d+)/i);
  if (durationMatch) {
    enriched.duration_seconds = parseInt(durationMatch[1], 10);
  }

  // ---- HTTP method from proxy logs ----
  const httpMethodMatch = raw.match(
    /\b(GET|POST|PUT|DELETE|PATCH|HEAD|CONNECT)\s+(https?:\/\/\S+)/i,
  );
  if (httpMethodMatch) {
    enriched.protocol = 'HTTP';
    enriched.service_name = httpMethodMatch[2]; // full URL
  }

  return enriched;
}
