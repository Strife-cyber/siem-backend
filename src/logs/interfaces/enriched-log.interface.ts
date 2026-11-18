import type { NormalizedLog } from './normalized-log.interface';

/**
 * Enriched log document sent to Elasticsearch.
 * Extends NormalizedLog with parsed fields extracted from raw_message.
 * No changes to the collector or NormalizedLog interface.
 */
export interface EnrichedLog extends NormalizedLog {
  /** Enrichment fields extracted from raw_message during processing */
  event_id?: number;
  logon_type?: number;
  target_user?: string;
  failure_reason?: string;
  source_network_address?: string;
  workstation?: string;
  auth_package?: string;
  service_name?: string;
  bytes_sent?: number;
  bytes_recv?: number;
  direction?: string;
  protocol?: string;
  duration_seconds?: number;
  rule_name?: string;
  /** Kerberos/AD fields (events 4768, 4769, 4662, 4624) — see AD playbook */
  preauth_type?: number;
  ticket_encryption_type?: string;
  spn?: string;
  logon_id?: string;
  subject_user_name?: string;
  status_code?: string;
  replication_right?: boolean;
  /** ARP/DHCP MITM fields (pfSense syslog, arpwatch, dhclient) — see MITM playbook */
  arp_usurped_ip?: string;
  arp_mac_old?: string;
  arp_mac_new?: string;
  arp_iface?: string;
  dhcp_server_ip?: string;
  dhcp_offered_ip?: string;
}
