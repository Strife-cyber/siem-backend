import {
  DetectionRule,
  DetectionResult,
} from '../interfaces/detection-rule.interface';
import { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import {
  fetchAdEvents,
  isMachineAccount,
  resolveLogonSourceIp,
} from './ad-events';

/**
 * R032 — DCSync (T1003.006).
 * Source: Windows 4662 (directory service access) whose Properties include
 * the replication GUIDs (enriched as replication_right = true), excluding
 * machine accounts (…$) and AD_REPLICATION_ALLOWED principals.
 * The attacker IP is resolved by joining SubjectLogonId to the 4624
 * logon-success event (TargetLogonId) within 24 h.
 * Playbook: AD playbook R032. Response: isolate_endpoint (CONFIRM).
 */
export class DcsyncRule implements DetectionRule {
  id = 'R032';
  name = 'DCSync — directory replication rights abuse';
  definition = {
    time_window_seconds: 300,
    interval_seconds: 60,
    threshold: 1,
    max_time_span_seconds: 300,
    source_types: ['windows_security', 'active_directory'],
    actions: ['windows_event'],
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM' as const,
    params: {
      replication_allowed_env: 'AD_REPLICATION_ALLOWED',
      dc_accounts_default: 'machine accounts (…$)',
    },
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchAdEvents(es, since, [4662]);
    const allowed = new Set(
      (process.env.AD_REPLICATION_ALLOWED ?? '')
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    );

    const results: DetectionResult[] = [];
    for (const e of events) {
      if (e.replication_right !== true) continue;
      if (e.status_code && e.status_code !== '0x0') continue;
      const subject = (e.subject_user_name ?? e.user_principal ?? '').trim();
      if (!subject) continue;
      if (isMachineAccount(subject)) continue; // DCs/machine accounts
      if (allowed.has(subject.toLowerCase())) continue;

      const ip = await resolveLogonSourceIp(es, e.logon_id, e.hostname);
      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity: 'CRITICAL',
        confidence_score: ip ? 95 : 85,
        summary: ip
          ? `DCSync attempt: ${subject} exercised directory-replication rights from ${ip}`
          : `DCSync attempt by ${subject} — source IP unresolved (no matching 4624 logon in 24h); manual containment required`,
        related_entities: {
          ips: ip ? [ip] : [],
          users: [subject],
          hosts: [],
        },
        matching_events: [e],
      });
    }
    return results;
  }
}
