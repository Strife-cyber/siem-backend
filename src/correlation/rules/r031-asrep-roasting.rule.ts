import {
  DetectionRule,
  DetectionResult,
} from '../interfaces/detection-rule.interface';
import { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import {
  AdHit,
  adNoPreAuthAllowed,
  fetchAdEvents,
  isMachineAccount,
} from './ad-events';

/**
 * R031 — AS-REP Roasting (T1558.004).
 * Source: Windows 4768 (TGT requested) with PreAuthType = 0 and Status 0x0.
 *  - ≥1 roastable account from an IP within the window → HIGH per account
 *  - ≥3 distinct accounts from the same IP                 → CRITICAL sweep
 * Playbook: AD playbook R031. Response: block_ip (CONFIRM).
 */
export class AsrepRoastingRule implements DetectionRule {
  id = 'R031';
  name = 'AS-REP Roasting — Kerberos pre-auth disabled account abuse';
  definition = {
    time_window_seconds: 600,
    interval_seconds: 60,
    threshold: 3,
    max_time_span_seconds: 600,
    source_types: ['windows_security', 'active_directory'],
    actions: ['windows_event'],
    trigger_playbook: 'block_ip',
    playbook_mode: 'CONFIRM' as const,
    params: { no_pre_auth_allowed_env: 'AD_NOPREAUTH_ALLOWED' },
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchAdEvents(es, since, [4768]);
    const allowed = adNoPreAuthAllowed();

    const eligible = events.filter((e) => {
      if (e.preauth_type !== 0) return false;
      if (e.status_code !== '0x0') return false;
      const user = (e.user_principal ?? '').trim();
      if (!user || isMachineAccount(user)) return false;
      if (allowed.has(user.toLowerCase())) return false;
      return true;
    });
    if (eligible.length === 0) return [];

    // Group by source IP, keep per-account events
    const byIp = new Map<string, AdHit[]>();
    for (const e of eligible) {
      const ip = e.source_ip;
      if (!ip) continue;
      const list = byIp.get(ip) ?? [];
      list.push(e);
      byIp.set(ip, list);
    }

    const results: DetectionResult[] = [];
    for (const [ip, group] of byIp) {
      const spanOk =
        Date.parse(group[group.length - 1].normalized_at ?? '') -
          Date.parse(group[0].normalized_at ?? '') <=
        600_000;
      if (!spanOk) continue;

      const byAccount = new Map<string, AdHit[]>();
      for (const e of group) {
        const user = (e.user_principal ?? '').trim().toLowerCase();
        const list = byAccount.get(user) ?? [];
        list.push(e);
        byAccount.set(user, list);
      }

      if (byAccount.size >= 3) {
        // Sweep: one CRITICAL per source IP
        const accounts = [...byAccount.keys()];
        results.push({
          rule_id: this.id,
          rule_name: this.name,
          severity: 'CRITICAL',
          confidence_score: 90,
          summary: `AS-REP Roasting sweep from ${ip}: ${byAccount.size} distinct pre-auth-disabled accounts requested (${accounts.join(', ')})`,
          related_entities: { ips: [ip], users: accounts, hosts: [] },
          matching_events: group.slice(0, 50),
        });
      } else {
        // Individual roastable requests: HIGH per account
        for (const [user, hits] of byAccount) {
          results.push({
            rule_id: this.id,
            rule_name: this.name,
            severity: 'HIGH',
            confidence_score: 80,
            summary: `AS-REP Roasting candidate: ${user} requested TGT without pre-authentication from ${ip}`,
            related_entities: { ips: [ip], users: [user], hosts: [] },
            matching_events: hits.slice(0, 50),
          });
        }
      }
    }
    return results;
  }
}
