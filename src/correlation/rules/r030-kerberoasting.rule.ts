import {
  DetectionRule,
  DetectionResult,
} from '../interfaces/detection-rule.interface';
import { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import {
  AdHit,
  adHoneyAccounts,
  adRc4AllowedServices,
  fetchAdEvents,
} from './ad-events';

/** Ticket encryption types considered weak/roastable (RC4 + legacy DES). */
const WEAK_ENCRYPTION_TYPES = new Set(['0x17', '0x18', '0x1', '0x3']);

/**
 * R030 — Kerberoasting / AS-REP adjacent service-ticket abuse (T1558.003).
 * Source: Windows 4769 (service ticket requested, Status 0x0).
 *  - Canary SPN (AD_HONEY_ACCOUNTS) requested at all      → CRITICAL
 *  - ≥3 distinct RC4/legacy-encrypted SPNs per (IP, user)  → HIGH
 * Playbook: AD playbook R030. Response: isolate_endpoint (CONFIRM).
 */
export class KerberoastingRule implements DetectionRule {
  id = 'R030';
  name = 'Kerberoasting — suspicious Kerberos service ticket requests';
  definition = {
    time_window_seconds: 600,
    interval_seconds: 60,
    threshold: 3,
    max_time_span_seconds: 600,
    source_types: ['windows_security', 'active_directory'],
    actions: ['windows_event'],
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM' as const,
    params: {
      honey_accounts_env: 'AD_HONEY_ACCOUNTS',
      rc4_allowed_env: 'AD_RC4_ALLOWED_SERVICES',
    },
  };

  async detect(
    es: ElasticsearchService,
    since: Date,
  ): Promise<DetectionResult[]> {
    const events = await fetchAdEvents(es, since, [4769]);
    const honey = adHoneyAccounts();
    const rc4Allowed = adRc4AllowedServices();

    const eligible = events.filter((e) => {
      if (e.status_code !== '0x0') return false;
      const spn = (e.spn ?? '').trim();
      if (!spn) return false;
      if (spn.endsWith('$')) return false; // machine accounts
      if (spn.toLowerCase() === 'krbtgt') return false;
      if (rc4Allowed.has(spn.toLowerCase())) return false;
      return true;
    });
    if (eligible.length === 0) return [];

    // Group by (source_ip, requesting user)
    const groups = new Map<string, AdHit[]>();
    for (const e of eligible) {
      const ip = e.source_ip;
      const user = e.user_principal;
      if (!ip || !user) continue;
      const key = `${ip}|${user.toLowerCase()}`;
      const list = groups.get(key) ?? [];
      list.push(e);
      groups.set(key, list);
    }

    const results: DetectionResult[] = [];
    for (const [key, group] of groups) {
      const spanOk =
        Date.parse(group[group.length - 1].normalized_at ?? '') -
          Date.parse(group[0].normalized_at ?? '') <=
        600_000;
      const honeyHits = group.filter((e) =>
        honey.has((e.spn ?? '').toLowerCase()),
      );
      const weakSpns = new Set(
        group
          .filter((e) =>
            WEAK_ENCRYPTION_TYPES.has(
              (e.ticket_encryption_type ?? '').toLowerCase(),
            ),
          )
          .map((e) => (e.spn ?? '').toLowerCase()),
      );

      if (!spanOk && honeyHits.length === 0) continue;

      let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      let reason: string;
      if (honeyHits.length > 0) {
        severity = 'CRITICAL';
        reason = `canary service account ${[...new Set(honeyHits.map((h) => h.spn))].join(', ')} targeted`;
      } else if (weakSpns.size >= 3) {
        severity = 'HIGH';
        reason = `${weakSpns.size} distinct weak-encrypted service tickets requested`;
      } else {
        continue;
      }

      const [ip, user] = key.split('|');
      const targeted = [...new Set(group.map((e) => e.spn).filter(Boolean))];
      results.push({
        rule_id: this.id,
        rule_name: this.name,
        severity,
        confidence_score: severity === 'CRITICAL' ? 95 : 85,
        summary: `Kerberoasting indicator from ${ip} (${user}): ${reason}. Targeted services: ${targeted.join(', ')}`,
        related_entities: { ips: [ip], users: [user], hosts: [] },
        matching_events: group.slice(0, 50),
      });
    }
    return results;
  }
}
