import type { ElasticsearchService } from '../../elasticsearch/elasticsearch.service';
import type {
  DetectionResult,
  DetectionRule,
  IncidentEventPayload,
  RuleDefinition,
} from '../interfaces/detection-rule.interface';

interface Hit {
  collected_at?: string;
  source_ip?: string;
  hostname?: string;
  user_principal?: string;
  action?: string;
  outcome?: string;
  source_type?: string;
  raw_message?: string;
}

async function fetchEvents(
  es: ElasticsearchService,
  since: Date,
  sourceTypes: string[],
  actions: string[],
  size = 500,
): Promise<Hit[]> {
  const now = new Date();
  const result = await es.getClient().search({
    index: 'ctu-logs',
    size,
    query: {
      bool: {
        filter: [
          { terms: { source_type: sourceTypes } },
          { terms: { action: actions } },
          { range: { normalized_at: { gte: since.toISOString(), lte: now.toISOString() } } },
        ],
      },
    },
  });
  return (result.hits.hits as Array<{ _source: Hit }>).map((h) => h._source);
}

function toPayload(e: Hit): IncidentEventPayload {
  return {
    collected_at: e.collected_at ?? new Date().toISOString(),
    source_ip: e.source_ip,
    hostname: e.hostname,
    user_principal: e.user_principal,
    action: e.action,
    outcome: e.outcome,
    source_type: e.source_type,
    raw_message: e.raw_message,
  };
}

function entities(events: Hit[]) {
  return {
    ips: [...new Set(events.map((e) => e.source_ip).filter(Boolean))] as string[],
    users: [...new Set(events.map((e) => e.user_principal).filter(Boolean))] as string[],
    hosts: [...new Set(events.map((e) => e.hostname).filter(Boolean))] as string[],
  };
}

/**
 * R010 — Suspicious New Admin Account (T1136.001)
 *
 * Account management events (useradd/userdel/useradmin) whose raw message
 * references administrative groups or privileges (sudo/wheel/admin/root).
 * Alert-only: no automated response (account disablement is a stub).
 */
export class SuspiciousAdminAccountRule implements DetectionRule {
  readonly id = 'R010';
  readonly name = 'Suspicious New Admin Account';
  readonly definition: RuleDefinition = {
    time_window_seconds: 3600,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['linux_auth', 'linux', 'syslog', 'active_directory', 'windows_security'],
    actions: ['user_management', 'account_created', 'account_modified'],
  };

  async detect(es: ElasticsearchService, since: Date): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
    );

    const suspicious = events.filter((e) =>
      /\b(sudo|wheel|admin|root|domain admins|administrators)\b/i.test(e.raw_message ?? ''),
    );
    if (suspicious.length < this.definition.threshold!) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 75,
        summary: `Suspicious admin account activity: ${suspicious.length} account-management event(s) referencing admin privileges`,
        related_entities: entities(suspicious),
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}

/**
 * R011 — Suspicious PowerShell (T1059.001)
 *
 * Windows process-creation events (4688) whose command line shows PowerShell
 * combined with execution-obfuscation or download-and-execute patterns.
 *
 * Response gap: the spec calls for `kill_process` CONFIRM, but no such SOAR
 * playbook exists yet — this rule is alert-only until one is implemented.
 */
export class SuspiciousPowerShellRule implements DetectionRule {
  readonly id = 'R011';
  readonly name = 'Suspicious PowerShell Execution';
  readonly definition: RuleDefinition = {
    time_window_seconds: 900,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['windows_security', 'windows_process', 'windows'],
    actions: ['process_start', 'process_create', 'process_activity'],
  };

  private readonly powershellRe = /powershell|pwsh/i;
  private readonly suspiciousRe =
    /(-enc\b|encodedcommand|downloadstring|invoke-expression|\biex\b|frombase64string|bitsex|net\.webclient|invoke-download)/i;

  async detect(es: ElasticsearchService, since: Date): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
      1000,
    );

    const suspicious = events.filter((e) => {
      const raw = e.raw_message ?? '';
      return this.powershellRe.test(raw) && this.suspiciousRe.test(raw);
    });
    if (suspicious.length < this.definition.threshold!) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 85,
        summary: `Suspicious PowerShell: ${suspicious.length} process(es) with encoded/download-execute patterns`,
        related_entities: entities(suspicious),
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}

/**
 * R013 — Privilege Escalation (T1068)
 *
 * Interactive privilege transitions to root (sudo -i/-s, su, sudo su) from
 * authentication telemetry. Plain sudo command usage is R014's territory.
 * Response: isolate_endpoint CONFIRM.
 */
export class PrivilegeEscalationRule implements DetectionRule {
  readonly id = 'R013';
  readonly name = 'Privilege Escalation to Root';
  readonly definition: RuleDefinition = {
    time_window_seconds: 3600,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['linux_auth', 'linux', 'syslog'],
    actions: ['privilege_escalation', 'privilege_change', 'user_privilege'],
    trigger_playbook: 'isolate_endpoint',
    playbook_mode: 'CONFIRM',
  };

  private readonly rootShellRe =
    /(sudo\s+(-i|-s|su)\b|su\s+-?\s*root|sudo\s+su\b|sudoedit|doas\s+-u\s+root)/i;

  async detect(es: ElasticsearchService, since: Date): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
    );

    const suspicious = events.filter((e) => this.rootShellRe.test(e.raw_message ?? ''));
    if (suspicious.length < this.definition.threshold!) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'HIGH',
        confidence_score: 80,
        summary: `Privilege escalation: ${suspicious.length} interactive root-transition event(s) detected`,
        related_entities: entities(suspicious),
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}

/**
 * R014 — Sudo Abuse (T1548.003)
 *
 * Sudo usage running dangerous/destructive commands (recursive delete of /,
 * world-writable chmod, account changes, disk ops, shutdown). Alert-only.
 */
export class SudoAbuseRule implements DetectionRule {
  readonly id = 'R014';
  readonly name = 'Sudo Command Abuse';
  readonly definition: RuleDefinition = {
    time_window_seconds: 3600,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['linux_auth', 'linux', 'syslog'],
    actions: ['privilege_escalation', 'sudo', 'auth_event'],
  };

  private readonly dangerousRe =
    /(rm\s+-rf\s+\/|chmod\s+(-R\s+)?777|dd\s+if=|mkfs|shutdown|reboot|\/etc\/passwd|\/etc\/shadow)/i;

  async detect(es: ElasticsearchService, since: Date): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
    );

    const suspicious = events.filter((e) => this.dangerousRe.test(e.raw_message ?? ''));
    if (suspicious.length < this.definition.threshold!) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 70,
        summary: `Sudo abuse: ${suspicious.length} dangerous privileged command(s) executed via sudo`,
        related_entities: entities(suspicious),
        matching_events: suspicious.slice(0, 50).map(toPayload),
      },
    ];
  }
}

/**
 * R015 — Scheduled Task Persistence (T1053.003)
 *
 * Windows scheduled-task creation/modification events (4698/4702). Alert-only
 * (no response playbook exists for task removal yet).
 */
export class ScheduledTaskRule implements DetectionRule {
  readonly id = 'R015';
  readonly name = 'Scheduled Task Persistence';
  readonly definition: RuleDefinition = {
    time_window_seconds: 3600,
    interval_seconds: 300,
    threshold: 1,
    source_types: ['windows_security', 'windows_tasks', 'windows'],
    actions: ['scheduled_task', 'scheduled_task_created', 'scheduled_task_changed'],
  };

  async detect(es: ElasticsearchService, since: Date): Promise<DetectionResult[]> {
    const events = await fetchEvents(
      es,
      since,
      this.definition.source_types!,
      this.definition.actions!,
    );
    if (events.length < this.definition.threshold!) return [];

    return [
      {
        rule_id: this.id,
        rule_name: this.name,
        severity: 'WARNING',
        confidence_score: 70,
        summary: `Scheduled task persistence: ${events.length} task creation/modification event(s)`,
        related_entities: entities(events),
        matching_events: events.slice(0, 50).map(toPayload),
      },
    ];
  }
}
