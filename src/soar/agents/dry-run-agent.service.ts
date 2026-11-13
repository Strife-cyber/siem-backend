import { Injectable, Logger } from '@nestjs/common';
import type {
  CheckIpResponse,
  FirewallActionResponse,
  FirewallAuditMeta,
  FirewallHealth,
  IFirewallAgent,
} from './firewall-agent.interface';

/**
 * In-memory firewall agent used by the attack-simulation harness.
 *
 * It never touches a real firewall: every action succeeds and is recorded
 * in memory so `checkIp` / `listRules` stay consistent within one process.
 * This lets simulation scenarios prove the full detection → correlation →
 * incident → SOAR orchestration without requiring the live pfSense /
 * Windows Defender lab to be up.
 *
 * Select with `SOAR_FIREWALL_PROVIDER=dry_run` (see docker-compose.simulation.yml).
 */
@Injectable()
export class DryRunAgentService implements IFirewallAgent {
  private readonly logger = new Logger(DryRunAgentService.name);

  readonly provider = 'dry_run';
  readonly isConfigured = true;

  private readonly blockedIps = new Set<string>();
  private readonly isolatedIps = new Set<string>();
  private readonly blockedPorts = new Map<
    string,
    { port: number; protocol: string }
  >();
  private readonly rules = new Map<string, FirewallActionResponse>();

  private respond(
    actionRequested: string,
    actionApplied: string,
    scope: string,
    effect: string,
    audit?: FirewallAuditMeta,
    extra: Record<string, unknown> = {},
  ): FirewallActionResponse {
    const response: FirewallActionResponse = {
      provider: this.provider,
      action_requested: actionRequested,
      action_applied: actionApplied,
      scope,
      effect,
      limitations: ['dry-run: no real firewall was modified'],
      audit: audit ?? {},
      success: true,
      ...extra,
    };
    this.logger.log(
      `[dry-run] ${actionApplied}: ${JSON.stringify(extra)} (incident=${audit?.incident_id ?? 'n/a'})`,
    );
    return response;
  }

  async blockIp(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    this.blockedIps.add(ip);
    const name = `siem-block-${ip}`;
    const response = this.respond(
      'block_ip',
      'block_ip',
      'dry_run_memory',
      `IP ${ip} would be blocked (${reason ?? 'no reason'})`,
      audit,
      { ip, rule_name: name },
    );
    this.rules.set(name, response);
    return response;
  }

  async blockPort(
    ip: string,
    port: number,
    protocol: 'tcp' | 'udp',
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    const key = `${ip}:${port}/${protocol}`;
    this.blockedPorts.set(key, { port, protocol });
    return this.respond(
      'block_port',
      'block_port',
      'dry_run_memory',
      `Port ${port}/${protocol} from ${ip} would be blocked (${reason ?? 'no reason'})`,
      audit,
      { ip, port, protocol },
    );
  }

  async isolateHost(
    ip: string,
    reason?: string,
    audit?: FirewallAuditMeta,
  ): Promise<FirewallActionResponse> {
    this.isolatedIps.add(ip);
    return this.respond(
      'isolate_endpoint',
      'isolate_host',
      'dry_run_memory',
      `Host ${ip} would be isolated (${reason ?? 'no reason'})`,
      audit,
      { ip },
    );
  }

  async checkIp(ip: string): Promise<CheckIpResponse> {
    return {
      blocked: this.blockedIps.has(ip) || this.isolatedIps.has(ip),
      rules: [...this.rules.values()],
    };
  }

  async unblockIp(ip: string): Promise<FirewallActionResponse> {
    this.blockedIps.delete(ip);
    return this.respond(
      'remove_rule',
      'unblock_ip',
      'dry_run_memory',
      `IP ${ip} unblocked`,
      undefined,
      { ip },
    );
  }

  async unIsolateHost(
    ip: string,
    _reason?: string,
  ): Promise<FirewallActionResponse> {
    this.isolatedIps.delete(ip);
    return this.respond(
      'un_isolate',
      'un_isolate_host',
      'dry_run_memory',
      `Host ${ip} released from isolation`,
      undefined,
      { ip },
    );
  }

  async listRules(): Promise<FirewallActionResponse> {
    return this.respond(
      'list_rules',
      'list_rules',
      'dry_run_memory',
      `${this.rules.size} dry-run rule(s)`,
      undefined,
      {
        rules: [...this.rules.keys()],
      },
    );
  }

  async deleteRule(name: string): Promise<FirewallActionResponse> {
    this.rules.delete(name);
    return this.respond(
      'delete_rule',
      'delete_rule',
      'dry_run_memory',
      `Rule ${name} deleted`,
      undefined,
      { name },
    );
  }

  async healthCheck(): Promise<FirewallHealth> {
    return {
      provider: this.provider,
      configured: true,
      reachable: true,
      version: 'dry-run-1.0.0',
    };
  }
}
