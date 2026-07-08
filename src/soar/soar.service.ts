import {
  Injectable,
  Logger,
  Inject,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { FIREWALL_AGENT } from './agents/firewall-agent.interface';
import type { IFirewallAgent } from './agents/firewall-agent.interface';
import { blockIpPlaybook } from './playbooks/block-ip.playbook';
import { isolateHostPlaybook } from './playbooks/isolate-host.playbook';
import { blockPortPlaybook } from './playbooks/block-port.playbook';
import { temporaryBlockPlaybook } from './playbooks/temporary-block.playbook';
import {
  createAliasPlaybook,
  deleteAliasPlaybook,
} from './playbooks/aliases.playbook';
import { checkIpPlaybook } from './playbooks/check-ip.playbook';
import { PfSenseAgentService } from './agents/pfsense-agent.service';

@Injectable()
export class SoarService {
  private readonly logger = new Logger(SoarService.name);

  constructor(
    private readonly prisma: PrismaService,
    @Inject(FIREWALL_AGENT) private readonly agent: IFirewallAgent,
  ) {}

  async executePlaybook(data: {
    incident_id: string;
    playbook_name: string;
    mode: 'AUTO' | 'CONFIRM';
    params?: Record<string, unknown>;
  }) {
    const incident = await this.prisma.incident.findUnique({
      where: { id: data.incident_id },
    });
    if (!incident) throw new NotFoundException('Incident not found');

    const execution = await this.prisma.playbookExecution.create({
      data: {
        incident_id: data.incident_id,
        playbook_name: data.playbook_name,
        mode: data.mode,
        status: 'PENDING',
      } as any,
    });

    // ── CONFIRM mode: pause and wait for analyst approval ──
    if (data.mode === 'CONFIRM') {
      this.logger.warn(
        `[SOAR] ${data.playbook_name} PENDING analyst approval (execution: ${execution.id})`,
      );
      return { execution_id: execution.id, status: 'PENDING', mode: 'CONFIRM' };
    }

    // ── AUTO mode: execute immediately ──
    let resultPayload: Record<string, unknown> = {};

    try {
      resultPayload = await this.runPlaybook(
        data.playbook_name,
        data.incident_id,
        data.params,
      );

      await this.prisma.playbookExecution.update({
        where: { id: execution.id },
        data: {
          status: 'EXECUTED',
          executed_at: new Date(),
          result_payload: resultPayload as any,
        },
      });

      this.logger.log(
        `[SOAR] ${data.playbook_name} executed (${execution.id}): ${JSON.stringify(resultPayload)}`,
      );
    } catch (err: any) {
      await this.prisma.playbookExecution.update({
        where: { id: execution.id },
        data: {
          status: 'FAILED',
          executed_at: new Date(),
          result_payload: { error: err.message } as any,
        },
      });
      this.logger.error(`[SOAR] ${data.playbook_name} FAILED: ${err.message}`);
    }

    return { execution_id: execution.id, status: 'EXECUTED' };
  }

  private async runPlaybook(
    playbookName: string,
    incidentId: string,
    params?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const entities = await this.getIncidentEntities(incidentId);
    const ips: string[] = entities?.ips ?? [];
    const hosts: string[] = entities?.hosts ?? [];
    const users: string[] = entities?.users ?? [];

    if (!this.agent.isConfigured) {
      this.logger.warn(
        `[SOAR] Firewall agent not configured — running ${playbookName} in dry-run mode`,
      );
    }

    switch (playbookName) {
      case 'block_ip': {
        if (ips.length === 0)
          return { skipped: true, reason: 'no IPs to block' };
        const result = await blockIpPlaybook(
          this.agent,
          ips,
          'Security incident detected',
          this.logger,
        );
        return result as any;
      }

      case 'isolate_endpoint': {
        if (hosts.length === 0)
          return { skipped: true, reason: 'no hosts to isolate' };
        const result = await isolateHostPlaybook(
          this.agent,
          hosts,
          'Suspicious host detected',
          this.logger,
        );
        return result as any;
      }

      case 'disable_account': {
        this.logger.warn(
          `[disable_account] Disabling accounts: ${users.join(', ')}`,
        );
        // In production: call AD/LDAP API here
        return { disabled: users };
      }

      case 'block_port': {
        const targetIp = (params?.ip as string) ?? ips[0];
        const port = Number(params?.port ?? '3389');
        const protocol = (params?.protocol as 'tcp' | 'udp') ?? 'tcp';
        if (!targetIp) return { skipped: true, reason: 'no target IP' };
        const result = await blockPortPlaybook(
          this.agent,
          [{ ip: targetIp, port, protocol }],
          (params?.reason as string) ?? 'Attack detected on port',
          this.logger,
        );
        return result as any;
      }

      case 'temporary_block': {
        const ttl = Number(params?.ttl_seconds ?? '1800');
        if (ips.length === 0)
          return { skipped: true, reason: 'no IPs to block' };
        const result = await temporaryBlockPlaybook(
          this.agent,
          this.prisma,
          ips,
          (params?.reason as string) ?? 'Temporary block',
          ttl,
          incidentId,
          this.logger,
        );
        return result as any;
      }

      case 'remove_rule': {
        // Support both new (ip-based) and legacy (pfSenseRuleId) params
        const ip = params?.ip as string | undefined;
        const legacyRuleId = params?.pfSenseRuleId as string | undefined;

        if (ip) {
          // New path: unblock by IP (provider-agnostic)
          const result = await this.agent.unblockIp(ip);
          this.logger.warn(`[remove_rule] Unblocked IP ${ip}`);
          return { ip, status: 'ok', ...result } as any;
        }

        if (legacyRuleId && this.agent.provider === 'pfsense') {
          // Legacy path: delete by pfSense rule ID
          const pfsense = this.agent as unknown as PfSenseAgentService;
          const result = await pfsense.unblockIP_deprecated(legacyRuleId);
          this.logger.warn(
            `[remove_rule] Deleted legacy rule ${legacyRuleId}: ${result.status}`,
          );
          return { ruleId: legacyRuleId, status: result.status };
        }

        return {
          skipped: true,
          reason: 'no IP or rule ID provided for removal',
        };
      }

      case 'create_alias': {
        if (this.agent.provider !== 'pfsense') {
          return {
            skipped: true,
            reason: 'Aliases require the pfSense firewall provider',
          };
        }
        const name =
          (params?.name as string) ?? `siem-blocked-${Date.now()}`;
        if (ips.length === 0) return { skipped: true, reason: 'no IPs' };
        const pfsense = this.agent as unknown as PfSenseAgentService;
        const aliasResult = await createAliasPlaybook(
          pfsense,
          name,
          ips,
          (params?.description as string) ?? 'Blocked by Smart SIEM',
          this.logger,
        );
        return aliasResult as any;
      }

      case 'delete_alias': {
        if (this.agent.provider !== 'pfsense') {
          return {
            skipped: true,
            reason: 'Aliases require the pfSense firewall provider',
          };
        }
        const aliasName = params?.name as string;
        if (!aliasName) return { skipped: true, reason: 'no alias name' };
        const pfsense = this.agent as unknown as PfSenseAgentService;
        const delResult = await deleteAliasPlaybook(
          pfsense,
          aliasName,
          this.logger,
        );
        return delResult as any;
      }

      case 'check_ip': {
        const checkIp = (params?.ip as string) ?? ips[0];
        if (!checkIp) return { skipped: true, reason: 'no IP to check' };
        const checkResult = await checkIpPlaybook(
          this.agent,
          checkIp,
          this.logger,
        );
        return checkResult as any;
      }

      case 'notify_teams': {
        this.logger.warn(`[notify_teams] SOC alert for incident ${incidentId}`);
        // In production: send Slack/email/PagerDuty
        return { notified: true };
      }

      default:
        this.logger.warn(`[SOAR] Unknown playbook: ${playbookName}`);
        return { error: `Unknown playbook: ${playbookName}` };
    }
  }

  private async getIncidentEntities(incidentId: string): Promise<{
    ips?: string[];
    hosts?: string[];
    users?: string[];
  } | null> {
    const incident = await this.prisma.incident.findUnique({
      where: { id: incidentId },
      select: { related_entities: true, summary: true },
    });
    return (incident?.related_entities as any) ?? null;
  }

  async abortPlaybook(executionId: string) {
    const execution = await this.prisma.playbookExecution.findUnique({
      where: { id: executionId },
    });
    if (!execution) throw new NotFoundException('Execution not found');

    const payload = execution.result_payload as Record<string, unknown> | null;

    // Try new format (ip-based)
    const ip = payload?.ip as string | undefined;
    if (typeof ip === 'string' && this.agent.isConfigured) {
      await this.agent.unblockIp(ip).catch(() => {});
    } else {
      // Legacy format (pfSense-specific rule ID)
      const legacyRuleId = payload?.pfSenseRuleId as string | undefined;
      if (
        typeof legacyRuleId === 'string' &&
        this.agent.provider === 'pfsense'
      ) {
        const pfsense = this.agent as unknown as PfSenseAgentService;
        await pfsense.unblockIP_deprecated(legacyRuleId).catch(() => {});
      }
    }

    await this.prisma.playbookExecution.update({
      where: { id: executionId },
      data: { status: 'ABORTED' },
    });
    return { status: 'aborted' };
  }

  // ══════════════════════════════════════════════════
  //  CONFIRM mode — analyst approval workflow
  // ══════════════════════════════════════════════════

  /** List all PENDING playbook executions awaiting analyst approval */
  async getPendingExecutions() {
    return this.prisma.playbookExecution.findMany({
      where: { status: 'PENDING', mode: 'CONFIRM' },
      include: {
        incident: { select: { id: true, severity: true, summary: true, triggered_at: true } },
      },
      orderBy: { initiated_at: 'desc' },
    });
  }

  /**
   * Approve a pending CONFIRM-mode execution and run the playbook.
   * Rejects with 404 if not found, 400 if not in PENDING/CONFIRM state.
   */
  async approveExecution(executionId: string) {
    const execution = await this.prisma.playbookExecution.findUnique({
      where: { id: executionId },
    });
    if (!execution) throw new NotFoundException('Execution not found');
    if (execution.status !== 'PENDING') {
      throw new NotFoundException(
        `Execution ${executionId} is ${execution.status}, not PENDING`,
      );
    }
    if (execution.mode !== 'CONFIRM') {
      throw new NotFoundException(
        `Execution ${executionId} is in ${execution.mode} mode, not CONFIRM`,
      );
    }

    const payload = execution.result_payload as Record<string, unknown> | undefined;

    let resultPayload: Record<string, unknown> = {};

    try {
      resultPayload = await this.runPlaybook(
        execution.playbook_name,
        execution.incident_id,
        payload?.params as Record<string, unknown> | undefined,
      );

      await this.prisma.playbookExecution.update({
        where: { id: executionId },
        data: {
          status: 'EXECUTED',
          executed_at: new Date(),
          result_payload: resultPayload as any,
        },
      });

      this.logger.warn(
        `[SOAR] CONFIRM approved — ${execution.playbook_name} executed (${executionId})`,
      );
    } catch (err: any) {
      await this.prisma.playbookExecution.update({
        where: { id: executionId },
        data: {
          status: 'FAILED',
          executed_at: new Date(),
          result_payload: { error: err.message } as any,
        },
      });
      this.logger.error(
        `[SOAR] CONFIRM approved — ${execution.playbook_name} FAILED: ${err.message}`,
      );
    }

    return { execution_id: executionId, status: 'EXECUTED' };
  }
}
