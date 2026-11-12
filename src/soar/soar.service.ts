import {
  BadRequestException,
  Injectable,
  Logger,
  Inject,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '../../generated/prisma/client';
import { ExecutionStatus, PlaybookMode } from '../../generated/prisma/enums';
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

/** Sentinel incident id for direct firewall actions that have no incident. */
const NO_INCIDENT = '00000000-0000-0000-0000-000000000000';

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

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
        status: ExecutionStatus.PENDING,
        // Persist params so a later CONFIRM approval replays the same input
        result_payload: data.params
          ? ({ params: data.params } as Prisma.InputJsonValue)
          : undefined,
      },
    });

    // ── CONFIRM mode: pause and wait for analyst approval ──
    if (data.mode === 'CONFIRM') {
      this.logger.warn(
        `[SOAR] ${data.playbook_name} PENDING analyst approval (execution: ${execution.id})`,
      );
      return { execution_id: execution.id, status: 'PENDING', mode: 'CONFIRM' };
    }

    // ── AUTO mode: execute immediately ──
    return this.runAndRecord(
      execution.id,
      data.playbook_name,
      data.incident_id,
      data.params,
    );
  }

  /**
   * Runs a playbook and persists the outcome on the execution row.
   * The returned status always reflects what actually happened:
   * EXECUTED on success, FAILED on error or unknown playbook.
   */
  private async runAndRecord(
    executionId: string,
    playbookName: string,
    incidentId: string,
    params?: Record<string, unknown>,
  ): Promise<{ execution_id: string; status: ExecutionStatus }> {
    try {
      const resultPayload = await this.runPlaybook(
        playbookName,
        incidentId,
        params,
        executionId,
      );

      const failed = typeof resultPayload.error === 'string';
      const status = failed ? ExecutionStatus.FAILED : ExecutionStatus.EXECUTED;

      await this.prisma.playbookExecution.update({
        where: { id: executionId },
        data: {
          status,
          executed_at: new Date(),
          result_payload: resultPayload as Prisma.InputJsonValue,
        },
      });

      if (failed) {
        this.logger.error(
          `[SOAR] ${playbookName} FAILED: ${errorMessage(resultPayload.error)}`,
        );
      } else {
        this.logger.log(
          `[SOAR] ${playbookName} executed (${executionId}): ${JSON.stringify(resultPayload)}`,
        );
      }

      return { execution_id: executionId, status };
    } catch (err) {
      const message = errorMessage(err);
      try {
        await this.prisma.playbookExecution.update({
          where: { id: executionId },
          data: {
            status: ExecutionStatus.FAILED,
            executed_at: new Date(),
            result_payload: { error: message },
          },
        });
      } catch (updateErr) {
        this.logger.error(
          `[SOAR] Could not persist FAILED status for execution ${executionId}: ${errorMessage(updateErr)}`,
        );
      }
      this.logger.error(`[SOAR] ${playbookName} FAILED: ${message}`);
      return { execution_id: executionId, status: ExecutionStatus.FAILED };
    }
  }

  private async runPlaybook(
    playbookName: string,
    incidentId: string,
    params?: Record<string, unknown>,
    executionId?: string,
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
        // Record each blocked IP as a SoarAction
        for (const ip of result.blocked) {
          await this.recordAction(
            incidentId,
            executionId,
            'block_ip',
            ip,
            result,
          ).catch((err) =>
            this.logger.warn(
              `[SOAR] Failed to record block_ip action for ${ip}: ${errorMessage(err)}`,
            ),
          );
        }
        // Auto-resolve incident if IPs were blocked
        if (result.blocked.length > 0) {
          await this.autoResolveIncident(incidentId, playbookName).catch(
            (err) =>
              this.logger.warn(
                `[SOAR] Failed to auto-resolve incident ${incidentId}: ${errorMessage(err)}`,
              ),
          );
        }
        return result;
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
        for (const host of result.isolated) {
          await this.recordAction(
            incidentId,
            executionId,
            'isolate_host',
            host,
            result,
          ).catch((err) =>
            this.logger.warn(
              `[SOAR] Failed to record isolate_host action for ${host}: ${errorMessage(err)}`,
            ),
          );
        }
        if (result.isolated.length > 0) {
          await this.autoResolveIncident(incidentId, playbookName).catch(
            (err) =>
              this.logger.warn(
                `[SOAR] Failed to auto-resolve incident ${incidentId}: ${errorMessage(err)}`,
              ),
          );
        }
        return result;
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
        return result;
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
        return result;
      }

      case 'remove_rule': {
        // Support both new (ip-based) and legacy (pfSenseRuleId) params
        const ip = params?.ip as string | undefined;
        const legacyRuleId = params?.pfSenseRuleId as string | undefined;

        if (ip) {
          // New path: unblock by IP (provider-agnostic)
          const result = await this.agent.unblockIp(ip);
          this.logger.warn(`[remove_rule] Unblocked IP ${ip}`);
          return { ip, status: 'ok', ...result };
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
        const name = (params?.name as string) ?? `siem-blocked-${Date.now()}`;
        if (ips.length === 0) return { skipped: true, reason: 'no IPs' };
        const pfsense = this.agent as unknown as PfSenseAgentService;
        const aliasResult = await createAliasPlaybook(
          pfsense,
          name,
          ips,
          (params?.description as string) ?? 'Blocked by Smart SIEM',
          this.logger,
        );
        return aliasResult;
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
        return delResult;
      }

      case 'check_ip': {
        const checkIp = (params?.ip as string) ?? ips[0];
        if (!checkIp) return { skipped: true, reason: 'no IP to check' };
        const checkResult = await checkIpPlaybook(
          this.agent,
          checkIp,
          this.logger,
        );
        return { blocked: checkResult.blocked, rules: checkResult.rules };
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
      select: { related_entities: true },
    });
    return (
      (incident?.related_entities as {
        ips?: string[];
        hosts?: string[];
        users?: string[];
      } | null) ?? null
    );
  }

  // ══════════════════════════════════════════════════
  //  SoarAction tracking
  // ══════════════════════════════════════════════════

  /**
   * Record a SOAR action in the database for audit and undo.
   */
  private async recordAction(
    incidentId: string,
    executionId: string | undefined,
    actionType: string,
    target: string,
    resultPayload: Record<string, unknown>,
  ): Promise<void> {
    await this.prisma.soarAction.create({
      data: {
        incident_id: incidentId,
        execution_id: executionId ?? null,
        action_type: actionType,
        target,
        status: 'EXECUTED',
        provider: this.agent.provider,
        description: `Action: ${actionType} on ${target}`,
        result_payload: resultPayload as Prisma.InputJsonValue,
      },
    });
  }

  /**
   * Auto-resolve the incident if the playbook succeeded.
   */
  private async autoResolveIncident(
    incidentId: string,
    playbookName: string,
  ): Promise<void> {
    try {
      await this.prisma.incident.update({
        where: { id: incidentId },
        data: {
          status: 'RESOLVED',
          resolved_at: new Date(),
        },
      });
      this.logger.log(
        `[SOAR] Auto-resolved incident ${incidentId} after ${playbookName} executed`,
      );
    } catch (err: any) {
      this.logger.warn(
        `[SOAR] Failed to auto-resolve incident ${incidentId}: ${errorMessage(err)}`,
      );
    }
  }

  /**
   * List all SOAR actions, with optional filter by incident.
   */
  async listActions(incidentId?: string) {
    return this.prisma.soarAction.findMany({
      where: incidentId ? { incident_id: incidentId } : undefined,
      orderBy: { created_at: 'desc' },
      take: incidentId ? undefined : 100,
    });
  }

  /**
   * Undo a SOAR action: reverse the firewall operation.
   */
  async undoAction(actionId: string): Promise<Record<string, unknown>> {
    const act = await this.prisma.soarAction.findUnique({
      where: { id: actionId },
    });

    if (!act) {
      throw new NotFoundException('SOAR action not found');
    }

    if (act.status === 'REVERTED') {
      return { error: 'Action already reverted', action_id: actionId };
    }

    let reverseResult: Record<string, unknown> = {};

    try {
      switch (act.action_type) {
        case 'block_ip':
          reverseResult = await this.agent.unblockIp(act.target);
          break;
        case 'isolate_host':
          reverseResult = await this.agent.unIsolateHost(act.target);
          break;
        default:
          return { error: `Cannot undo action type: ${act.action_type}` };
      }

      await this.prisma.soarAction.update({
        where: { id: actionId },
        data: { status: 'REVERTED', reverted_at: new Date() },
      });

      this.logger.warn(
        `[SOAR] Undid action ${actionId}: ${act.action_type} on ${act.target}`,
      );

      return {
        action_id: actionId,
        action_type: act.action_type,
        target: act.target,
        status: 'REVERTED',
        reverse_result: reverseResult,
      };
    } catch (err) {
      return { error: errorMessage(err), action_id: actionId };
    }
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
      await this.agent
        .unblockIp(ip)
        .catch((err) =>
          this.logger.warn(
            `[SOAR] Failed to unblock ${ip} while aborting ${executionId}: ${errorMessage(err)}`,
          ),
        );
    } else {
      // Legacy format (pfSense-specific rule ID)
      const legacyRuleId = payload?.pfSenseRuleId as string | undefined;
      if (
        typeof legacyRuleId === 'string' &&
        this.agent.provider === 'pfsense'
      ) {
        const pfsense = this.agent as unknown as PfSenseAgentService;
        await pfsense
          .unblockIP_deprecated(legacyRuleId)
          .catch((err) =>
            this.logger.warn(
              `[SOAR] Failed to delete legacy rule ${legacyRuleId} while aborting ${executionId}: ${errorMessage(err)}`,
            ),
          );
      }
    }

    await this.prisma.playbookExecution.update({
      where: { id: executionId },
      data: { status: ExecutionStatus.ABORTED },
    });
    return { status: 'aborted' };
  }

  // ══════════════════════════════════════════════════
  //  CONFIRM mode — analyst approval workflow
  // ══════════════════════════════════════════════════

  /** List all PENDING playbook executions awaiting analyst approval */
  async getPendingExecutions() {
    return this.prisma.playbookExecution.findMany({
      where: { status: ExecutionStatus.PENDING, mode: PlaybookMode.CONFIRM },
      include: {
        incident: {
          select: {
            id: true,
            severity: true,
            summary: true,
            triggered_at: true,
          },
        },
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
    if (execution.status !== ExecutionStatus.PENDING) {
      throw new BadRequestException(
        `Execution ${executionId} is ${execution.status}, not PENDING`,
      );
    }
    if (execution.mode !== PlaybookMode.CONFIRM) {
      throw new BadRequestException(
        `Execution ${executionId} is in ${execution.mode} mode, not CONFIRM`,
      );
    }

    // Params are persisted at creation time (see executePlaybook)
    const payload = execution.result_payload as {
      params?: Record<string, unknown>;
    } | null;

    return this.runAndRecord(
      executionId,
      execution.playbook_name,
      execution.incident_id,
      payload?.params,
    );
  }

  // ══════════════════════════════════════════════════
  //  Direct firewall actions (provider-agnostic)
  // ══════════════════════════════════════════════════

  async directBlockIp(ip: string, reason?: string) {
    return blockIpPlaybook(
      this.agent,
      [ip],
      reason ?? 'Manual block',
      this.logger,
    );
  }

  async directBlockPort(
    ip: string,
    port: number,
    protocol: 'tcp' | 'udp',
    reason?: string,
  ) {
    return blockPortPlaybook(
      this.agent,
      [{ ip, port, protocol }],
      reason ?? 'Manual port block',
      this.logger,
    );
  }

  async directTemporaryBlock(ip: string, ttlSeconds: number, reason?: string) {
    return temporaryBlockPlaybook(
      this.agent,
      undefined,
      [ip],
      reason ?? 'Temporary manual block',
      ttlSeconds,
      NO_INCIDENT,
      this.logger,
    );
  }

  async checkIp(ip: string) {
    return checkIpPlaybook(this.agent, ip, this.logger);
  }

  async unblockIp(ip: string) {
    return this.agent.unblockIp(ip);
  }

  async listFirewallRules() {
    return this.agent.listRules();
  }

  async deleteFirewallRule(name: string) {
    return this.agent.deleteRule(name);
  }

  async firewallHealth() {
    return this.agent.healthCheck();
  }

  async createAlias(name: string, addresses: string[], description?: string) {
    this.ensurePfSense('create aliases');
    const pfsense = this.agent as unknown as PfSenseAgentService;
    return createAliasPlaybook(
      pfsense,
      name,
      addresses,
      description ?? 'Smart SIEM alias',
      this.logger,
    );
  }

  async deleteAlias(id: string) {
    this.ensurePfSense('delete aliases');
    const pfsense = this.agent as unknown as PfSenseAgentService;
    return deleteAliasPlaybook(pfsense, id, this.logger);
  }

  async listAliases() {
    this.ensurePfSense('list aliases');
    const pfsense = this.agent as unknown as PfSenseAgentService;
    const result = await pfsense.listAliases();
    return result.data ?? [];
  }

  private ensurePfSense(operation: string): void {
    if (this.agent.provider !== 'pfsense') {
      throw new BadRequestException(
        `Cannot ${operation}: this operation requires the pfSense firewall provider. ` +
          `Current provider: ${this.agent.provider}. ` +
          `Set SOAR_FIREWALL_PROVIDER=pfsense in your environment.`,
      );
    }
  }
}
