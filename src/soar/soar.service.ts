import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PfSenseClientService } from './pfsense-client.service';
import { blockIpPlaybook } from './playbooks/block-ip.playbook';
import { isolateHostPlaybook } from './playbooks/isolate-host.playbook';
import { blockPortPlaybook } from './playbooks/block-port.playbook';
import { temporaryBlockPlaybook } from './playbooks/temporary-block.playbook';
import {
  createAliasPlaybook,
  deleteAliasPlaybook,
} from './playbooks/aliases.playbook';
import { checkIpPlaybook } from './playbooks/check-ip.playbook';

@Injectable()
export class SoarService {
  private readonly logger = new Logger(SoarService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly pfsense: PfSenseClientService,
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

    if (!this.pfsense.isConfigured) {
      this.logger.warn(
        `[SOAR] pfSense not configured (PFSENSE_API_KEY missing) — running ${playbookName} in dry-run mode`,
      );
    }

    switch (playbookName) {
      case 'block_ip': {
        if (ips.length === 0)
          return { skipped: true, reason: 'no IPs to block' };
        const result = await blockIpPlaybook(
          this.pfsense,
          ips,
          'Security incident detected',
          this.logger,
        );
        return result;
      }

      case 'isolate_endpoint': {
        if (hosts.length === 0)
          return { skipped: true, reason: 'no hosts to isolate' };
        const result = await isolateHostPlaybook(
          this.pfsense,
          hosts,
          'Suspicious host detected',
          this.logger,
        );
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
          this.pfsense,
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
          this.pfsense,
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
        const ruleId = params?.pfSenseRuleId as string;
        if (!ruleId) return { skipped: true, reason: 'no rule ID' };
        const result = await this.pfsense.unblockIP(ruleId);
        this.logger.warn(
          `[remove_rule] Deleted rule ${ruleId}: ${result.status}`,
        );
        return { ruleId, status: result.status };
      }

      case 'create_alias': {
        const name = (params?.name as string) ?? `siem-blocked-${Date.now()}`;
        if (ips.length === 0) return { skipped: true, reason: 'no IPs' };
        const aliasResult = await createAliasPlaybook(
          this.pfsense,
          name,
          ips,
          (params?.description as string) ?? 'Blocked by Smart SIEM',
          this.logger,
        );
        return aliasResult;
      }

      case 'delete_alias': {
        const aliasName = params?.name as string;
        if (!aliasName) return { skipped: true, reason: 'no alias name' };
        const delResult = await deleteAliasPlaybook(
          this.pfsense,
          aliasName,
          this.logger,
        );
        return delResult;
      }

      case 'check_ip': {
        const checkIp = (params?.ip as string) ?? ips[0];
        if (!checkIp) return { skipped: true, reason: 'no IP to check' };
        const checkResult = await checkIpPlaybook(
          this.pfsense,
          checkIp,
          this.logger,
        );
        return checkResult;
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

    // If it was a temporary block, try to remove the rule from pfSense
    const payload = execution.result_payload as Record<string, unknown> | null;
    const ruleId = payload?.pfSenseRuleId;
    if (typeof ruleId === 'string' && this.pfsense.isConfigured) {
      await this.pfsense.unblockIP(ruleId).catch(() => {});
    }

    await this.prisma.playbookExecution.update({
      where: { id: executionId },
      data: { status: 'ABORTED' },
    });
    return { status: 'aborted' };
  }
}
