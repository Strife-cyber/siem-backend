import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class SoarService {
  private readonly logger = new Logger(SoarService.name);

  constructor(private readonly prisma: PrismaService) {}

  async executePlaybook(data: {
    incident_id: string;
    playbook_name: string;
    mode: 'AUTO' | 'CONFIRM';
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

    // Execute playbook actions
    await this.runPlaybook(data.playbook_name, data.incident_id);

    // Update status to EXECUTED
    await this.prisma.playbookExecution.update({
      where: { id: execution.id },
      data: { status: 'EXECUTED', executed_at: new Date() },
    });

    return { execution_id: execution.id, status: 'EXECUTED' };
  }

  private async runPlaybook(
    playbookName: string,
    incidentId: string,
  ): Promise<void> {
    switch (playbookName) {
      case 'block_ip': {
        const incident = await this.prisma.incident.findUnique({
          where: { id: incidentId },
          select: { related_entities: true },
        });
        const entities = incident?.related_entities as any;
        const ips: string[] = entities?.ips ?? [];
        this.logger.warn(`[SOAR] Blocking IPs: ${ips.join(', ')}`);
        break;
      }
      case 'disable_account': {
        const incident = await this.prisma.incident.findUnique({
          where: { id: incidentId },
          select: { related_entities: true },
        });
        const entities = incident?.related_entities as any;
        const users: string[] = entities?.users ?? [];
        this.logger.warn(`[SOAR] Disabling accounts: ${users.join(', ')}`);
        break;
      }
      case 'isolate_endpoint': {
        const incident = await this.prisma.incident.findUnique({
          where: { id: incidentId },
          select: { related_entities: true },
        });
        const entities = incident?.related_entities as any;
        const hosts: string[] = entities?.hosts ?? [];
        this.logger.warn(`[SOAR] Isolating endpoints: ${hosts.join(', ')}`);
        // In production: call firewall API, NAC, or cloud provider
        break;
      }
      case 'notify_teams': {
        this.logger.warn(
          `[SOAR] Notifying SOC team about incident ${incidentId}`,
        );
        break;
      }
      default:
        this.logger.warn(`[SOAR] Unknown playbook: ${playbookName}`);
    }
  }

  async abortPlaybook(executionId: string) {
    const execution = await this.prisma.playbookExecution.findUnique({
      where: { id: executionId },
    });
    if (!execution) throw new NotFoundException('Execution not found');
    await this.prisma.playbookExecution.update({
      where: { id: executionId },
      data: { status: 'ABORTED' },
    });
    return { status: 'aborted' };
  }
}
