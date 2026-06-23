import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class SoarService {
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
    return { execution_id: execution.id, status: execution.status };
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
