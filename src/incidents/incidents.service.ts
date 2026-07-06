import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class IncidentsService {
  private readonly logger = new Logger(IncidentsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  findAll(filters: {
    status?: string;
    severity?: string;
    from?: string;
    to?: string;
  }) {
    const where: Record<string, unknown> = {};
    if (filters.status) where.status = filters.status;
    if (filters.severity) where.severity = filters.severity;
    if (filters.from || filters.to) {
      where.triggered_at = {};
      if (filters.from)
        (where.triggered_at as Record<string, string>).gte = filters.from;
      if (filters.to)
        (where.triggered_at as Record<string, string>).lte = filters.to;
    }
    return this.prisma.incident.findMany({
      where,
      orderBy: { triggered_at: 'desc' },
      include: { rule: { select: { id: true, name: true } } },
    });
  }

  async findOne(id: string, actingUserId?: string) {
    const incident = await this.prisma.incident.findUnique({
      where: { id },
      include: {
        rule: true,
        assigned_user: { select: { id: true, username: true } },
        playbook_executions: true,
      },
    });
    if (!incident) throw new NotFoundException('Incident not found');

    // Audit: log incident consultation
    if (actingUserId) {
      await this.audit.log({
        userId: actingUserId,
        action: 'INCIDENT_VIEWED',
        metadata: { incident_id: id, severity: incident.severity },
      });
    }

    return incident;
  }

  async update(
    id: string,
    data: { status?: string; summary?: string; assigned_to?: string },
    actingUserId?: string,
  ) {
    const incident = await this.prisma.incident.findUnique({ where: { id } });
    if (!incident) throw new NotFoundException('Incident not found');
    const updateData: Record<string, unknown> = { ...data };
    if (data.status === 'RESOLVED' || data.status === 'FALSE_POSITIVE') {
      updateData.resolved_at = new Date();
    }
    const updated = await this.prisma.incident.update({
      where: { id },
      data: updateData as any,
    });

    // Audit: log incident processing
    if (actingUserId) {
      const metadata: Record<string, unknown> = { incident_id: id };
      if (data.status && data.status !== incident.status) {
        metadata.old_status = incident.status;
        metadata.new_status = data.status;
      }
      await this.audit.log({
        userId: actingUserId,
        action: 'INCIDENT_UPDATED',
        metadata,
      });
    }

    return updated;
  }
}
