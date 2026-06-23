import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class IncidentsService {
  constructor(private readonly prisma: PrismaService) {}

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

  async findOne(id: string) {
    const incident = await this.prisma.incident.findUnique({
      where: { id },
      include: {
        rule: true,
        assigned_user: { select: { id: true, username: true } },
        playbook_executions: true,
      },
    });
    if (!incident) throw new NotFoundException('Incident not found');
    return incident;
  }

  async update(
    id: string,
    data: { status?: string; summary?: string; assigned_to?: string },
  ) {
    const incident = await this.prisma.incident.findUnique({ where: { id } });
    if (!incident) throw new NotFoundException('Incident not found');
    const updateData: Record<string, unknown> = { ...data };
    if (data.status === 'RESOLVED' || data.status === 'FALSE_POSITIVE') {
      updateData.resolved_at = new Date();
    }
    return this.prisma.incident.update({
      where: { id },
      data: updateData as any,
    });
  }
}
