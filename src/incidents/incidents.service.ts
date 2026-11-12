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

    const events = await this.prisma.incidentEvent.findMany({
      where: { incident_id: id },
      orderBy: { collected_at: 'desc' },
      take: 200,
      select: {
        id: true,
        es_id: true,
        collected_at: true,
        source_ip: true,
        destination_ip: true,
        hostname: true,
        user_principal: true,
        action: true,
        outcome: true,
        source_type: true,
        raw_message: true,
      },
    });

    // Audit: log incident consultation
    if (actingUserId) {
      await this.audit.log({
        userId: actingUserId,
        action: 'INCIDENT_VIEWED',
        metadata: { incident_id: id, severity: incident.severity },
      });
    }

    return { ...incident, incident_events: events };
  }

  /**
   * Forensic timeline: correlated log events, SOAR actions and entity
   * observations for one incident, merged and sorted chronologically.
   */
  async getTimeline(id: string) {
    const incident = await this.prisma.incident.findUnique({ where: { id } });
    if (!incident) throw new NotFoundException('Incident not found');

    const [logEvents, soarActions, observations, riskEvents] =
      await Promise.all([
        this.prisma.incidentEvent.findMany({
          where: { incident_id: id },
          orderBy: { collected_at: 'asc' },
          take: 500,
          select: {
            id: true,
            collected_at: true,
            source_ip: true,
            destination_ip: true,
            hostname: true,
            user_principal: true,
            action: true,
            outcome: true,
            source_type: true,
          },
        }),
        this.prisma.soarAction.findMany({
          where: { incident_id: id },
          orderBy: { created_at: 'asc' },
        }),
        this.prisma.entityObservation.findMany({
          where: { incident_id: id },
          orderBy: { observed_at: 'asc' },
          take: 200,
          include: { entity: { select: { entity_type: true, value: true } } },
        }),
        this.prisma.entityRiskEvent.findMany({
          where: { incident_id: id },
          orderBy: { observed_at: 'asc' },
          include: { entity: { select: { entity_type: true, value: true } } },
        }),
      ]);

    const events = [
      ...logEvents.map((e) => ({
        type: 'log',
        at: e.collected_at,
        data: e,
      })),
      ...soarActions.map((a) => ({
        type: 'soar',
        at: a.created_at,
        data: a,
      })),
      ...observations.map((o) => ({
        type: 'entity_observation',
        at: o.observed_at,
        data: o,
      })),
      ...riskEvents.map((r) => ({
        type: 'risk',
        at: r.observed_at,
        data: r,
      })),
    ].sort((a, b) => a.at.getTime() - b.at.getTime());

    return {
      incident: {
        id: incident.id,
        rule_id: incident.rule_id,
        severity: incident.severity,
        status: incident.status,
        triggered_at: incident.triggered_at,
        summary: incident.summary,
      },
      events,
    };
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
