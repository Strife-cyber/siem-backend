import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { MailService } from '../mail/mail.service';

@Processor('notifications', { concurrency: 3 })
export class NotificationsProcessor extends WorkerHost {
  private readonly logger = new Logger(NotificationsProcessor.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly mail: MailService,
  ) {
    super();
  }

  async process(job: Job): Promise<void> {
    switch (job.name) {
      case 'incident-alert':
        return this.handleIncidentAlert(job.data.incidentId);
      case 'daily-digest':
        return this.handleDailyDigest();
      default:
        this.logger.warn(`Unknown job type: ${job.name}`);
    }
  }

  private async handleIncidentAlert(incidentId: string): Promise<void> {
    try {
      const incident = await this.prisma.incident.findUnique({
        where: { id: incidentId },
        include: { rule: { select: { id: true, name: true } } },
      });
      if (!incident) {
        this.logger.warn(`[Notifications] Incident ${incidentId} not found`);
        return;
      }

      const entities = (incident.related_entities as any) ?? {};

      await this.mail.sendIncidentAlert({
        id: incident.id,
        severity: incident.severity,
        rule_id: incident.rule_id,
        rule_name: incident.rule?.name ?? undefined,
        summary: incident.summary,
        confidence_score: incident.confidence_score,
        triggered_at: incident.triggered_at,
        ips: entities.ips,
        hosts: entities.hosts,
        users: entities.users,
      });

      this.logger.log(`[Notifications] Alert sent for incident ${incidentId}`);
    } catch (err: any) {
      this.logger.error(`[Notifications] Failed to send alert: ${err.message}`);
    }
  }

  private async handleDailyDigest(): Promise<void> {
    try {
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const today = new Date();

      const incidents = await this.prisma.incident.findMany({
        where: { triggered_at: { gte: yesterday, lte: today } },
        include: { rule: { select: { name: true } } },
      });

      const counts: Record<string, number> = {};
      const ruleCounts: Record<string, number> = {};

      for (const inc of incidents) {
        counts[inc.severity] = (counts[inc.severity] ?? 0) + 1;
        const ruleName = inc.rule?.name ?? inc.rule_id ?? 'Unknown';
        ruleCounts[ruleName] = (ruleCounts[ruleName] ?? 0) + 1;
      }

      const topRules = Object.entries(ruleCounts)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      await this.mail.sendDailyDigest({
        date: yesterday.toISOString().split('T')[0],
        total: incidents.length,
        counts,
        topRules,
      });

      this.logger.log(`[Notifications] Daily digest sent: ${incidents.length} incidents`);
    } catch (err: any) {
      this.logger.error(`[Notifications] Daily digest failed: ${err.message}`);
    }
  }
}
