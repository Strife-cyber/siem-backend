import { Injectable } from '@nestjs/common';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class DashboardService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly elasticsearch: ElasticsearchService,
  ) {}

  async getStats() {
    const [openIncidents, criticalAlerts, highAlerts] = await Promise.all([
      this.prisma.incident.count({ where: { status: 'OPEN' } }),
      this.prisma.incident.count({
        where: {
          severity: 'CRITICAL',
          status: { in: ['OPEN', 'IN_PROGRESS'] },
        },
      }),
      this.prisma.incident.count({
        where: { severity: 'HIGH', status: { in: ['OPEN', 'IN_PROGRESS'] } },
      }),
    ]);

    return {
      critical_alerts: criticalAlerts,
      high_alerts: highAlerts,
      open_incidents: openIncidents,
      logs_per_hour: 0,
      top_attackers: [],
      system_status: 'OK' as const,
    };
  }
}
