import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UebaBaselineService } from './ueba-baseline.service';

@Injectable()
export class UebaService {
  private readonly logger = new Logger(UebaService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly baselineService: UebaBaselineService,
  ) {}

  findAll(minRisk?: number, maxRisk?: number) {
    const where: Record<string, unknown> = {};
    if (minRisk !== undefined || maxRisk !== undefined) {
      where.risk_score = {};
      if (minRisk !== undefined)
        (where.risk_score as Record<string, number>).gte = minRisk;
      if (maxRisk !== undefined)
        (where.risk_score as Record<string, number>).lte = maxRisk;
    }
    return this.prisma.uebaProfile.findMany({
      where,
      orderBy: { risk_score: 'desc' },
    });
  }

  async findOne(userPrincipal: string) {
    const profile = await this.prisma.uebaProfile.findUnique({
      where: { user_principal: userPrincipal },
    });
    if (!profile) throw new NotFoundException('UEBA profile not found');
    return profile;
  }

  /**
   * Get UEBA system-wide statistics for the Crisis Room dashboard.
   */
  async getStats() {
    const [totalUsers, highRiskUsers, avgRisk, totalAnomalies] =
      await Promise.all([
        this.prisma.uebaProfile.count(),
        this.prisma.uebaProfile.count({
          where: { risk_score: { gte: 70 } },
        }),
        this.prisma.uebaProfile.aggregate({
          _avg: { risk_score: true },
        }),
        this.prisma.uebaProfile.aggregate({
          _sum: { anomaly_count: true },
        }),
      ]);

    return {
      total_users: totalUsers,
      high_risk_users: highRiskUsers,
      average_risk_score: Math.round((avgRisk._avg?.risk_score ?? 0) * 10) / 10,
      total_anomalies: totalAnomalies._sum?.anomaly_count ?? 0,
    };
  }

  /**
   * Manually trigger baseline rebuild for all users.
   * Called via API endpoint.
   */
  async triggerBaselineRebuild(): Promise<{ usersProcessed: number }> {
    this.logger.log('Manual baseline rebuild triggered');
    return this.baselineService.buildAllBaselines();
  }

  /**
   * Nightly baseline rebuild runs via BullMQ job scheduler (2:00 AM).
   * Handled in UebaProcessor.handleRebuildBaselines().
   */
}
