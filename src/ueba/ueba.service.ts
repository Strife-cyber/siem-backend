import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UebaService {
  constructor(private readonly prisma: PrismaService) {}

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
}
