import {
  Controller,
  Get,
  Param,
  Query,
  NotFoundException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
} from '@nestjs/swagger';
import { PrismaService } from '../prisma/prisma.service';

export const RISK_BANDS = [
  { name: 'Informational', min: 0, max: 19 },
  { name: 'Low', min: 20, max: 39 },
  { name: 'Medium', min: 40, max: 59 },
  { name: 'High', min: 60, max: 79 },
  { name: 'Critical', min: 80, max: 100 },
] as const;

export function riskBand(score: number): string {
  return (
    RISK_BANDS.find((b) => score >= b.min && score <= b.max)?.name ??
    'Informational'
  );
}

@ApiTags('Entities')
@ApiBearerAuth('BearerAuth')
@Controller('entities')
export class EntitiesController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  @ApiOperation({ summary: 'List entities, highest risk first' })
  @ApiQuery({ name: 'type', required: false })
  @ApiQuery({
    name: 'q',
    required: false,
    description: 'Substring match on value',
  })
  @ApiQuery({ name: 'min_risk', required: false, type: Number })
  async list(
    @Query('type') type?: string,
    @Query('q') q?: string,
    @Query('min_risk') minRisk?: string,
  ) {
    const entities = await this.prisma.entity.findMany({
      where: {
        ...(type ? { entity_type: type.toUpperCase() } : {}),
        ...(q ? { value: { contains: q, mode: 'insensitive' } } : {}),
        ...(minRisk ? { risk_score: { gte: Number(minRisk) } } : {}),
      },
      orderBy: [{ risk_score: 'desc' }, { last_seen_at: 'desc' }],
      take: 200,
    });
    return entities.map((e) => ({ ...e, risk_band: riskBand(e.risk_score) }));
  }

  @Get('leaderboard')
  @ApiOperation({ summary: 'Top entities by risk score' })
  async leaderboard() {
    const entities = await this.prisma.entity.findMany({
      orderBy: { risk_score: 'desc' },
      take: 20,
    });
    return entities.map((e, i) => ({
      rank: i + 1,
      id: e.id,
      entity_type: e.entity_type,
      value: e.value,
      risk_score: e.risk_score,
      risk_band: riskBand(e.risk_score),
      observation_count: e.observation_count,
      last_seen_at: e.last_seen_at,
    }));
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Entity detail with relationships and recent risk events',
  })
  async detail(@Param('id') id: string) {
    const entity = await this.prisma.entity.findUnique({
      where: { id },
      include: {
        edges_out: {
          include: { target: true },
          orderBy: { last_seen_at: 'desc' },
          take: 50,
        },
        edges_in: {
          include: { source: true },
          orderBy: { last_seen_at: 'desc' },
          take: 50,
        },
        risk_events: { orderBy: { observed_at: 'desc' }, take: 25 },
      },
    });
    if (!entity) throw new NotFoundException('Entity not found');
    return { ...entity, risk_band: riskBand(entity.risk_score) };
  }

  @Get(':id/risk')
  @ApiOperation({ summary: 'Risk score history and band for an entity' })
  async risk(@Param('id') id: string) {
    const entity = await this.prisma.entity.findUnique({
      where: { id },
      include: { risk_events: { orderBy: { observed_at: 'desc' }, take: 100 } },
    });
    if (!entity) throw new NotFoundException('Entity not found');
    return {
      entity_id: entity.id,
      entity_type: entity.entity_type,
      value: entity.value,
      risk_score: entity.risk_score,
      risk_band: riskBand(entity.risk_score),
      risk_updated_at: entity.risk_updated_at,
      events: entity.risk_events,
    };
  }
}
