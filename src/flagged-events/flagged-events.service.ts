import {
  Injectable,
  Logger,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { FlagEventDto } from './dto/flag-event.dto';
import type { UpdateFlagDto } from './dto/update-flag.dto';
import type { ListFlagsDto } from './dto/list-flags.dto';

@Injectable()
export class FlaggedEventsService {
  private readonly logger = new Logger(FlaggedEventsService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Flag one or more events by ingestion_hash for cross-investigation.
   */
  async flag(
    dto: FlagEventDto,
    userId: string,
  ): Promise<{ id: string; ingestion_hash: string }> {
    const existing = await this.prisma.flaggedEvent.findUnique({
      where: { ingestion_hash: dto.ingestion_hash },
    });

    if (existing) {
      // Already flagged — update reason & snapshot instead of erroring
      const updated = await this.prisma.flaggedEvent.update({
        where: { id: existing.id },
        data: {
          reason: dto.reason ?? existing.reason,
          event_snapshot: (dto.event_snapshot ?? existing.event_snapshot) as any,
          status: 'OPEN',
        },
      });
      this.logger.log(`Re-flagged existing event ${dto.ingestion_hash}`);
      return { id: updated.id, ingestion_hash: updated.ingestion_hash };
    }

    const flagged = await this.prisma.flaggedEvent.create({
      data: {
        ingestion_hash: dto.ingestion_hash,
        user_id: userId,
        reason: dto.reason,
        event_snapshot: dto.event_snapshot as any,
      },
    });

    this.logger.log(`Flagged event ${flagged.ingestion_hash} (${flagged.id})`);
    return { id: flagged.id, ingestion_hash: flagged.ingestion_hash };
  }

  /**
   * Remove a flag by ingestion_hash.
   */
  async unflag(ingestionHash: string): Promise<void> {
    const existing = await this.prisma.flaggedEvent.findUnique({
      where: { ingestion_hash: ingestionHash },
    });

    if (!existing) {
      throw new NotFoundException(
        `No flag found for ingestion_hash: ${ingestionHash}`,
      );
    }

    await this.prisma.flaggedEvent.delete({ where: { id: existing.id } });
    this.logger.log(`Unflagged event ${ingestionHash}`);
  }

  /**
   * List flagged events with optional status / investigation / text filters.
   */
  async list(dto: ListFlagsDto) {
    const where: Record<string, any> = {};

    if (dto.status) {
      where.status = dto.status;
    }
    if (dto.investigation_id) {
      where.investigation_id = dto.investigation_id;
    }
    if (dto.q) {
      where.OR = [
        { reason: { contains: dto.q, mode: 'insensitive' } },
        { ingestion_hash: { contains: dto.q, mode: 'insensitive' } },
      ];
    }

    const [items, total] = await Promise.all([
      this.prisma.flaggedEvent.findMany({
        where,
        orderBy: { flagged_at: 'desc' },
        skip: dto.from ?? 0,
        take: dto.size ?? 50,
        include: {
          user: { select: { id: true, username: true } },
        },
      }),
      this.prisma.flaggedEvent.count({ where }),
    ]);

    return { total, items };
  }

  /**
   * Update a flag's status, reason, or investigation group.
   */
  async update(
    ingestionHash: string,
    dto: UpdateFlagDto,
  ): Promise<{ id: string; ingestion_hash: string }> {
    const existing = await this.prisma.flaggedEvent.findUnique({
      where: { ingestion_hash: ingestionHash },
    });

    if (!existing) {
      throw new NotFoundException(
        `No flag found for ingestion_hash: ${ingestionHash}`,
      );
    }

    const data: Record<string, any> = {};
    if (dto.reason !== undefined) data.reason = dto.reason;
    if (dto.status !== undefined) {
      data.status = dto.status;
      if (dto.status === 'RESOLVED' || dto.status === 'FALSE_POSITIVE') {
        data.resolved_at = new Date();
      }
    }
    if (dto.investigation_id !== undefined) {
      data.investigation_id = dto.investigation_id;
    }

    const updated = await this.prisma.flaggedEvent.update({
      where: { id: existing.id },
      data,
    });

    return { id: updated.id, ingestion_hash: updated.ingestion_hash };
  }

  /**
   * Link two flagged events together for cross-investigation.
   */
  async link(
    fromHash: string,
    toHash: string,
    userId: string,
  ): Promise<void> {
    const from = await this.prisma.flaggedEvent.findUnique({
      where: { ingestion_hash: fromHash },
    });
    const to = await this.prisma.flaggedEvent.findUnique({
      where: { ingestion_hash: toHash },
    });

    if (!from || !to) {
      throw new NotFoundException('One or both flagged events not found');
    }

    // Check for existing link
    const existing = await this.prisma.flaggedEventLink.findFirst({
      where: {
        OR: [
          { from_event_id: from.id, to_event_id: to.id },
          { from_event_id: to.id, to_event_id: from.id },
        ],
      },
    });

    if (existing) {
      throw new ConflictException('Events are already linked');
    }

    await this.prisma.flaggedEventLink.create({
      data: {
        from_event_id: from.id,
        to_event_id: to.id,
      },
    });

    this.logger.log(`Linked flagged events: ${fromHash} ↔ ${toHash}`);
  }
}
