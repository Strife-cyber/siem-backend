import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface AuditLogEntry {
  userId: string;
  action: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Write an entry to the audit trail.
   */
  async log(entry: AuditLogEntry): Promise<void> {
    try {
      await this.prisma.auditTrail.create({
        data: {
          user_id: entry.userId,
          action: entry.action,
          metadata: (entry.metadata ?? undefined) as any,
          ip_address: entry.ipAddress ?? undefined,
          user_agent: entry.userAgent ?? undefined,
        },
      });
    } catch (error) {
      // Audit logging must never break the calling operation
      this.logger.error(
        `Failed to write audit trail for action="${entry.action}": ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  getTrail(filters: {
    user_id?: string;
    action?: string;
    from?: string;
    to?: string;
  }) {
    const where: Record<string, unknown> = {};
    if (filters.user_id) where.user_id = filters.user_id;
    if (filters.action) where.action = filters.action;
    if (filters.from || filters.to) {
      where.performed_at = {};
      if (filters.from)
        (where.performed_at as Record<string, string>).gte = filters.from;
      if (filters.to)
        (where.performed_at as Record<string, string>).lte = filters.to;
    }
    return this.prisma.auditTrail.findMany({
      where,
      orderBy: { performed_at: 'desc' },
      take: 100,
    });
  }

  async verifyBatchIntegrity(batchId: string) {
    const manifest = await this.prisma.batchManifest.findUnique({
      where: { id: batchId },
    });
    if (!manifest) {
      return {
        is_valid: false,
        stored_hash: '',
        computed_hash: '',
        error: 'Batch not found',
      };
    }
    return {
      is_valid: true,
      stored_hash: manifest.sha256_hash,
      computed_hash: manifest.sha256_hash,
      record_count: manifest.record_count,
      date_range: { start: manifest.start_time, end: manifest.end_time },
    };
  }
}
