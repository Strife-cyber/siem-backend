import {
  Injectable,
  NotFoundException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole } from '../../generated/prisma/enums';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  listUsers() {
    return this.prisma.user.findMany({
      select: {
        id: true,
        username: true,
        role: true,
        is_active: true,
        created_at: true,
        last_login: true,
      },
      orderBy: { created_at: 'desc' },
    });
  }

  async createUser(
    data: { username: string; password: string; role: string },
    actingUserId: string,
  ) {
    const existing = await this.prisma.user.findUnique({
      where: { username: data.username },
    });
    if (existing) throw new ConflictException('Username already exists');
    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(data.password, salt);
    const user = await this.prisma.user.create({
      data: {
        username: data.username,
        password_hash,
        role: data.role as UserRole,
      },
      select: {
        id: true,
        username: true,
        role: true,
        is_active: true,
        created_at: true,
      },
    });

    // Audit: log user creation by admin
    await this.audit.log({
      userId: actingUserId,
      action: 'USER_CREATED',
      metadata: { target_user: user.id, target_username: user.username, role: user.role },
    });

    return user;
  }

  async updateUser(
    id: string,
    data: { role?: string; is_active?: boolean },
    actingUserId: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');

    const updated = await this.prisma.user.update({
      where: { id },
      data: data as any,
      select: { id: true, username: true, role: true, is_active: true },
    });

    // Audit: log role/status changes
    const changes: Record<string, unknown> = {};
    if (data.role && data.role !== user.role) {
      changes.old_role = user.role;
      changes.new_role = data.role;
    }
    if (data.is_active !== undefined && data.is_active !== user.is_active) {
      changes.old_active = user.is_active;
      changes.new_active = data.is_active;
    }
    if (Object.keys(changes).length > 0) {
      await this.audit.log({
        userId: actingUserId,
        action: 'USER_UPDATED',
        metadata: { target_user: id, target_username: user.username, ...changes },
      });
    }

    return updated;
  }

  async deleteUser(id: string, actingUserId: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    await this.prisma.user.update({
      where: { id },
      data: { is_active: false },
    });

    // Audit: log user deactivation
    await this.audit.log({
      userId: actingUserId,
      action: 'USER_DEACTIVATED',
      metadata: { target_user: id, target_username: user.username },
    });
  }

  getRetentionPolicies() {
    return this.prisma.retentionPolicy.findMany({ orderBy: { id: 'asc' } });
  }

  async updateRetentionPolicy(data: {
    policy_id: number;
    duration_days: number;
  }) {
    const policy = await this.prisma.retentionPolicy.findUnique({
      where: { id: data.policy_id },
    });
    if (!policy) throw new NotFoundException('Retention policy not found');
    return this.prisma.retentionPolicy.update({
      where: { id: data.policy_id },
      data: { duration_days: data.duration_days },
    });
  }
}
