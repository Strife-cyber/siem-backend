import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole } from '../../generated/prisma/enums';

@Injectable()
export class AdminService {
  constructor(private readonly prisma: PrismaService) {}

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

  async createUser(data: { username: string; password: string; role: string }) {
    const existing = await this.prisma.user.findUnique({
      where: { username: data.username },
    });
    if (existing) throw new ConflictException('Username already exists');
    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(data.password, salt);
    return this.prisma.user.create({
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
  }

  async updateUser(id: string, data: { role?: string; is_active?: boolean }) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.user.update({
      where: { id },
      data: data as any,
      select: { id: true, username: true, role: true, is_active: true },
    });
  }

  async deleteUser(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    await this.prisma.user.update({
      where: { id },
      data: { is_active: false },
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
