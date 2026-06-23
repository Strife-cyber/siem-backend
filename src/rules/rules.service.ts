import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class RulesService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll() {
    return this.prisma.correlationRule.findMany({
      orderBy: { created_at: 'desc' },
    });
  }

  async findOne(id: string) {
    const rule = await this.prisma.correlationRule.findUnique({
      where: { id },
    });
    if (!rule) throw new NotFoundException('Rule not found');
    return rule;
  }

  async create(data: {
    id: string;
    name: string;
    tactic?: string;
    technique?: string;
    definition: any;
    confidence_weight?: number;
    is_active?: boolean;
  }) {
    const existing = await this.prisma.correlationRule.findUnique({
      where: { id: data.id },
    });
    if (existing) throw new ConflictException('Rule ID already exists');
    return this.prisma.correlationRule.create({
      data: { ...data, definition: data.definition } as any,
    });
  }

  async update(
    id: string,
    data: {
      name?: string;
      tactic?: string;
      technique?: string;
      definition?: any;
      confidence_weight?: number;
      is_active?: boolean;
    },
  ) {
    await this.findOne(id);
    return this.prisma.correlationRule.update({
      where: { id },
      data: data as any,
    });
  }

  async remove(id: string) {
    await this.findOne(id);
    await this.prisma.correlationRule.delete({ where: { id } });
  }
}
