import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { PrismaService } from '../prisma/prisma.service';

@ApiTags('MITRE')
@ApiBearerAuth('BearerAuth')
@Controller('mitre')
export class MitreController {
  constructor(private readonly prisma: PrismaService) {}

  @Get('coverage')
  @ApiOperation({
    summary: 'MITRE ATT&CK coverage: techniques, tactics, detection counts',
  })
  async coverage() {
    const rules = await this.prisma.correlationRule.findMany({
      include: { _count: { select: { incidents: true } } },
      orderBy: { id: 'asc' },
    });

    const techniques = new Map<
      string,
      {
        technique: string;
        tactic: string | null;
        rules: {
          rule_id: string;
          name: string;
          layer: number;
          incidents: number;
          is_active: boolean;
        }[];
        total_incidents: number;
      }
    >();

    for (const rule of rules) {
      const definition = (rule.definition ?? {}) as { layer?: number };
      const technique = rule.technique ?? 'Unmapped';
      const entry = techniques.get(technique) ?? {
        technique,
        tactic: rule.tactic,
        rules: [],
        total_incidents: 0,
      };
      entry.rules.push({
        rule_id: rule.id,
        name: rule.name,
        layer: definition.layer ?? 1,
        incidents: rule._count.incidents,
        is_active: rule.is_active,
      });
      entry.total_incidents += rule._count.incidents;
      techniques.set(technique, entry);
    }

    return {
      generated_at: new Date().toISOString(),
      technique_count: techniques.size,
      techniques: [...techniques.values()].sort(
        (a, b) => b.total_incidents - a.total_incidents,
      ),
    };
  }
}
