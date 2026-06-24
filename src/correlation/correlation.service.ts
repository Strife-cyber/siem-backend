import { Injectable, Logger } from '@nestjs/common';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { PrismaService } from '../prisma/prisma.service';
import { SoarService } from '../soar/soar.service';
import { BruteForceRule } from './rules/r001-brute-force.rule';
import { PassTheHashRule } from './rules/r002-pass-the-hash.rule';
import { DataExfilRule } from './rules/r003-data-exfiltration.rule';
import { LogClearingRule } from './rules/r004-log-clearing.rule';
import type {
  DetectionRule,
  DetectionResult,
} from './interfaces/detection-rule.interface';

export interface CycleReport {
  cycleId: string;
  startedAt: string;
  elapsedMs: number;
  activeRuleCount: number;
  inactiveRuleCount: number;
  results: RuleResult[];
  totalIncidentsCreated: number;
}

export interface RuleResult {
  ruleId: string;
  ruleName: string;
  status: 'ran' | 'skipped_inactive' | 'error';
  esQueryTimeWindow: string;
  matchedEventCount?: number;
  incidentsCreated: number;
  error?: string;
}

@Injectable()
export class CorrelationService {
  private readonly logger = new Logger(CorrelationService.name);

  private readonly builtinRules: DetectionRule[] = [
    new BruteForceRule(),
    new PassTheHashRule(),
    new DataExfilRule(),
    new LogClearingRule(),
  ];

  /** Track when each rule last ran to avoid re-scanning old events */
  private readonly lastRunPerRule = new Map<string, Date>();

  constructor(
    private readonly es: ElasticsearchService,
    private readonly prisma: PrismaService,
    private readonly soar: SoarService,
  ) {}

  async runCycle(): Promise<CycleReport> {
    const cycleId = `cycle-${Date.now()}`;
    const startedAt = new Date().toISOString();
    const startTime = Date.now();
    const results: RuleResult[] = [];
    let totalIncidentsCreated = 0;

    const allDbRules = await this.prisma.correlationRule.findMany();
    const activeRuleIds = new Set(
      allDbRules.filter((r) => r.is_active).map((r) => r.id),
    );

    const activeInDb = allDbRules.filter((r) => r.is_active).length;
    const totalInDb = allDbRules.length;

    this.logger.log(
      `=== Cycle ${cycleId} === Active rules in DB: ${activeInDb}/${totalInDb}`,
    );

    if (totalInDb === 0) {
      this.logger.warn(
        'No rules found in database. Run the seed script first (npm run seed:rules).',
      );
    }

    if (activeInDb === 0) {
      this.logger.warn(
        'All rules are inactive. Activate via PATCH /api/v1/rules/{id} with {"is_active": true}.',
      );
    }

    for (const dbRule of allDbRules) {
      this.logger.log(
        `  [${dbRule.is_active ? 'ACTIVE' : 'INACTIVE'}] ${dbRule.id} - ${dbRule.name}`,
      );
    }

    for (const rule of this.builtinRules) {
      if (!activeRuleIds.has(rule.id)) {
        results.push({
          ruleId: rule.id,
          ruleName: rule.name,
          status: 'skipped_inactive',
          esQueryTimeWindow: `${rule.definition.time_window_seconds}s`,
          incidentsCreated: 0,
        });
        continue;
      }

      const ruleResult: RuleResult = {
        ruleId: rule.id,
        ruleName: rule.name,
        status: 'ran',
        esQueryTimeWindow: `${rule.definition.time_window_seconds}s`,
        incidentsCreated: 0,
      };

      try {
        // Only scan events since this rule last ran
        const since = this.lastRunPerRule.get(rule.id) ?? new Date(0);
        this.logger.log(
          `[SEARCH] Running ${rule.id} - ${rule.name} (since ${since.toISOString().slice(11, 19)})`,
        );

        const ruleStart = Date.now();
        const detectionResults = await rule.detect(this.es, since);
        this.lastRunPerRule.set(rule.id, new Date());
        const queryTime = Date.now() - ruleStart;

        let matchedCount = 0;
        try {
          const countResult = await this.es
            .getClient()
            .count({
              index: 'ctu-logs',
              query: {
                bool: {
                  filter: [
                    ...(rule.definition.source_types
                      ? [
                          {
                            terms: {
                              source_type: rule.definition.source_types,
                            },
                          },
                        ]
                      : []),
                    ...(rule.definition.actions
                      ? [{ terms: { action: rule.definition.actions } }]
                      : []),
                    ...(rule.definition.outcomes
                      ? [{ terms: { outcome: rule.definition.outcomes } }]
                      : []),
                    {
                      range: {
                        collected_at: {
                          gte: new Date(
                            Date.now() -
                              rule.definition.time_window_seconds * 1000,
                          ).toISOString(),
                        },
                      },
                    },
                  ],
                },
              },
            })
            .then((r: any) => r);
          matchedCount = countResult.count ?? 0;
        } catch {
          // Count query is best-effort
        }

        ruleResult.matchedEventCount = matchedCount;

        this.logger.log(
          `  [DATA] ${rule.id}: scanned ${matchedCount} matching events in ${queryTime}ms -> ${detectionResults.length} detection(s)`,
        );

        if (detectionResults.length === 0 && matchedCount > 0) {
          this.logger.log(
            `  [OK] ${rule.id}: ${matchedCount} events checked, none exceeded threshold (${rule.definition.threshold})`,
          );
        }

        if (detectionResults.length === 0 && matchedCount === 0) {
          this.logger.log(
            `  [SLEEP] ${rule.id}: no matching events found in the last ${rule.definition.time_window_seconds}s window`,
          );
        }

        for (const result of detectionResults) {
          await this.handleDetection(result);
          ruleResult.incidentsCreated++;
          totalIncidentsCreated++;
        }

        if (detectionResults.length > 0) {
          this.logger.warn(
            `  [ALERT] ${rule.id}: ${detectionResults.length} incident(s) created!`,
          );
          for (const det of detectionResults) {
            this.logger.warn(
              `     -> ${det.severity}: ${det.summary} [confidence: ${det.confidence_score}]`,
            );
          }
        }
      } catch (error: any) {
        ruleResult.status = 'error';
        ruleResult.error = error.message ?? String(error);
        this.logger.error(
          `  [FAIL] ${rule.id} failed: ${error.message ?? error}`,
        );
      }

      results.push(ruleResult);
    }

    const elapsed = Date.now() - startTime;

    const report: CycleReport = {
      cycleId,
      startedAt,
      elapsedMs: elapsed,
      activeRuleCount: activeInDb,
      inactiveRuleCount: totalInDb - activeInDb,
      results,
      totalIncidentsCreated,
    };

    this.logger.log('=== Cycle Summary ===');
    this.logger.log(`  Duration: ${elapsed}ms`);
    this.logger.log(`  Active rules: ${activeInDb}`);
    this.logger.log(`  Incidents created: ${totalIncidentsCreated}`);
    if (results.some((r) => r.status === 'error')) {
      this.logger.warn(
        `  Errors: ${results.filter((r) => r.status === 'error').length} rule(s) failed`,
      );
    }
    this.logger.log('====================');

    return report;
  }

  private async handleDetection(result: DetectionResult): Promise<void> {
    try {
      const duplicate = await this.findRecentDuplicate(result);
      if (duplicate) {
        this.logger.log(
          `  [SKIP] Duplicate for ${result.rule_id}: same rule already fired in last 5min`,
        );
        return;
      }

      const incident = await this.prisma.incident.create({
        data: {
          rule_id: result.rule_id,
          severity: result.severity as any,
          confidence_score: result.confidence_score,
          summary: result.summary,
          related_entities: JSON.parse(JSON.stringify(result.related_entities)),
          status: 'OPEN',
        },
      });

      this.logger.warn(
        `  [NEW] Incident ${incident.id}: ${result.severity} - ${result.summary}`,
      );

      const rule = this.builtinRules.find((r) => r.id === result.rule_id);
      if (rule?.definition.trigger_playbook) {
        this.logger.log(
          `  [SOAR] Triggering playbook "${rule.definition.trigger_playbook}" for incident ${incident.id}`,
        );
        await this.soar
          .executePlaybook({
            incident_id: incident.id,
            playbook_name: rule.definition.trigger_playbook,
            mode: rule.definition.playbook_mode ?? 'CONFIRM',
          })
          .catch((err) => {
            this.logger.error(
              `  [FAIL] SOAR trigger failed for ${incident.id}: ${err.message}`,
            );
          });
      }
    } catch (error: any) {
      this.logger.error(
        `  [FAIL] Failed to handle detection: ${error.message ?? error}`,
      );
    }
  }

  private async findRecentDuplicate(result: DetectionResult): Promise<boolean> {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
    const targetHost = result.related_entities.hosts?.[0];
    const targetIp = result.related_entities.ips?.[0];

    const recent = await this.prisma.incident.findFirst({
      where: {
        rule_id: result.rule_id,
        triggered_at: { gte: fiveMinAgo },
      },
      orderBy: { triggered_at: 'desc' },
    });

    if (!recent) return false;

    // Also dedup by hostname if present
    if (targetHost && recent.related_entities) {
      const recentEntities = recent.related_entities as any;
      if (
        Array.isArray(recentEntities.hosts) &&
        recentEntities.hosts.includes(targetHost)
      ) {
        return true;
      }
    }

    // Dedup by IP if present
    if (targetIp && recent.related_entities) {
      const recentEntities = recent.related_entities as any;
      if (
        Array.isArray(recentEntities.ips) &&
        recentEntities.ips.includes(targetIp)
      ) {
        return true;
      }
    }

    return false;
  }
}
