import { Injectable, Logger } from '@nestjs/common';
import { Queue } from 'bullmq';
import { InjectQueue } from '@nestjs/bullmq';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { PrismaService } from '../prisma/prisma.service';
import { SoarService } from '../soar/soar.service';
import { BruteForceRule } from './rules/r001-brute-force.rule';
import { PassTheHashRule } from './rules/r002-pass-the-hash.rule';
import { DataExfilRule } from './rules/r003-data-exfiltration.rule';
import { LogClearingRule } from './rules/r004-log-clearing.rule';
import { ReconnaissanceRule } from './rules/r005-reconnaissance.rule';
import { SuccessfulLoginAfterFailuresRule } from './rules/r008-successful-login-after-failures.rule';
import { ATTACK_CORRELATION_RULES } from './rules/attack-correlation.rules';
import type {
  DetectionRule,
  DetectionResult,
} from './interfaces/detection-rule.interface';
import type { AttackCorrelationResult } from './interfaces/attack-correlation.interface';
import { EntityGraphService } from '../entities/entity-graph.service';
import { RiskScoringService } from '../entities/risk-scoring.service';

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
    new ReconnaissanceRule(),
    new SuccessfulLoginAfterFailuresRule(),
  ];

  /** Layer-2 attack correlation rules (C001–C003) — run after event rules */
  private readonly attackRules = ATTACK_CORRELATION_RULES;

  /** Track when each rule last ran to avoid re-scanning old events */
  private readonly lastRunPerRule = new Map<string, Date>();
  private readonly lastRunPerAttackRule = new Map<string, Date>();

  constructor(
    private readonly es: ElasticsearchService,
    private readonly prisma: PrismaService,
    private readonly soar: SoarService,
    @InjectQueue('notifications') private readonly notificationsQueue: Queue,
    @InjectQueue('logs') private readonly logsQueue: Queue,
    @InjectQueue('ueba') private readonly uebaQueue: Queue,
    @InjectQueue('reports') private readonly reportsQueue: Queue,
    private readonly entityGraph: EntityGraphService,
    private readonly riskScoring: RiskScoringService,
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
                        normalized_at: {
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

    // ── Layer 2: attack correlation rules (consume incidents from Layer 1) ──
    for (const rule of this.attackRules) {
      if (!activeRuleIds.has(rule.id)) continue;

      const attackResult: RuleResult = {
        ruleId: rule.id,
        ruleName: rule.name,
        status: 'ran',
        esQueryTimeWindow: 'incident-history',
        incidentsCreated: 0,
      };

      try {
        const since = this.lastRunPerAttackRule.get(rule.id) ?? new Date(0);
        this.logger.log(
          `[CORRELATE] Running ${rule.id} - ${rule.name} (since ${since.toISOString().slice(11, 19)})`,
        );

        const detections = await rule.detect(this.prisma, since);
        this.lastRunPerAttackRule.set(rule.id, new Date());

        this.logger.log(
          `  [DATA] ${rule.id}: ${detections.length} correlation(s) found`,
        );

        for (const det of detections) {
          await this.handleAttackDetection(det);
          attackResult.incidentsCreated++;
          totalIncidentsCreated++;
        }

        if (detections.length > 0) {
          this.logger.warn(
            `  [ALERT] ${rule.id}: ${detections.length} correlation incident(s) created!`,
          );
          for (const det of detections) {
            this.logger.warn(`     -> ${det.severity}: ${det.summary}`);
          }
        }
      } catch (error: any) {
        attackResult.status = 'error';
        attackResult.error = error.message ?? String(error);
        this.logger.error(
          `  [FAIL] ${rule.id} failed: ${error.message ?? error}`,
        );
      }

      results.push(attackResult);
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

    // Queue stats
    try {
      const [lW, lA, lD, lF, lC] = await Promise.all([
        this.logsQueue.getWaitingCount(),
        this.logsQueue.getActiveCount(),
        this.logsQueue.getDelayedCount(),
        this.logsQueue.getFailedCount(),
        this.logsQueue.getCompletedCount(),
      ]);
      const [nW, uW, rD] = await Promise.all([
        this.notificationsQueue.getWaitingCount(),
        this.uebaQueue.getWaitingCount(),
        this.reportsQueue.getDelayedCount(),
      ]);
      this.logger.log(
        `  [QUEUES] logs(w:${lW} a:${lA} d:${lD} f:${lF} ✓:${lC}) | notifs:${nW} | ueba:${uW} | reports:${rD}`,
      );
    } catch {
      /* non-critical */
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

      // Fetch and store the individual log events that caused this detection
      const rule = this.builtinRules.find((r) => r.id === result.rule_id);
      await this.storeMatchingEvents(incident.id, result, rule?.definition);

      // TDIR Phase 1: entity graph + decaying risk scoring
      await this.recordEntitiesAndRisk(incident.id, result);

      this.logger.warn(
        `  [NEW] Incident ${incident.id}: ${result.severity} - ${result.summary}`,
      );

      // Queue email notification (non-blocking)
      this.notificationsQueue
        .add('incident-alert', { incidentId: incident.id })
        .catch(() => {});

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

  /** Entity graph nodes/edges + rule-deduplicated decaying risk score. */
  private async recordEntitiesAndRisk(
    incidentId: string,
    result: DetectionResult,
  ): Promise<void> {
    try {
      const entityIds = await this.entityGraph.recordDetection(
        result,
        incidentId,
      );
      const observedAt = new Date();
      for (const entityId of entityIds) {
        await this.riskScoring.applyDetection(
          entityId,
          result.rule_id,
          incidentId,
          result.severity,
          observedAt,
        );
      }
      await this.entityGraph.recordEdges(incidentId, result.rule_id);
    } catch (error: any) {
      // Non-blocking: graph/risk failure must not lose the incident
      this.logger.warn(
        `  [GRAPH] Entity/risk recording failed for ${incidentId}: ${error.message ?? error}`,
      );
    }
  }

  /** Handle a Layer-2 attack correlation detection (C001–C010). */
  private async handleAttackDetection(
    result: AttackCorrelationResult,
  ): Promise<void> {
    try {
      const duplicate = await this.findRecentDuplicate(result);
      if (duplicate) {
        this.logger.log(
          `  [SKIP] Duplicate for ${result.rule_id}: correlation already fired in last 5min`,
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

      // Store the prerequisite incidents as correlation evidence
      const prereqs = await this.prisma.incident.findMany({
        where: { id: { in: result.prerequisite_incident_ids } },
        select: {
          id: true,
          rule_id: true,
          triggered_at: true,
          related_entities: true,
        },
      });
      for (const p of prereqs) {
        const ent = (p.related_entities ?? {}) as {
          ips?: string[];
          users?: string[];
          hosts?: string[];
        };
        await this.prisma.incidentEvent
          .create({
            data: {
              incident_id: incident.id,
              collected_at: p.triggered_at,
              source_ip: ent.ips?.[0] ?? null,
              hostname: ent.hosts?.[0] ?? null,
              user_principal: ent.users?.[0] ?? null,
              action: 'CORRELATION',
              outcome: p.rule_id ?? null,
              raw_message: `Prerequisite incident ${p.id} (${p.rule_id})`,
            },
          })
          .catch((err) =>
            this.logger.warn(
              `  [EVENTS] Failed to store correlation evidence: ${err.message}`,
            ),
          );
      }

      this.logger.warn(
        `  [NEW] Correlation incident ${incident.id}: ${result.severity} - ${result.summary}`,
      );

      this.notificationsQueue
        .add('incident-alert', { incidentId: incident.id })
        .catch(() => {});

      // Entity graph + risk for the correlation itself
      await this.recordEntitiesAndRisk(incident.id, result);

      if (result.response) {
        this.logger.log(
          `  [SOAR] Triggering playbook "${result.response.playbook}" (${result.response.mode}) for incident ${incident.id}`,
        );
        await this.soar
          .executePlaybook({
            incident_id: incident.id,
            playbook_name: result.response.playbook,
            mode: result.response.mode,
          })
          .catch((err) => {
            this.logger.error(
              `  [FAIL] SOAR trigger failed for ${incident.id}: ${err.message}`,
            );
          });
      }
    } catch (error: any) {
      this.logger.error(
        `  [FAIL] Failed to handle attack detection: ${error.message ?? error}`,
      );
    }
  }

  /**
   * Fetch individual log events from ES that caused this detection and
   * store them as incident_events so analysts can see the raw evidence.
   */
  private async storeMatchingEvents(
    incidentId: string,
    result: DetectionResult,
    definition?: import('./interfaces/detection-rule.interface').RuleDefinition,
  ): Promise<void> {
    try {
      const events = result.matching_events?.length
        ? result.matching_events
        : await this.fetchMatchingEventsFromEs(result, definition);

      if (events.length === 0) {
        this.logger.log(
          `  [EVENTS] No matching events to store for incident ${incidentId}`,
        );
        return;
      }

      // collected_at is NOT NULL — skip events without a timestamp
      const storable = events.filter((e) => e.collected_at);
      let stored = 0;
      for (const e of storable) {
        try {
          await this.prisma.incidentEvent.create({
            data: {
              incident_id: incidentId,
              es_id: e.es_id ?? null,
              collected_at: new Date(e.collected_at),
              source_ip: e.source_ip ?? null,
              destination_ip: e.destination_ip ?? null,
              hostname: e.hostname ?? null,
              user_principal: e.user_principal ?? null,
              action: e.action ?? null,
              outcome: e.outcome ?? null,
              source_type: e.source_type ?? null,
              raw_message: e.raw_message ?? null,
            },
          });
          stored += 1;
        } catch (err) {
          this.logger.warn(
            `  [EVENTS] Failed to store event ${e.es_id ?? '(no es_id)'} for incident ${incidentId}: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }

      this.logger.log(
        `  [EVENTS] Stored ${stored}/${events.length} matching event(s) for incident ${incidentId}`,
      );
    } catch (error: any) {
      // Non-blocking: event storage failure shouldn't prevent incident creation
      this.logger.warn(
        `  [EVENTS] Failed to store matching events for ${incidentId}: ${error.message ?? error}`,
      );
    }
  }

  /**
   * Build an ES query using the rule definition + detection context
   * to fetch the individual log events that triggered the incident.
   */
  private async fetchMatchingEventsFromEs(
    result: DetectionResult,
    definition?: import('./interfaces/detection-rule.interface').RuleDefinition,
  ): Promise<
    import('./interfaces/detection-rule.interface').IncidentEventPayload[]
  > {
    if (!definition) return [];

    const filter: Record<string, unknown>[] = [];

    // Rule-level filters
    if (definition.source_types?.length) {
      filter.push({ terms: { source_type: definition.source_types } });
    }
    if (definition.actions?.length) {
      filter.push({ terms: { action: definition.actions } });
    }
    if (definition.outcomes?.length) {
      filter.push({ terms: { outcome: definition.outcomes } });
    }

    // Detection-specific entity filters
    if (result.related_entities.ips?.length) {
      filter.push({ terms: { source_ip: result.related_entities.ips } });
    }
    if (result.related_entities.hosts?.length) {
      filter.push({ terms: { hostname: result.related_entities.hosts } });
    }
    if (result.related_entities.users?.length) {
      filter.push({ terms: { user_principal: result.related_entities.users } });
    }

    // Time window — use normalized_at with a larger buffer (5min) to account for processing delays
    filter.push({
      range: {
        normalized_at: {
          gte: new Date(
            Date.now() - Math.max(definition.time_window_seconds, 300) * 1000,
          ).toISOString(),
        },
      },
    });

    const esResult = await this.es
      .getClient()
      .search({
        index: 'ctu-logs',
        size: 100,
        _source: [
          'collected_at',
          'source_ip',
          'destination_ip',
          'hostname',
          'user_principal',
          'action',
          'outcome',
          'source_type',
          'raw_message',
          'event_id',
          'failure_reason',
          'destination_port',
          'protocol',
          'bytes_sent',
          'bytes_recv',
        ] as any,
        sort: [{ collected_at: { order: 'desc' as const } }],
        query: { bool: { filter } },
      })
      .then((r: any) => r);

    const hits = esResult?.hits?.hits ?? [];
    return hits.map((hit: any) => ({
      es_id: hit._id,
      ...(hit._source as Record<string, unknown>),
    }));
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
